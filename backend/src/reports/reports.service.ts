import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import type pg from 'pg';
import { AuditService } from '../audit/audit.service.js';
import { CryptoService } from '../common/crypto.service.js';
import type { TokenPayload } from '../common/security.js';
import { DatabaseService } from '../db/database.service.js';
import { baseScore, CvssError } from '../scoring/cvss31.js';
import { combinedScore, DUPLICATE_THRESHOLD, similarity, targetKey } from '../scoring/dedup.js';
import { inScope } from './scope.js';
import {
  baselineReward,
  multiFactorReward,
  QualityChecklist,
  qualityScore,
  RewardMatrix,
  rewardForTier,
  Tier,
} from '../scoring/reward.js';
import { canTransition, Status } from './workflow.js';

const SENSITIVE = ['title', 'target', 'description', 'steps', 'impact', 'poc'] as const;
type SensitiveField = (typeof SENSITIVE)[number];

export interface SubmitInput {
  programId: number;
  vulnType: string;
  title: string;
  target: string;
  description: string;
  steps: string;
  impact: string;
  poc?: string;
  cvssVector: string;
}

export interface AssessInput {
  cvssVector: string;
  realImpact: 'NONE' | 'LIMITED' | 'SIGNIFICANT' | 'SEVERE';
  exploitability: 'THEORETICAL' | 'CONDITIONAL_POC' | 'RELIABLE_POC' | 'TRIVIAL_AUTOMATABLE';
  scale: 'SINGLE_USER' | 'USER_SUBSET' | 'ALL_USERS' | 'CROSS_SYSTEM';
  quality: QualityChecklist;
  finalTier?: Tier;
  overrideReason?: string;
}

const POINTS: Record<Tier, number> = { LOW: 10, MEDIUM: 25, HIGH: 50, CRITICAL: 100, EXCEPTIONAL: 150 };
// Statuses from which the asset owner (AGENCY) may see a report
const AGENCY_VISIBLE: Status[] = [
  'ACCEPTED',
  'SEVERITY_ASSIGNED',
  'REWARD_APPROVED',
  'PAID',
  'REMEDIATION',
  'RETEST',
  'CLOSED',
];

@Injectable()
export class ReportsService {
  constructor(
    @Inject(DatabaseService) private readonly db: DatabaseService,
    @Inject(CryptoService) private readonly crypto: CryptoService,
    @Inject(AuditService) private readonly audit: AuditService,
  ) {}

  private aad(publicId: string, field: SensitiveField) {
    return `report:${publicId}:${field}`;
  }

  private decryptRow(row: any) {
    const out: Record<string, string | null> = {};
    for (const f of SENSITIVE) {
      const blob = row[`${f}_enc`];
      out[f] = blob ? this.crypto.decrypt(blob, this.aad(row.public_id, f)) : null;
    }
    return out;
  }

  // ------------------------------------------------------------------ submit
  async submit(u: TokenPayload, input: SubmitInput) {
    let cvss: number;
    try {
      cvss = baseScore(input.cvssVector);
    } catch (e) {
      if (e instanceof CvssError) throw new BadRequestException(e.message);
      throw e;
    }
    const program = await this.db.one('SELECT * FROM programs WHERE id=$1', [input.programId]);
    if (!program) throw new NotFoundException('Program not found');
    const today = new Date();
    if (new Date(program.starts_at) > today || new Date(program.ends_at) < today) {
      throw new UnprocessableEntityException('Program is not active');
    }
    const sh = await this.db.one(
      'SELECT id FROM safe_harbor_acceptances WHERE user_id=$1 AND program_id=$2 AND rules_version=$3',
      [u.sub, program.id, program.rules_version],
    );
    if (!sh) throw new ForbiddenException('Safe Harbor terms for the current rules version must be accepted first');

    const scopeMatch = inScope(input.target, program.in_scope, program.out_of_scope);
    const fingerprint = this.crypto.hmac(`${program.id}|${targetKey(input.target)}`);
    const similar = await this.findSimilar(program.id, null, input, fingerprint);

    const result = await this.db.tx(async (c) => {
      const { rows } = await c.query<{ id: string }>("SELECT nextval('reports_id_seq') AS id");
      const id = Number(rows[0].id);
      const publicId = `CHR-${today.getFullYear()}-${String(id).padStart(6, '0')}`;
      const enc = (f: SensitiveField, v: string | undefined) =>
        v ? this.crypto.encrypt(v, this.aad(publicId, f)) : null;
      await c.query(
        `INSERT INTO reports (id, public_id, program_id, researcher_id, vuln_type, title_enc, target_enc, description_enc,
           steps_enc, impact_enc, poc_enc, target_fingerprint, cvss_vector, cvss_score, status, auto_checks)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'SUBMITTED',$15)`,
        [
          id,
          publicId,
          program.id,
          u.sub,
          input.vulnType,
          enc('title', input.title),
          enc('target', input.target),
          enc('description', input.description),
          enc('steps', input.steps),
          enc('impact', input.impact),
          enc('poc', input.poc),
          fingerprint,
          input.cvssVector,
          cvss,
          { scopeMatch, possibleDuplicates: similar },
        ],
      );
      await c.query(
        `INSERT INTO report_transitions (report_id, from_status, to_status, actor_id) VALUES ($1, NULL, 'SUBMITTED', $2)`,
        [id, u.sub],
      );
      // NB: audit details never contain the confidential report content
      await this.audit.log(
        {
          actorId: u.sub,
          actorRole: u.role,
          action: 'REPORT_SUBMITTED',
          entity: 'report',
          entityId: publicId,
          details: { programId: program.id, cvss, scopeMatch, possibleDuplicates: similar.length },
        },
        c,
      );
      return { id, publicId };
    });
    return { ...result, status: 'SUBMITTED', cvssScore: cvss, scopeMatch, possibleDuplicates: similar };
  }

  /** Automatic duplicate search among earlier, non-rejected reports of the same program. */
  async findSimilar(programId: number, excludeId: number | null, input: Partial<SubmitInput>, fingerprint: string) {
    const r = await this.db.query(
      `SELECT id, public_id, title_enc, target_enc, description_enc, steps_enc, impact_enc, poc_enc, target_fingerprint
         FROM reports WHERE program_id=$1 AND status <> 'REJECTED' AND ($2::int IS NULL OR id < $2)`,
      [programId, excludeId],
    );
    if (r.rows.length === 0) return [];
    const corpus = r.rows.map((row) => {
      const d = this.decryptRow(row);
      return { id: row.id, publicId: row.public_id, sameTarget: row.target_fingerprint === fingerprint,
        text: [d.title, d.target, d.description, d.steps].join(' ') };
    });
    const query = { id: 0, text: [input.title, input.target, input.description, input.steps].join(' ') };
    const scores = similarity(query, corpus);
    return scores
      .map((s) => {
        const doc = corpus.find((d) => d.id === s.id)!;
        return { reportId: doc.publicId, textSimilarity: s.score, sameTarget: doc.sameTarget,
          score: combinedScore(s.score, doc.sameTarget) };
      })
      .filter((s) => s.score >= DUPLICATE_THRESHOLD)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3);
  }

  // ------------------------------------------------------------------ read
  private async loadAuthorised(u: TokenPayload, idOrPublic: string) {
    const row = await this.db.one(
      `SELECT r.*, p.organization_id, p.name AS program_name, p.reward_matrix, p.asset_criticality
         FROM reports r JOIN programs p ON p.id=r.program_id WHERE r.public_id=$1`,
      [idOrPublic],
    );
    // Same 404 for "missing" and "not yours": avoids leaking which report ids exist (IDOR).
    if (!row) throw new NotFoundException('Report not found');
    const allowed =
      u.role === 'OPERATOR' ||
      u.role === 'ADMIN' ||
      (u.role === 'RESEARCHER' && row.researcher_id === u.sub) ||
      (u.role === 'AGENCY' && row.organization_id === u.org && AGENCY_VISIBLE.includes(row.status));
    if (!allowed) throw new NotFoundException('Report not found');
    return row;
  }

  async get(u: TokenPayload, publicId: string) {
    const row = await this.loadAuthorised(u, publicId);
    const content = this.decryptRow(row);
    await this.audit.log({
      actorId: u.sub,
      actorRole: u.role,
      action: content.poc ? 'REPORT_VIEWED_WITH_POC' : 'REPORT_VIEWED',
      entity: 'report',
      entityId: row.public_id,
    });
    const [transitions, assessment, remediation] = await Promise.all([
      this.db.query(
        `SELECT t.from_status, t.to_status, t.comment, t.at, u.role AS actor_role
           FROM report_transitions t JOIN users u ON u.id=t.actor_id WHERE report_id=$1 ORDER BY t.id`,
        [row.id],
      ),
      this.db.one('SELECT * FROM assessments WHERE report_id=$1', [row.id]),
      this.db.one('SELECT * FROM remediations WHERE report_id=$1', [row.id]),
    ]);
    const showChecks = u.role === 'OPERATOR' || u.role === 'ADMIN';
    return {
      id: row.public_id,
      program: { id: row.program_id, name: row.program_name },
      vulnType: row.vuln_type,
      status: row.status,
      cvssVector: row.cvss_vector,
      cvssScore: Number(row.cvss_score),
      duplicateOf: row.duplicate_of,
      createdAt: row.created_at,
      ...content,
      autoChecks: showChecks ? row.auto_checks : undefined,
      transitions: transitions.rows,
      assessment: assessment ?? null,
      remediation: remediation ?? null,
      rewardMatrix: row.reward_matrix,
    };
  }

  async list(u: TokenPayload) {
    let where = '';
    const params: unknown[] = [];
    if (u.role === 'RESEARCHER') {
      where = 'WHERE r.researcher_id=$1';
      params.push(u.sub);
    } else if (u.role === 'AGENCY') {
      where = 'WHERE p.organization_id=$1 AND r.status = ANY($2)';
      params.push(u.org, AGENCY_VISIBLE);
    }
    const r = await this.db.query(
      `SELECT r.public_id, r.title_enc, r.vuln_type, r.status, r.cvss_score, r.created_at, r.updated_at,
              p.name AS program_name, a.final_tier, a.recommended_reward, r.auto_checks
         FROM reports r JOIN programs p ON p.id=r.program_id LEFT JOIN assessments a ON a.report_id=r.id
         ${where} ORDER BY r.id DESC`,
      params,
    );
    return r.rows.map((row) => ({
      id: row.public_id,
      title: this.crypto.decrypt(row.title_enc, this.aad(row.public_id, 'title')),
      vulnType: row.vuln_type,
      status: row.status,
      cvssScore: Number(row.cvss_score),
      program: row.program_name,
      tier: row.final_tier,
      reward: row.recommended_reward,
      possibleDuplicates:
        u.role === 'OPERATOR' || u.role === 'ADMIN' ? (row.auto_checks?.possibleDuplicates?.length ?? 0) : undefined,
      scopeMatch: u.role === 'OPERATOR' || u.role === 'ADMIN' ? row.auto_checks?.scopeMatch : undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  // ------------------------------------------------------------------ workflow
  private async move(c: pg.PoolClient, u: TokenPayload, row: any, to: Status, comment?: string) {
    const check = canTransition(row.status, to, u.role);
    if (!check.ok) {
      if (check.reason === 'FORBIDDEN_ROLE') throw new ForbiddenException(`Role ${u.role} cannot move ${row.status} -> ${to}`);
      throw new ConflictException(`Transition ${row.status} -> ${to} is not allowed`);
    }
    // optimistic concurrency: the status must not have changed in the meantime
    const upd = await c.query('UPDATE reports SET status=$1, updated_at=now() WHERE id=$2 AND status=$3', [
      to,
      row.id,
      row.status,
    ]);
    if (upd.rowCount !== 1) throw new ConflictException('Report status changed concurrently');
    await c.query(
      'INSERT INTO report_transitions (report_id, from_status, to_status, actor_id, comment) VALUES ($1,$2,$3,$4,$5)',
      [row.id, row.status, to, u.sub, comment ?? null],
    );
    await this.audit.log(
      {
        actorId: u.sub,
        actorRole: u.role,
        action: 'REPORT_TRANSITION',
        entity: 'report',
        entityId: row.public_id,
        details: { from: row.status, to },
      },
      c,
    );
  }

  /** Generic transitions that need no extra data (assessment and remediation have their own endpoints). */
  async transition(u: TokenPayload, publicId: string, to: Status, comment?: string, duplicateOf?: string) {
    const row = await this.loadAuthorised(u, publicId);
    if (to === 'SEVERITY_ASSIGNED' || to === 'REMEDIATION' && row.status === 'PAID' || to === 'RETEST') {
      throw new BadRequestException('Use the dedicated endpoint for this step');
    }
    if (to === 'REJECTED' && !comment) throw new BadRequestException('A reason is required to reject a report');
    await this.db.tx(async (c) => {
      if (to === 'DUPLICATE') {
        if (!duplicateOf) throw new BadRequestException('duplicateOf is required');
        const orig = await c.query('SELECT id FROM reports WHERE public_id=$1 AND program_id=$2 AND id<$3', [
          duplicateOf,
          row.program_id,
          row.id,
        ]);
        if (!orig.rows[0]) throw new BadRequestException('duplicateOf must be an earlier report in the same program');
        await c.query('UPDATE reports SET duplicate_of=$1 WHERE id=$2', [orig.rows[0].id, row.id]);
      }
      if (to === 'REWARD_APPROVED') {
        const a = await c.query('SELECT assessor_id FROM assessments WHERE report_id=$1', [row.id]);
        if (a.rows[0]?.assessor_id === u.sub) throw new ForbiddenException('Four-eyes rule: assessor cannot approve');
        await c.query('UPDATE assessments SET approved_by=$1, approved_at=now() WHERE report_id=$2', [u.sub, row.id]);
      }
      await this.move(c, u, row, to, comment);
      if (to === 'PAID') {
        const a = await c.query('SELECT final_tier FROM assessments WHERE report_id=$1', [row.id]);
        const tier = a.rows[0].final_tier as Tier;
        await c.query('UPDATE assessments SET paid_at=now() WHERE report_id=$1', [row.id]);
        await c.query(
          `UPDATE users SET points = points + $1,
             level = CASE WHEN points + $1 >= 1000 THEN 'ELITE'
                          WHEN points + $1 >= 200 AND level IN ('RESEARCHER','VERIFIED') THEN 'TRUSTED'
                          ELSE level END
           WHERE id=$2`,
          [POINTS[tier], row.researcher_id],
        );
      }
      if (to === 'REMEDIATION' && row.status === 'RETEST') {
        await c.query('UPDATE remediations SET retest_result=$1, fixed_at=NULL WHERE report_id=$2', [
          'FAILED',
          row.id,
        ]);
      }
      if (to === 'CLOSED') {
        await c.query("UPDATE remediations SET retest_result='PASSED' WHERE report_id=$1", [row.id]);
      }
    });
    return this.get(u, publicId);
  }

  async assess(u: TokenPayload, publicId: string, a: AssessInput) {
    const row = await this.loadAuthorised(u, publicId);
    let cvss: number;
    try {
      cvss = baseScore(a.cvssVector);
    } catch (e) {
      if (e instanceof CvssError) throw new BadRequestException(e.message);
      throw e;
    }
    const matrix = row.reward_matrix as RewardMatrix;
    const quality = qualityScore(a.quality);
    const base = baselineReward(cvss, matrix);
    const mf = multiFactorReward(
      { cvssScore: cvss, realImpact: a.realImpact, exploitability: a.exploitability, scale: a.scale,
        assetCriticality: row.asset_criticality, quality },
      matrix,
    );
    if (mf.tier === 'NONE' && !a.finalTier) throw new UnprocessableEntityException('Finding has no rewardable impact; reject it instead');
    const finalTier = (a.finalTier ?? mf.tier) as Tier;
    if (a.finalTier && a.finalTier !== mf.tier && !a.overrideReason) {
      throw new BadRequestException('overrideReason is required when the final tier differs from the model');
    }
    const recommended = finalTier === mf.tier ? mf.reward : rewardForTier(finalTier, quality, matrix);
    await this.db.tx(async (c) => {
      await this.move(c, u, row, 'SEVERITY_ASSIGNED', a.overrideReason);
      await c.query(
        `INSERT INTO assessments (report_id, assessor_id, cvss_vector, cvss_score, real_impact, exploitability, scale,
           report_quality, multifactor_score, baseline_tier, baseline_reward, multifactor_tier, recommended_reward,
           final_tier, override_reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [row.id, u.sub, a.cvssVector, cvss, a.realImpact, a.exploitability, a.scale, quality, mf.score,
          base.tier, base.reward, mf.tier, recommended, finalTier, a.overrideReason ?? null],
      );
      await this.audit.log(
        { actorId: u.sub, actorRole: u.role, action: 'SEVERITY_ASSESSED', entity: 'report', entityId: row.public_id,
          details: { cvss, multifactor: mf.score, baselineTier: base.tier, modelTier: mf.tier, finalTier,
            overridden: finalTier !== mf.tier } },
        c,
      );
    });
    return { cvssScore: cvss, baseline: base, multiFactor: mf, quality, finalTier, recommendedReward: recommended };
  }

  async startRemediation(u: TokenPayload, publicId: string, responsible: string, deadline: string) {
    const row = await this.loadAuthorised(u, publicId);
    await this.db.tx(async (c) => {
      await this.move(c, u, row, 'REMEDIATION', `Responsible: ${responsible}; deadline ${deadline}`);
      await c.query(
        `INSERT INTO remediations (report_id, responsible, deadline) VALUES ($1,$2,$3)
         ON CONFLICT (report_id) DO UPDATE SET responsible=EXCLUDED.responsible, deadline=EXCLUDED.deadline`,
        [row.id, responsible, deadline],
      );
    });
    return this.get(u, publicId);
  }

  async markFixed(u: TokenPayload, publicId: string, fixNote: string) {
    const row = await this.loadAuthorised(u, publicId);
    await this.db.tx(async (c) => {
      await this.move(c, u, row, 'RETEST', 'Fix submitted for retest');
      await c.query('UPDATE remediations SET fix_note=$1, fixed_at=now() WHERE report_id=$2', [fixNote, row.id]);
    });
    return this.get(u, publicId);
  }
}
