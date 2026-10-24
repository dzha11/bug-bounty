import { Controller, Get, Inject } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import { CurrentUser, Public, Roles } from '../auth/auth.guard.js';
import type { TokenPayload } from '../common/security.js';
import { DatabaseService } from '../db/database.service.js';

@Controller()
export class AnalyticsController {
  constructor(
    @Inject(DatabaseService) private readonly db: DatabaseService,
    @Inject(AuditService) private readonly audit: AuditService,
  ) {}

  /** Operator / admin see everything; an agency sees only its own programs. */
  @Roles('OPERATOR', 'ADMIN', 'AGENCY')
  @Get('analytics/summary')
  async summary(@CurrentUser() u: TokenPayload) {
    const scoped = u.role === 'AGENCY';
    const filter = scoped ? 'WHERE p.organization_id = $1' : '';
    const params = scoped ? [u.org] : [];
    const counts = await this.db.query(
      `SELECT r.status, count(*)::int AS n FROM reports r JOIN programs p ON p.id=r.program_id ${filter} GROUP BY r.status`,
      params,
    );
    const tiers = await this.db.query(
      `SELECT a.final_tier AS tier, count(*)::int AS n, coalesce(sum(a.recommended_reward) FILTER (WHERE a.paid_at IS NOT NULL),0)::bigint AS paid
         FROM assessments a JOIN reports r ON r.id=a.report_id JOIN programs p ON p.id=r.program_id ${filter}
        GROUP BY a.final_tier`,
      params,
    );
    const timing = await this.db.one(
      `WITH t AS (
         SELECT r.id, r.created_at,
                min(tr.at) FILTER (WHERE tr.to_status IN ('VALIDATED','REJECTED')) AS triaged_at,
                min(tr.at) FILTER (WHERE tr.to_status = 'ACCEPTED') AS accepted_at,
                max(tr.at) FILTER (WHERE tr.to_status = 'CLOSED') AS closed_at
           FROM reports r JOIN programs p ON p.id=r.program_id
           JOIN report_transitions tr ON tr.report_id=r.id ${filter}
          GROUP BY r.id, r.created_at)
       SELECT round(avg(extract(epoch FROM triaged_at - created_at))/3600, 3) AS avg_triage_hours,
              round(avg(extract(epoch FROM closed_at - accepted_at))/86400, 3) AS mttr_days
         FROM t`,
      params,
    );
    const byStatus = Object.fromEntries(counts.rows.map((r) => [r.status, r.n]));
    const total = counts.rows.reduce((a, r) => a + r.n, 0);
    return {
      total,
      byStatus,
      valid: total - (byStatus.REJECTED ?? 0) - (byStatus.DUPLICATE ?? 0) - (byStatus.SUBMITTED ?? 0) - (byStatus.TRIAGE ?? 0),
      duplicates: byStatus.DUPLICATE ?? 0,
      rejected: byStatus.REJECTED ?? 0,
      byTier: Object.fromEntries(tiers.rows.map((r) => [r.tier, r.n])),
      totalPaidKzt: tiers.rows.reduce((a, r) => a + Number(r.paid), 0),
      avgTriageHours: timing?.avg_triage_hours == null ? null : Number(timing.avg_triage_hours),
      mttrDays: timing?.mttr_days == null ? null : Number(timing.mttr_days),
    };
  }

  /** Public leaderboard shows pseudonymous researcher IDs only. */
  @Public()
  @Get('leaderboard')
  async leaderboard() {
    const r = await this.db.query(
      `SELECT researcher_id, level, points FROM users WHERE role='RESEARCHER' AND points > 0
        ORDER BY points DESC, id LIMIT 20`,
    );
    return r.rows;
  }

  @Roles('ADMIN', 'OPERATOR')
  @Get('audit')
  list() {
    return this.audit.list(100);
  }

  @Roles('ADMIN', 'OPERATOR')
  @Get('audit/verify')
  verify() {
    return this.audit.verify();
  }

  @Public()
  @Get('health')
  health() {
    return { status: 'ok' };
  }
}
