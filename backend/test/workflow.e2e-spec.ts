/**
 * End-to-end functional test: the full report lifecycle through the real HTTP API
 * and a real PostgreSQL database (researcher -> operator -> payment committee -> agency).
 */
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { DatabaseService } from '../src/db/database.service.js';
import { bootApp, login, sampleReport } from './helpers.js';

describe('Report lifecycle (E2E, PostgreSQL)', () => {
  let app: INestApplication;
  let db: DatabaseService;
  let T: Record<string, string>;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    ({ app, db } = await bootApp());
    T = {
      researcher: await login(app, 'researcher@cyberhunt.test'),
      operator: await login(app, 'operator@cyberhunt.test'),
      admin: await login(app, 'admin@cyberhunt.test'),
      agency: await login(app, 'agency@cyberhunt.test'),
    };
  });
  afterAll(async () => app.close());

  const as = (who: string) => ({ Authorization: `Bearer ${T[who]}` });

  it('F1 public catalog shows scope and the reward matrix before testing', async () => {
    const r = await http().get('/programs').expect(200);
    expect(r.body).toHaveLength(2);
    expect(r.body[0].reward_matrix.CRITICAL).toEqual({ min: 1_500_000, max: 3_000_000 });
    expect(r.body[0].out_of_scope).toContain('status.portal.agency-a.test');
  });

  it('F2 submission is refused until Safe Harbor is accepted', async () => {
    await http().post('/reports').set(as('researcher')).send(sampleReport()).expect(403);
    const sh = await http().post('/programs/1/safe-harbor').set(as('researcher')).expect(201);
    expect(sh.body.rules_version).toBe('v1.0');
  });

  let id = '';
  it('F3 researcher submits a report; CVSS is computed server-side', async () => {
    const r = await http().post('/reports').set(as('researcher')).send(sampleReport()).expect(201);
    id = r.body.publicId;
    expect(id).toMatch(/^CHR-\d{4}-\d{6}$/);
    expect(r.body.cvssScore).toBe(6.5);
    expect(r.body.scopeMatch).toBe(true);
  });

  it('F4 full workflow: triage -> validated -> accepted -> assessed -> approved -> paid -> remediation -> retest -> closed', async () => {
    const step = (who: string, to: string, extra = {}) =>
      http().post(`/reports/${id}/transition`).set(as(who)).send({ to, ...extra });
    await step('operator', 'TRIAGE').expect(200);
    await step('operator', 'VALIDATED').expect(200);
    await step('operator', 'ACCEPTED').expect(200);

    const a = await http()
      .post(`/reports/${id}/assess`)
      .set(as('operator'))
      .send({
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
        realImpact: 'SEVERE',
        exploitability: 'TRIVIAL_AUTOMATABLE',
        scale: 'ALL_USERS',
        quality: { reproducible: true, clearSteps: true, workingPoc: true, impactExplained: true, remediationAdvice: false },
      })
      .expect(200);
    expect(a.body.baseline.tier).toBe('MEDIUM');
    expect(a.body.multiFactor.tier).toBe('HIGH');
    expect(a.body.recommendedReward).toBeGreaterThanOrEqual(500_000);

    await step('admin', 'REWARD_APPROVED').expect(200);
    await step('admin', 'PAID').expect(200);
    await http().post(`/reports/${id}/remediation`).set(as('agency'))
      .send({ responsible: 'Head of IT Security, Agency A', deadline: '2026-12-01' }).expect(200);
    await http().post(`/reports/${id}/remediation/fixed`).set(as('agency'))
      .send({ fixNote: 'Ownership check added in ApplicationsController' }).expect(200);
    const closed = await step('operator', 'CLOSED').expect(200);
    expect(closed.body.status).toBe('CLOSED');
    expect(closed.body.transitions.map((t: any) => t.to_status)).toEqual([
      'SUBMITTED', 'TRIAGE', 'VALIDATED', 'ACCEPTED', 'SEVERITY_ASSIGNED', 'REWARD_APPROVED', 'PAID',
      'REMEDIATION', 'RETEST', 'CLOSED',
    ]);
  });

  it('F5 researcher earns points after payment and sees the outcome', async () => {
    const me = await http().get('/auth/me').set(as('researcher')).expect(200);
    expect(me.body.points).toBe(50); // HIGH
    const lb = await http().get('/leaderboard').expect(200);
    expect(lb.body[0]).toEqual({ researcher_id: 'CH-DEMO01', level: 'RESEARCHER', points: 50 });
  });

  it('F6 automatic duplicate check flags a near-identical second report', async () => {
    const t2 = await login(app, 'researcher2@cyberhunt.test');
    await http().post('/programs/1/safe-harbor').set({ Authorization: `Bearer ${t2}` }).expect(201);
    const r = await http().post('/reports').set({ Authorization: `Bearer ${t2}` })
      .send(sampleReport({ title: 'Application status IDOR exposes other applicants data',
        description: 'Changing the numeric application id returns another applicant record because the server performs no ownership check.' }))
      .expect(201);
    expect(r.body.possibleDuplicates[0].reportId).toBe(id);
    expect(r.body.possibleDuplicates[0].sameTarget).toBe(true);
  });

  it('F7 invalid transitions are rejected (409) and state is unchanged', async () => {
    const list = await http().get('/reports').set(as('operator')).expect(200);
    const fresh = list.body.find((x: any) => x.status === 'SUBMITTED').id;
    await http().post(`/reports/${fresh}/transition`).set(as('admin')).send({ to: 'PAID' }).expect(409);
    const r = await http().get(`/reports/${fresh}`).set(as('operator')).expect(200);
    expect(r.body.status).toBe('SUBMITTED');
  });

  it('F8 analytics summarise the pipeline', async () => {
    const s = await http().get('/analytics/summary').set(as('operator')).expect(200);
    expect(s.body.total).toBe(2);
    expect(s.body.byTier).toEqual({ HIGH: 1 });
    expect(s.body.totalPaidKzt).toBeGreaterThan(0);
    expect(s.body.avgTriageHours).not.toBeNull();
  });
});
