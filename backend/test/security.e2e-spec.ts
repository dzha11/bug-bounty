/**
 * Security test cases mapped to OWASP ASVS 4.0.3 / OWASP API Security Top 10 (2023).
 * IDs (S1..S12) are referenced in the Assignment 3 report, Table 5.
 */
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { DatabaseService } from '../src/db/database.service.js';
import { bootApp, login, sampleReport } from './helpers.js';

describe('Security controls (E2E, PostgreSQL)', () => {
  let app: INestApplication;
  let db: DatabaseService;
  let T: Record<string, string>;
  let reportId = '';
  const http = () => request(app.getHttpServer());
  const as = (who: string) => ({ Authorization: `Bearer ${T[who]}` });

  beforeAll(async () => {
    ({ app, db } = await bootApp());
    T = {
      researcher: await login(app, 'researcher@cyberhunt.test'),
      researcher2: await login(app, 'researcher2@cyberhunt.test'),
      operator: await login(app, 'operator@cyberhunt.test'),
      admin: await login(app, 'admin@cyberhunt.test'),
      agency: await login(app, 'agency@cyberhunt.test'),
      agencyB: await login(app, 'agency-b@cyberhunt.test'),
    };
    await http().post('/programs/1/safe-harbor').set(as('researcher'));
    const r = await http().post('/reports').set(as('researcher')).send(sampleReport()).expect(201);
    reportId = r.body.publicId;
  });
  afterAll(async () => app.close());

  it('S1 [ASVS V4.1.1] protected endpoints deny anonymous access', async () => {
    await http().get('/reports').expect(401);
    await http().get(`/reports/${reportId}`).expect(401);
    await http().get('/audit/verify').expect(401);
  });

  it('S2 [ASVS V3.5.3] forged, tampered and alg=none tokens are rejected', async () => {
    const [h, , s] = T.researcher.split('.');
    const forged = Buffer.from(JSON.stringify({ sub: 3, role: 'ADMIN', iat: 0, exp: 9e9 })).toString('base64url');
    await http().get('/reports').set({ Authorization: `Bearer ${h}.${forged}.${s}` }).expect(401);
    const none = Buffer.from('{"alg":"none"}').toString('base64url');
    await http().get('/reports').set({ Authorization: `Bearer ${none}.${forged}.` }).expect(401);
  });

  it('S3 [ASVS V4.1.3, API5 BFLA] researcher cannot perform operator/admin functions', async () => {
    await http().post(`/reports/${reportId}/transition`).set(as('researcher')).send({ to: 'TRIAGE' }).expect(403);
    await http().post(`/reports/${reportId}/assess`).set(as('researcher')).send({}).expect(403);
    await http().get('/analytics/summary').set(as('researcher')).expect(403);
    await http().get('/audit').set(as('researcher')).expect(403);
  });

  it('S4 [ASVS V4.2.1, API1 BOLA/IDOR] a researcher cannot read another researcher\'s report', async () => {
    const r = await http().get(`/reports/${reportId}`).set(as('researcher2')).expect(404);
    expect(JSON.stringify(r.body)).not.toContain('IDOR in application');
    const list = await http().get('/reports').set(as('researcher2')).expect(200);
    expect(list.body).toHaveLength(0);
  });

  it('S5 [API1 BOLA] agencies see only their own, accepted reports', async () => {
    await http().get(`/reports/${reportId}`).set(as('agency')).expect(404); // not yet ACCEPTED
    for (const to of ['TRIAGE', 'VALIDATED', 'ACCEPTED']) {
      await http().post(`/reports/${reportId}/transition`).set(as('operator')).send({ to }).expect(200);
    }
    await http().get(`/reports/${reportId}`).set(as('agency')).expect(200);
    await http().get(`/reports/${reportId}`).set(as('agencyB')).expect(404); // other organisation
  });

  it('S6 [ASVS V6.2.1, V8.3.4] confidential fields are encrypted at rest (AES-256-GCM)', async () => {
    const row = (await db.query('SELECT * FROM reports WHERE public_id=$1', [reportId])).rows[0];
    const dump = JSON.stringify(row);
    for (const secret of ['IDOR in application', 'portal.agency-a.test', 'Authorization: Bearer', 'ownership check']) {
      expect(dump).not.toContain(secret);
    }
    expect(row.poc_enc).toMatch(/^v1\./);
    const u = (await db.query("SELECT * FROM users WHERE email='researcher@cyberhunt.test'")).rows[0];
    expect(u.password_hash).toMatch(/^scrypt\$/);
  });

  it('S7 [ASVS V7.1.1] audit log never contains confidential report content', async () => {
    const all = JSON.stringify((await db.query('SELECT * FROM audit_log')).rows);
    expect(all).not.toContain('IDOR in application');
    expect(all).not.toContain('/api/applications/1044');
  });

  it('S8 [ASVS V7.3.3] audit log is append-only and tampering is detected by the hash chain', async () => {
    const v = await http().get('/audit/verify').set(as('admin')).expect(200);
    expect(v.body.valid).toBe(true);
    await expect(db.query("UPDATE audit_log SET action='X' WHERE id=1")).rejects.toThrow(/append-only/);
    await expect(db.query('DELETE FROM audit_log WHERE id=1')).rejects.toThrow(/append-only/);
    // simulate a privileged attacker who disables the trigger and edits history
    await db.query('ALTER TABLE audit_log DISABLE TRIGGER USER');
    await db.query("UPDATE audit_log SET details='{\"tampered\":true}' WHERE id=3");
    await db.query('ALTER TABLE audit_log ENABLE TRIGGER USER');
    const v2 = await http().get('/audit/verify').set(as('admin')).expect(200);
    expect(v2.body).toMatchObject({ valid: false, brokenAt: 3 });
  });

  it('S9 [ASVS V2.2.1] brute force: login is throttled after 5 failures', async () => {
    const codes: number[] = [];
    for (let i = 0; i < 6; i++) {
      const r = await http().post('/auth/login').send({ email: 'operator@cyberhunt.test', password: `wrong-${i}` });
      codes.push(r.status);
    }
    expect(codes).toEqual([401, 401, 401, 401, 401, 429]);
  });

  it('S10 [ASVS V2.1, V5.1.3] input validation and no user enumeration', async () => {
    const a = await http().post('/auth/login').send({ email: 'nobody@cyberhunt.test', password: 'x' }).expect(401);
    const b = await http().post('/auth/login').send({ email: 'admin@cyberhunt.test', password: 'x' }).expect(401);
    expect(a.body.message).toBe(b.body.message);
    await http().post('/reports').set(as('researcher')).send(sampleReport({ cvssVector: 'CVSS:3.1/AV:X' })).expect(400);
    await http().post('/reports').set(as('researcher')).send({ ...sampleReport(), programId: '1 OR 1=1' }).expect(400);
  });

  it('S11 [ASVS V5.3.4] SQL metacharacters are stored as data (parameterised queries)', async () => {
    const r = await http().post('/reports').set(as('researcher'))
      .send(sampleReport({ title: "x'); DROP TABLE reports; --" })).expect(201);
    const back = await http().get(`/reports/${r.body.publicId}`).set(as('researcher')).expect(200);
    expect(back.body.title).toBe("x'); DROP TABLE reports; --");
    expect((await db.query('SELECT count(*)::int AS n FROM reports')).rows[0].n).toBe(2);
  });

  it('S12 [ASVS V14.4] security headers and no caching of confidential responses', async () => {
    const r = await http().get(`/reports/${reportId}`).set(as('operator')).expect(200);
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['x-frame-options']).toBe('DENY');
    expect(r.headers['cache-control']).toBe('no-store');
  });

  it('S13 [ASVS V7.2] viewing a PoC is itself logged', async () => {
    const n = (await db.query("SELECT count(*)::int AS n FROM audit_log WHERE action='REPORT_VIEWED_WITH_POC'")).rows[0].n;
    expect(n).toBeGreaterThan(0);
  });
});
