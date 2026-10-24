/**
 * Seeds DEMO data only: fictional organisations, test accounts and programs on
 * reserved ".test" domains. No real government asset is authorised for testing here.
 *
 * Usage: npm run seed   (uses DATABASE_URL)
 */
import { hashPassword } from '../common/security.js';
import { DEFAULT_MATRIX } from '../scoring/reward.js';
import { DatabaseService } from './database.service.js';

export const DEMO_PASSWORD = process.env.SEED_PASSWORD ?? 'Demo-Passw0rd!';

export const DEMO_USERS = [
  { email: 'researcher@cyberhunt.test', name: 'Demo Researcher', role: 'RESEARCHER', org: null, rid: 'CH-DEMO01' },
  { email: 'researcher2@cyberhunt.test', name: 'Demo Researcher Two', role: 'RESEARCHER', org: null, rid: 'CH-DEMO02' },
  { email: 'operator@cyberhunt.test', name: 'Demo Operator', role: 'OPERATOR', org: null, rid: null },
  { email: 'admin@cyberhunt.test', name: 'Demo Payment Committee', role: 'ADMIN', org: null, rid: null },
  { email: 'agency@cyberhunt.test', name: 'Demo Agency Security Officer', role: 'AGENCY', org: 'Demo State Agency A', rid: null },
  { email: 'agency-b@cyberhunt.test', name: 'Demo Agency B Officer', role: 'AGENCY', org: 'Demo State Agency B', rid: null },
] as const;

export async function seed(db: DatabaseService) {
  await db.migrate();
  await db.query(`ALTER TABLE audit_log DISABLE TRIGGER USER`);
  await db.query(
    `TRUNCATE audit_log, remediations, assessments, report_transitions, reports, safe_harbor_acceptances,
              programs, users, organizations RESTART IDENTITY CASCADE`,
  );
  await db.query(`ALTER TABLE audit_log ENABLE TRIGGER USER`);

  const orgA = await db.one(`INSERT INTO organizations (name) VALUES ('Demo State Agency A') RETURNING id`);
  const orgB = await db.one(`INSERT INTO organizations (name) VALUES ('Demo State Agency B') RETURNING id`);
  const orgId = (name: string | null) => (name === 'Demo State Agency A' ? orgA.id : name ? orgB.id : null);

  const pw = hashPassword(DEMO_PASSWORD);
  for (const u of DEMO_USERS) {
    await db.query(
      `INSERT INTO users (email, full_name, password_hash, role, researcher_id, organization_id) VALUES ($1,$2,$3,$4,$5,$6)`,
      [u.email, u.name, pw, u.role, u.rid, orgId(u.org)],
    );
  }

  const year = new Date().getFullYear();
  await db.query(
    `INSERT INTO programs (organization_id, name, asset_type, asset_criticality, in_scope, out_of_scope, allowed_methods,
       forbidden_methods, reward_matrix, rules_version, starts_at, ends_at)
     VALUES
     ($1, 'e-Services Citizen Portal (demo)', 'WEB', 'CRITICAL',
      ARRAY['portal.agency-a.test','*.portal.agency-a.test','api.agency-a.test/v1'],
      ARRAY['status.portal.agency-a.test'],
      ARRAY['Manual testing','Authenticated testing with own test accounts','Rate-limited automated scanning (<= 5 req/s)'],
      ARRAY['DoS / load testing','Social engineering','Accessing other citizens'' real data beyond minimal proof','Physical attacks'],
      $3, 'v1.0', $4, $5),
     ($2, 'Open Data API (demo)', 'API', 'MEDIUM',
      ARRAY['data.agency-b.test'], ARRAY[]::text[],
      ARRAY['Manual testing','Rate-limited automated scanning (<= 5 req/s)'],
      ARRAY['DoS / load testing','Social engineering'],
      $3, 'v1.0', $4, $5)`,
    [orgA.id, orgB.id, DEFAULT_MATRIX, `${year}-01-01`, `${year + 1}-12-31`],
  );
}

if (process.argv[1]?.endsWith('seed.js') || process.argv[1]?.endsWith('seed.ts')) {
  const db = new DatabaseService();
  seed(db)
    .then(() => console.log('Seeded demo data. Test password for all demo accounts:', DEMO_PASSWORD))
    .finally(() => db.onModuleDestroy());
}
