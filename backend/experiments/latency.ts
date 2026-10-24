/**
 * Experiment E3 — API latency and scalability of submission.
 *
 * Prereq: API running on API_URL (default http://localhost:3001) against a freshly seeded DB.
 * Sequential requests (one client) so numbers reflect server work, not queueing.
 *  - GET /programs           public, no crypto                     (n = 200)
 *  - GET /reports (operator) list + decrypt title of every report  (n = 100, after the submissions)
 *  - POST /reports           validate + CVSS + encrypt 6 fields + duplicate search over all earlier reports
 *    submitted one after another up to N_SUBMIT, so latency is recorded as the corpus grows.
 *
 * Output: experiments/out/e3_latency.json
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';

const API = process.env.API_URL ?? 'http://localhost:3001';
const PASSWORD = process.env.SEED_PASSWORD ?? 'Demo-Passw0rd!';
const N_SUBMIT = Number(process.env.N_SUBMIT ?? 300);

async function call(path: string, token?: string, body?: unknown) {
  const t0 = performance.now();
  const r = await fetch(API + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json();
  const ms = performance.now() - t0;
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${JSON.stringify(data)}`);
  return { ms, data };
}

const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return Math.round(s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)] * 10) / 10;
};
const stats = (xs: number[]) => ({
  n: xs.length,
  mean: Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10,
  p50: pct(xs, 50),
  p95: pct(xs, 95),
  p99: pct(xs, 99),
  max: Math.round(Math.max(...xs) * 10) / 10,
});

const TOPICS = ['application status', 'document download', 'feedback form', 'profile settings', 'payment receipt',
  'appointment booking', 'notification centre', 'certificate request', 'tax statement', 'address change'];

const login = async (email: string) => (await call('/auth/login', undefined, { email, password: PASSWORD })).data.token as string;

const researcher = await login('researcher@cyberhunt.test');
const operator = await login('operator@cyberhunt.test');
await call('/programs/1/safe-harbor', researcher, {});

// warm-up
for (let i = 0; i < 20; i++) await call('/programs');

const programs: number[] = [];
for (let i = 0; i < 200; i++) programs.push((await call('/programs')).ms);

const submit: { i: number; ms: number }[] = [];
for (let i = 0; i < N_SUBMIT; i++) {
  const topic = TOPICS[i % TOPICS.length];
  const { ms } = await call('/reports', researcher, {
    programId: 1,
    vulnType: 'IDOR',
    title: `Access control issue in ${topic} module #${i}`,
    target: `https://portal.agency-a.test/${topic.replace(' ', '-')}/${i}`,
    description: `Benchmark report ${i}. The ${topic} module returns records of other users when the identifier is changed.`,
    steps: `1. Log in as a test user. 2. Open the ${topic} page. 3. Change the identifier. 4. Observe another record.`,
    impact: 'Disclosure of other users records (benchmark text).',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  });
  submit.push({ i, ms });
}

const list: number[] = [];
for (let i = 0; i < 100; i++) list.push((await call('/reports', operator)).ms);

const bucket = (lo: number, hi: number) => stats(submit.filter((s) => s.i >= lo && s.i < hi).map((s) => s.ms));
const result = {
  environment: {
    node: process.version,
    cpus: os.cpus().length,
    cpuModel: os.cpus()[0]?.model,
    totalMemGb: Math.round(os.totalmem() / 1e9),
    note: 'API and PostgreSQL 16 on the same host; single sequential client',
    at: new Date().toISOString(),
  },
  getPrograms: stats(programs),
  submitAll: stats(submit.map((s) => s.ms)),
  submitByCorpusSize: {
    '0-49': bucket(0, 50),
    '50-99': bucket(50, 100),
    '100-149': bucket(100, 150),
    '150-199': bucket(150, 200),
    '200-249': bucket(200, 250),
    '250-299': bucket(250, 300),
  },
  listReportsOperator: { ...stats(list), reportsInList: N_SUBMIT },
};
mkdirSync(new URL('./out/', import.meta.url), { recursive: true });
writeFileSync(new URL('./out/e3_latency.json', import.meta.url), JSON.stringify(result, null, 2));
writeFileSync(new URL('./out/e3_submit_series.csv', import.meta.url), ['i,ms', ...submit.map((s) => `${s.i},${s.ms.toFixed(2)}`)].join('\n'));
console.log(JSON.stringify(result, null, 2));
