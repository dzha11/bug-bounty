import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/app.setup.js';
import { resetLoginLimiter } from '../src/auth/auth.controller.js';
import { DatabaseService } from '../src/db/database.service.js';
import { DEMO_PASSWORD, seed } from '../src/db/seed.js';

export async function bootApp() {
  const mod = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app = configureApp(mod.createNestApplication());
  await app.init();
  const db = app.get(DatabaseService);
  await seed(db);
  resetLoginLimiter();
  return { app, db };
}

export async function login(app: INestApplication, email: string, password = DEMO_PASSWORD) {
  const r = await request(app.getHttpServer()).post('/auth/login').send({ email, password });
  if (r.status !== 200) throw new Error(`login ${email} failed: ${r.status}`);
  return r.body.token as string;
}

export const sampleReport = (over: Record<string, unknown> = {}) => ({
  programId: 1,
  vulnType: 'IDOR',
  title: 'IDOR in application status endpoint exposes other applicants',
  target: 'https://portal.agency-a.test/api/applications/1043',
  description:
    'The endpoint returns the application of any applicant when the numeric id is changed. No ownership check is performed on the server side.',
  steps: '1. Log in as test user A. 2. Open /api/applications/1043 (own). 3. Change id to 1044. 4. Response contains user B data.',
  impact: 'Disclosure of name, IIN and address of other applicants.',
  poc: 'GET /api/applications/1044 HTTP/1.1\nAuthorization: Bearer <test-user-A>',
  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  ...over,
});
