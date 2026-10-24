# CyberHunt KZ — state bug bounty platform (research prototype)

Diploma project by **Rinatuly Bakdaulet** and **Zhumagali Yessen**.

> Development of the state Bug Bounty platform «CyberHunt KZ» for managing the process of
> vulnerability discovery, assessment, and reward.

This repository contains the **core slice** used for Assignment 3 (Methodology and Core Practical
Implementation): researcher submits a report → operator triage → severity assessment → reward
recommendation (multi-factor model vs. CVSS-only baseline) → payment approval → remediation →
retest → closure, with role-based access, encryption of confidential fields at rest and a
tamper-evident audit log.

It is a research prototype, not a production system. Not yet implemented: KYC, 2FA, Bounty
Wallet integration, appeals committee, private programs, SIEM export, file attachments.

## Stack

| Part | Technology |
|---|---|
| Backend | NestJS 12, TypeScript, `pg`, `zod` |
| Database | PostgreSQL 16 |
| Frontend | Next.js 16, React 19, Tailwind CSS 4 |
| Tests | Vitest 4 + Supertest (unit, E2E, security), Playwright (UI walkthrough) |

## Run locally

Prerequisites: Node.js 22+, PostgreSQL 16.

```bash
# 1. database
createuser cyberhunt -P            # password: cyberhunt_dev (dev only)
createdb -O cyberhunt cyberhunt
createdb -O cyberhunt cyberhunt_test

# 2. backend (http://localhost:3001)
cd backend
npm install
npm run seed                       # demo organisations, accounts and programs
npm run start:dev

# 3. frontend (http://localhost:3000)
cd ../frontend
npm install
npm run dev
```

Demo accounts (all use the seed test password printed by `npm run seed`, default `Demo-Passw0rd!`):

| Email | Role |
|---|---|
| researcher@cyberhunt.test, researcher2@cyberhunt.test | Researcher |
| operator@cyberhunt.test | Triage operator |
| admin@cyberhunt.test | Payment committee |
| agency@cyberhunt.test, agency-b@cyberhunt.test | Agency (asset owner) |

All seeded programs use reserved `.test` domains. No real government asset is authorised for
testing by this repository.

Environment variables (production must set all secrets): `DATABASE_URL`, `FIELD_ENC_KEY`
(32 bytes, base64), `HMAC_KEY` (32 bytes, base64), `JWT_SECRET`, `CORS_ORIGIN`, `PORT`;
frontend: `NEXT_PUBLIC_API_URL`.

## Tests and experiments

```bash
cd backend
npm test                 # unit tests (CVSS 3.1, reward models, workflow, crypto, tokens, audit hash)
npm run test:e2e         # E2E lifecycle + security tests against cyberhunt_test
npm run experiments      # E1 reward sensitivity (no server needed)
npm run bench            # E3 latency (needs the API running on a freshly seeded DB)
python3 ../docs/e2e_ui_walkthrough.py   # UI walkthrough + screenshots (needs both servers)
```

Results from the Assignment 3 run are kept in `backend/experiments/out/` and `docs/screenshots/`.

## Structure

```
backend/src
  auth/        register, login, global RBAC guard
  programs/    catalog, scope, reward matrix, Safe Harbor
  reports/     submission, workflow state machine, scope check
  scoring/     CVSS 3.1 calculator, baseline + multi-factor reward, duplicate check
  audit/       hash-chained append-only audit log
  analytics/   summary, leaderboard, audit verification
  common/      AES-256-GCM field encryption, password hashing, tokens, validation
  db/          schema.sql, seed
backend/test   E2E and security suites
backend/experiments   E1 and E3 scripts and outputs
frontend/src/app      pages: catalog, login, program, reports, report detail, analytics
docs/          diagrams, screenshots, UI walkthrough script
```
