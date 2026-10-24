-- CyberHunt KZ — research prototype schema (PostgreSQL 16)
-- Sensitive report fields are stored ONLY as AES-256-GCM ciphertext (columns *_enc).

CREATE TABLE IF NOT EXISTS organizations (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
  id              SERIAL PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  full_name       TEXT NOT NULL,
  password_hash   TEXT NOT NULL,                 -- scrypt$salt$hash
  role            TEXT NOT NULL CHECK (role IN ('RESEARCHER','OPERATOR','AGENCY','ADMIN')),
  iin_hmac        TEXT UNIQUE,                   -- HMAC-SHA256 of IIN; plaintext IIN is never stored
  phone_enc       TEXT,                          -- encrypted
  researcher_id   TEXT UNIQUE,                   -- public pseudonymous handle, e.g. CH-7F3A9C
  level           TEXT NOT NULL DEFAULT 'RESEARCHER'
                  CHECK (level IN ('RESEARCHER','VERIFIED','TRUSTED','ELITE')),
  points          INTEGER NOT NULL DEFAULT 0,
  organization_id INTEGER REFERENCES organizations(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS programs (
  id               SERIAL PRIMARY KEY,
  organization_id  INTEGER NOT NULL REFERENCES organizations(id),
  name             TEXT NOT NULL,
  asset_type       TEXT NOT NULL CHECK (asset_type IN ('WEB','API','MOBILE','OTHER')),
  asset_criticality TEXT NOT NULL CHECK (asset_criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  in_scope         TEXT[] NOT NULL,
  out_of_scope     TEXT[] NOT NULL,
  allowed_methods  TEXT[] NOT NULL,
  forbidden_methods TEXT[] NOT NULL,
  reward_matrix    JSONB NOT NULL,               -- {"LOW":{"min":..,"max":..}, ...} in KZT
  rules_version    TEXT NOT NULL,
  starts_at        DATE NOT NULL,
  ends_at          DATE NOT NULL,
  is_private       BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS safe_harbor_acceptances (
  id             SERIAL PRIMARY KEY,
  user_id        INTEGER NOT NULL REFERENCES users(id),
  program_id     INTEGER NOT NULL REFERENCES programs(id),
  rules_version  TEXT NOT NULL,
  accepted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, program_id, rules_version)
);

CREATE TABLE IF NOT EXISTS reports (
  id               SERIAL PRIMARY KEY,
  public_id        TEXT NOT NULL UNIQUE,         -- e.g. CHR-2026-000123
  program_id       INTEGER NOT NULL REFERENCES programs(id),
  researcher_id    INTEGER NOT NULL REFERENCES users(id),
  vuln_type        TEXT NOT NULL,                -- CWE-like category
  title_enc        TEXT NOT NULL,
  target_enc       TEXT NOT NULL,                -- URL / IP / API endpoint
  description_enc  TEXT NOT NULL,
  steps_enc        TEXT NOT NULL,
  impact_enc       TEXT NOT NULL,
  poc_enc          TEXT,
  target_fingerprint TEXT NOT NULL,              -- HMAC(host+path) for exact-match duplicate pre-filter
  cvss_vector      TEXT NOT NULL,
  cvss_score       NUMERIC(3,1) NOT NULL,
  status           TEXT NOT NULL,
  duplicate_of     INTEGER REFERENCES reports(id),
  auto_checks      JSONB NOT NULL DEFAULT '{}',  -- automatic scope + duplicate checks at submission
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS report_transitions (
  id          SERIAL PRIMARY KEY,
  report_id   INTEGER NOT NULL REFERENCES reports(id),
  from_status TEXT,
  to_status   TEXT NOT NULL,
  actor_id    INTEGER NOT NULL REFERENCES users(id),
  comment     TEXT,
  at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assessments (
  id                 SERIAL PRIMARY KEY,
  report_id          INTEGER NOT NULL UNIQUE REFERENCES reports(id),
  assessor_id        INTEGER NOT NULL REFERENCES users(id),
  cvss_vector        TEXT NOT NULL,              -- operator-confirmed vector
  cvss_score         NUMERIC(3,1) NOT NULL,
  real_impact        TEXT NOT NULL,
  exploitability     TEXT NOT NULL,
  scale              TEXT NOT NULL,
  report_quality     NUMERIC(4,3) NOT NULL,
  multifactor_score  NUMERIC(4,2) NOT NULL,
  baseline_tier      TEXT NOT NULL,
  baseline_reward    INTEGER NOT NULL,
  multifactor_tier   TEXT NOT NULL,
  recommended_reward INTEGER NOT NULL,
  final_tier         TEXT NOT NULL,              -- operator confirms (may override with justification)
  override_reason    TEXT,
  approved_by        INTEGER REFERENCES users(id),
  approved_at        TIMESTAMPTZ,
  paid_at            TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS remediations (
  id               SERIAL PRIMARY KEY,
  report_id        INTEGER NOT NULL UNIQUE REFERENCES reports(id),
  responsible      TEXT NOT NULL,
  deadline         DATE NOT NULL,
  fix_note         TEXT,
  fixed_at         TIMESTAMPTZ,
  retest_result    TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only, hash-chained audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  at          TIMESTAMPTZ NOT NULL,
  actor_id    INTEGER,
  actor_role  TEXT,
  action      TEXT NOT NULL,
  entity      TEXT NOT NULL,
  entity_id   TEXT,
  details     JSONB NOT NULL DEFAULT '{}',
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_fingerprint ON reports(target_fingerprint);
