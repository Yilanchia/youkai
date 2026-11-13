-- youkai schema (DEVPLAN-v0.2 module 2)
--
-- The discipline guarantees live in the database, not in a comment:
--   * audit_log is append-only (trigger)
--   * a finding cannot become verified unless an operator verdict is confirmed in
--     the same transaction (trigger)
--   * an intent cannot become approved unless an unconsumed operator approval
--     matching its fingerprint exists (trigger)
--   * facts are idempotent on (engagement, dedupe_key)

CREATE TABLE IF NOT EXISTS engagements (
  id         BIGSERIAL PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  scope      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 资产图
CREATE TABLE IF NOT EXISTS assets (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  value         TEXT NOT NULL,
  props         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (engagement_id, kind, value)
);

-- 探索图:facts
CREATE TABLE IF NOT EXISTS facts (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  statement     TEXT NOT NULL,
  evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
  tags          TEXT[] NOT NULL DEFAULT '{}',
  state         TEXT NOT NULL DEFAULT 'observed',
  dedupe_key    TEXT NOT NULL,
  run_id        BIGINT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (engagement_id, dedupe_key)
);

CREATE TABLE IF NOT EXISTS findings (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL DEFAULT 'info',
  kind          TEXT NOT NULL DEFAULT '',
  where_        TEXT NOT NULL DEFAULT '',
  detail        TEXT NOT NULL DEFAULT '',
  state         TEXT NOT NULL DEFAULT 'candidate'
                CHECK (state IN ('candidate','verified','false-positive','remediated','accepted-risk')),
  evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
  tags          TEXT[] NOT NULL DEFAULT '{}',
  operator      TEXT,
  verdict_note  TEXT,
  verified_at   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS intents (
  id                BIGSERIAL PRIMARY KEY,
  engagement_id     BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  capability        TEXT NOT NULL,
  args              JSONB NOT NULL DEFAULT '{}'::jsonb,
  tier              INT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'todo'
                    CHECK (status IN ('todo','active','done','skipped','blocked','needs_approval')),
  requires_approval BOOLEAN NOT NULL DEFAULT false,
  approved          BOOLEAN NOT NULL DEFAULT false,
  fingerprint       TEXT NOT NULL,
  rationale         TEXT NOT NULL DEFAULT '',
  expected_fact     TEXT NOT NULL DEFAULT '',
  provenance        TEXT NOT NULL DEFAULT '',
  inferred          BOOLEAN NOT NULL DEFAULT false,
  gate_reason       TEXT NOT NULL DEFAULT '',
  trace             TEXT NOT NULL DEFAULT '',
  deps              BIGINT[] NOT NULL DEFAULT '{}',
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Deriving the same next step twice must not fork the graph: one intent per
-- (engagement, exact action fingerprint).
CREATE UNIQUE INDEX IF NOT EXISTS intents_dedupe_idx ON intents (engagement_id, fingerprint);

CREATE TABLE IF NOT EXISTS approvals (
  id             BIGSERIAL PRIMARY KEY,
  engagement_id  BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  intent_id      BIGINT NOT NULL REFERENCES intents(id) ON DELETE CASCADE,
  fingerprint    TEXT NOT NULL,
  operator       TEXT NOT NULL,
  basis          TEXT NOT NULL,
  high_auth_path TEXT NOT NULL DEFAULT '',
  high_auth_nonce TEXT NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS edges (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  from_kind     TEXT NOT NULL,
  from_id       BIGINT NOT NULL,
  to_kind       TEXT NOT NULL,
  to_id         BIGINT NOT NULL,
  rel           TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (engagement_id, from_kind, from_id, to_kind, to_id, rel)
);

-- 不可改真值:逐请求审计
CREATE TABLE IF NOT EXISTS audit_log (
  id            BIGSERIAL PRIMARY KEY,
  engagement    TEXT NOT NULL,
  request_id    TEXT NOT NULL UNIQUE,
  ts            TIMESTAMPTZ NOT NULL,
  method        TEXT NOT NULL,
  url           TEXT NOT NULL,
  host          TEXT NOT NULL DEFAULT '',
  status        INT NOT NULL DEFAULT 0,
  bytes         BIGINT NOT NULL DEFAULT 0,
  verdict       TEXT NOT NULL,
  reason        TEXT NOT NULL DEFAULT '',
  purpose       TEXT NOT NULL DEFAULT '',
  duration_ms   BIGINT NOT NULL DEFAULT 0,
  detail        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_engagement_idx ON audit_log (engagement, ts DESC);

CREATE TABLE IF NOT EXISTS runs (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  status        TEXT NOT NULL DEFAULT 'running',
  stop_reason   TEXT NOT NULL DEFAULT '',
  steps         INT NOT NULL DEFAULT 0,
  derived       INT NOT NULL DEFAULT 0,
  config        JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS planner_calls (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  run_id        BIGINT,
  model         TEXT NOT NULL DEFAULT '',
  temperature   DOUBLE PRECISION NOT NULL DEFAULT 0,
  system_prompt TEXT NOT NULL DEFAULT '',
  prompt        TEXT NOT NULL DEFAULT '',
  raw_completion TEXT NOT NULL DEFAULT '',
  parsed        JSONB,
  rejected      JSONB,
  error         TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- guards ----

-- audit_log is append-only. Not "we promise", a trigger.
CREATE OR REPLACE FUNCTION youkai_audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only: % is forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_append_only_trg ON audit_log;
CREATE TRIGGER audit_log_append_only_trg
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION youkai_audit_append_only();

-- candidate -> verified requires an operator verdict in the same transaction.
CREATE OR REPLACE FUNCTION youkai_findings_verdict_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.state = 'verified' AND OLD.state IS DISTINCT FROM 'verified' THEN
    IF coalesce(current_setting('youkai.operator_verdict', true), '') <> 'confirmed' THEN
      RAISE EXCEPTION 'candidate->verified requires an operator verdict (set youkai.operator_verdict)';
    END IF;
    NEW.verified_at := now();
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS findings_verdict_guard_trg ON findings;
CREATE TRIGGER findings_verdict_guard_trg
  BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION youkai_findings_verdict_guard();

-- approved=true requires an unconsumed, fingerprint-matching operator approval.
CREATE OR REPLACE FUNCTION youkai_intents_approval_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.approved AND NOT OLD.approved THEN
    IF NOT EXISTS (
      SELECT 1 FROM approvals a
       WHERE a.intent_id = NEW.id
         AND a.fingerprint = NEW.fingerprint
         AND a.consumed_at IS NULL
    ) THEN
      RAISE EXCEPTION 'intent approval requires an unconsumed operator approval matching fingerprint %', NEW.fingerprint;
    END IF;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS intents_approval_guard_trg ON intents;
CREATE TRIGGER intents_approval_guard_trg
  BEFORE UPDATE ON intents
  FOR EACH ROW EXECUTE FUNCTION youkai_intents_approval_guard();
