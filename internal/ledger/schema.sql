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

-- Findings are idempotent per (engagement, title+kind+where) so re-running a
-- scan does not duplicate the same candidate.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedupe_key TEXT;
-- The counter-argument: why this could be a false positive and what would be
-- needed to grade it. Empty means "nobody stated one", which the report treats as
-- missing evidence rather than filling in silence.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS counter TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS findings_dedupe_idx ON findings (engagement_id, dedupe_key);

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

-- Runtime configuration (DEVPLAN-v0.4). Non-secret fields live in `value`; a
-- secret (e.g. the LLM API key) goes into `secret_enc` as an AES-256-GCM blob and
-- is never returned by the read API. Configured here so the UI can change how the
-- platform connects to a model without a restart.
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL DEFAULT '{}'::jsonb,
  secret_enc BYTEA,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by TEXT NOT NULL DEFAULT ''
);

-- Immutable report snapshots (DEVPLAN-v0.5). A report is a projection of the
-- ledger, and this table pins one projection: the exact bytes (via sha256), the
-- passport in force when it was produced, and the bundle itself. Append-only, like
-- the audit log: a snapshot you can edit proves nothing.
CREATE TABLE IF NOT EXISTS report_snapshots (
  id             BIGSERIAL PRIMARY KEY,
  engagement_id  BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  content_sha256 TEXT NOT NULL,
  scope_snapshot JSONB NOT NULL,
  bundle         JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS report_snapshots_eng_idx
  ON report_snapshots (engagement_id, created_at DESC);

CREATE OR REPLACE FUNCTION report_snapshots_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'report_snapshots is append-only: % is not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS report_snapshots_no_update ON report_snapshots;
CREATE TRIGGER report_snapshots_no_update
  BEFORE UPDATE OR DELETE ON report_snapshots
  FOR EACH ROW EXECUTE FUNCTION report_snapshots_append_only();

-- Signed mandates (ADR-005). A mandate lets tier-2 action CLASSES run without a
-- per-step approval, inside a scope and budget, until it expires or a human stops
-- it. The payload and signature are stored verbatim so an auditor can re-verify the
-- authorisation without trusting this database.
CREATE TABLE IF NOT EXISTS mandates (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  payload       JSONB NOT NULL,
  signature     TEXT NOT NULL,
  assets        TEXT[] NOT NULL,
  classes       TEXT[] NOT NULL,
  max_requests  INT NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  activated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  stopped_at    TIMESTAMPTZ,
  approver      TEXT NOT NULL DEFAULT '',
  basis         TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS mandates_eng_idx ON mandates (engagement_id, activated_at DESC);

-- Conversation history (v0.12). Append-only: the operator should be able to scroll
-- back and see exactly what was said, and what the model proposed at the time.
-- No response bodies, no headers, no credentials - only what youkai said and what
-- the operator typed.
CREATE TABLE IF NOT EXISTS chat_messages (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  role          TEXT NOT NULL CHECK (role IN ('user','assistant')),
  content       TEXT NOT NULL,
  cards         JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS chat_messages_eng_idx ON chat_messages (engagement_id, id);

-- chat history is a record, but it must still disappear with its engagement.
--
-- A plain "refuse everything" trigger also refuses the ON DELETE CASCADE from the
-- parent row, which makes an engagement undeletable (found the hard way: test
-- cleanup hung). UPDATE is always refused; DELETE is allowed only when it comes
-- from the cascading parent, which pg_trigger_depth() can see.
CREATE OR REPLACE FUNCTION youkai_chat_append_only() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'chat_messages is append-only';
  END IF;
  IF pg_trigger_depth() > 1 THEN
    RETURN OLD;          -- cascade from engagements: allowed
  END IF;
  RAISE EXCEPTION 'chat_messages is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS chat_messages_append_only_trg ON chat_messages;
CREATE TRIGGER chat_messages_append_only_trg
  BEFORE UPDATE OR DELETE ON chat_messages
  FOR EACH ROW EXECUTE FUNCTION youkai_chat_append_only();

-- Whitebox hypotheses (v0.13). A lead, not a finding: the ladder is
-- hypothesis -> candidate -> verified, and rows here only ever move along it with
-- evidence recorded in `note`. Source text is never stored - only file:line.
CREATE TABLE IF NOT EXISTS hypotheses (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  entry         TEXT NOT NULL DEFAULT '',
  param         TEXT NOT NULL DEFAULT '',
  sink          TEXT NOT NULL DEFAULT '',
  path          TEXT NOT NULL DEFAULT '',
  confidence    TEXT NOT NULL DEFAULT 'code-only',
  note          TEXT NOT NULL DEFAULT '',
  file          TEXT NOT NULL DEFAULT '',
  line          INT NOT NULL DEFAULT 0,
  state         TEXT NOT NULL DEFAULT 'open'
                CHECK (state IN ('open','probing','unconfirmed','candidate')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (engagement_id, kind, entry, param, sink, path)
);

CREATE INDEX IF NOT EXISTS hypotheses_eng_idx ON hypotheses (engagement_id, state, id);
