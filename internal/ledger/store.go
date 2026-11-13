package ledger

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"youkai/internal/discipline"
)

//go:embed schema.sql
var schemaSQL string

// Store is the PostgreSQL-backed truth store.
type Store struct {
	pool *pgxpool.Pool
	dsn  string
}

// ErrNotFound is returned for missing rows.
var ErrNotFound = errors.New("ledger: not found")

// Open connects and verifies the connection.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("ledger: parse dsn: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("ledger: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ledger: ping: %w", err)
	}
	return &Store{pool: pool, dsn: dsn}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Pool exposes the pool for tests that need raw access.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Migrate applies schema.sql. It is idempotent (IF NOT EXISTS + CREATE OR REPLACE).
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("ledger: migrate: acquire: %w", err)
	}
	defer conn.Release()
	// PgConn.Exec speaks the simple protocol, which is what multi-statement
	// DDL (including $$ function bodies) needs.
	if _, err := conn.Conn().PgConn().Exec(ctx, schemaSQL).ReadAll(); err != nil {
		return fmt.Errorf("ledger: migrate: %w", err)
	}
	return nil
}

// ---- engagements -----------------------------------------------------------

// CreateEngagement registers an engagement and its scope passport.
func (s *Store) CreateEngagement(ctx context.Context, name string, scope any) (Engagement, error) {
	raw, err := json.Marshal(scope)
	if err != nil {
		return Engagement{}, fmt.Errorf("ledger: encode scope: %w", err)
	}
	var e Engagement
	err = s.pool.QueryRow(ctx, `
		INSERT INTO engagements (name, scope) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET scope = EXCLUDED.scope
		RETURNING id, name, scope, created_at`, name, raw).
		Scan(&e.ID, &e.Name, &e.Scope, &e.CreatedAt)
	if err != nil {
		return Engagement{}, fmt.Errorf("ledger: create engagement: %w", err)
	}
	return e, nil
}

// Engagement looks an engagement up by name.
func (s *Store) Engagement(ctx context.Context, name string) (Engagement, error) {
	var e Engagement
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, scope, created_at FROM engagements WHERE name = $1`, name).
		Scan(&e.ID, &e.Name, &e.Scope, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, err
	}
	return e, nil
}

// ListEngagements returns engagements, newest first.
func (s *Store) ListEngagements(ctx context.Context) ([]Engagement, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, scope, created_at FROM engagements ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Engagement
	for rows.Next() {
		var e Engagement
		if err := rows.Scan(&e.ID, &e.Name, &e.Scope, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- audit (implements discipline.Auditor) ---------------------------------

// Record appends one audit row. The table has an append-only trigger, so this is
// the only write that can ever succeed.
func (s *Store) Record(ctx context.Context, ev discipline.AuditEvent) error {
	detail, err := json.Marshal(ev.Detail)
	if err != nil {
		detail = []byte("{}")
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_log
			(engagement, request_id, ts, method, url, host, status, bytes, verdict, reason, purpose, duration_ms, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		ev.Engagement, ev.RequestID, ev.TS, ev.Method, ev.URL, ev.Host,
		ev.Status, ev.Bytes, ev.Verdict, ev.Reason, ev.Purpose, ev.DurationMS, detail)
	if err != nil {
		return fmt.Errorf("ledger: audit append: %w", err)
	}
	return nil
}

// AuditTail returns the newest audit rows for an engagement.
func (s *Store) AuditTail(ctx context.Context, engagement string, limit int) ([]AuditRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, engagement, request_id, ts, method, url, host, status, bytes,
		       verdict, reason, purpose, duration_ms, detail
		  FROM audit_log WHERE engagement = $1 ORDER BY id DESC LIMIT $2`, engagement, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		var detail []byte
		if err := rows.Scan(&a.ID, &a.Engagement, &a.RequestID, &a.TS, &a.Method, &a.URL,
			&a.Host, &a.Status, &a.Bytes, &a.Verdict, &a.Reason, &a.Purpose, &a.DurationMS, &detail); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detail, &a.Detail)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AuditStats summarises the audit trail: attempts, refusals, and the last time
// bytes actually left.
func (s *Store) AuditStats(ctx context.Context, engagement string) (allowed, blocked, errored int, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE verdict = 'allowed'),
			count(*) FILTER (WHERE verdict = 'blocked'),
			count(*) FILTER (WHERE verdict = 'error')
		  FROM audit_log WHERE engagement = $1`, engagement).
		Scan(&allowed, &blocked, &errored)
	return
}

// ---- ingest ----------------------------------------------------------------

// IngestResult reports what landed.
type IngestResult struct {
	FactIDs         []int64 `json:"fact_ids"`
	NewFacts        int     `json:"new_facts"`
	Deduped         int     `json:"deduped_facts"`
	DedupedFindings int     `json:"deduped_findings"`
	FindingIDs      []int64 `json:"finding_ids"`
	AssetIDs        []int64 `json:"asset_ids"`
}

// Ingest writes an observation. Idempotent on facts; findings are append-only.
//
// The intentID, when set, links every new fact/finding back to the intent that
// produced it, so lineage survives.
func (s *Store) Ingest(ctx context.Context, engagementID int64, runID *int64, intentID *int64, obs Observation) (IngestResult, error) {
	var res IngestResult
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	assetIDs := map[string]int64{}

	for _, a := range obs.Assets {
		id, err := upsertAsset(ctx, tx, engagementID, a)
		if err != nil {
			return res, err
		}
		assetIDs[a.Value] = id
		res.AssetIDs = append(res.AssetIDs, id)
	}

	anchor := func(kind string, id int64, values []string) error {
		for _, v := range values {
			aid, ok := assetIDs[v]
			if !ok {
				seed := AssetSeed{Kind: kindFromAnchor(v), Value: v}
				aid, err = upsertAsset(ctx, tx, engagementID, seed)
				if err != nil {
					return err
				}
				assetIDs[v] = aid
			}
			if err := addEdge(ctx, tx, engagementID, kind, id, "asset", aid, RelAnchors); err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range obs.Facts {
		if strings.TrimSpace(f.Statement) == "" {
			continue
		}
		key := DedupeKey(f.Statement, f.Evidence)
		ev, err := json.Marshal(f.Evidence)
		if err != nil {
			ev = []byte("{}")
		}
		var id int64
		err = tx.QueryRow(ctx, `
			INSERT INTO facts (engagement_id, statement, evidence, tags, dedupe_key, run_id)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (engagement_id, dedupe_key) DO NOTHING
			RETURNING id`,
			engagementID, f.Statement, ev, nonNilStrings(f.Tags), key, runID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			// Already known: idempotent, and the refusal is visible in the counter.
			res.Deduped++
			continue
		}
		if err != nil {
			return res, fmt.Errorf("ledger: insert fact: %w", err)
		}
		res.FactIDs = append(res.FactIDs, id)
		res.NewFacts++
		if intentID != nil {
			if err := addEdge(ctx, tx, engagementID, "intent", *intentID, "fact", id, RelSupports); err != nil {
				return res, err
			}
		}
		if err := anchor("fact", id, f.Anchors); err != nil {
			return res, err
		}
	}

	for _, f := range obs.Findings {
		if strings.TrimSpace(f.Title) == "" {
			continue
		}
		ev, err := json.Marshal(f.Evidence)
		if err != nil {
			ev = []byte("{}")
		}
		var id int64
		fkey := Hash(f.Title, f.Kind, f.Where)
		err = tx.QueryRow(ctx, `
			INSERT INTO findings (engagement_id, title, severity, kind, where_, detail, evidence, tags, dedupe_key)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (engagement_id, dedupe_key) DO NOTHING
			RETURNING id`,
			engagementID, f.Title, NormaliseSeverity(f.Severity), f.Kind, f.Where, f.Detail, ev, nonNilStrings(f.Tags), fkey).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			res.DedupedFindings++
			continue // same candidate at the same place: already on record
		}
		if err != nil {
			return res, fmt.Errorf("ledger: insert finding: %w", err)
		}
		res.FindingIDs = append(res.FindingIDs, id)
		if intentID != nil {
			if err := addEdge(ctx, tx, engagementID, "intent", *intentID, "finding", id, RelSupports); err != nil {
				return res, err
			}
		}
		if err := anchor("finding", id, f.Anchors); err != nil {
			return res, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	return res, nil
}

func upsertAsset(ctx context.Context, db execer, engagementID int64, a AssetSeed) (int64, error) {
	props, err := json.Marshal(a.Props)
	if err != nil {
		props = []byte("{}")
	}
	var id int64
	err = db.QueryRow(ctx, `
		INSERT INTO assets (engagement_id, kind, value, props) VALUES ($1,$2,$3,$4)
		ON CONFLICT (engagement_id, kind, value)
		DO UPDATE SET props = assets.props || EXCLUDED.props
		RETURNING id`, engagementID, a.Kind, a.Value, props).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("ledger: upsert asset %s: %w", a.Value, err)
	}
	return id, nil
}

func addEdge(ctx context.Context, tx pgx.Tx, engagementID int64, fromKind string, fromID int64, toKind string, toID int64, rel string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO edges (engagement_id, from_kind, from_id, to_kind, to_id, rel)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT DO NOTHING`, engagementID, fromKind, fromID, toKind, toID, rel)
	return err
}

// kindFromAnchor infers an asset kind from an anchor value's prefix.
func kindFromAnchor(value string) string {
	switch {
	case strings.HasPrefix(value, "host:"):
		return "host"
	case strings.HasPrefix(value, "surface:"):
		return "surface"
	case strings.HasPrefix(value, "artifact:"):
		return "artifact"
	case strings.HasPrefix(value, "endpoint:"):
		return "endpoint"
	default:
		return "asset"
	}
}

// UpsertAsset inserts or enriches an asset vertex and returns its id.
func (s *Store) UpsertAsset(ctx context.Context, engagementID int64, seed AssetSeed) (int64, error) {
	return upsertAsset(ctx, s.pool, engagementID, seed)
}

// ---- intents ---------------------------------------------------------------

// IntentSpec is a typed next step before it is stored.
type IntentSpec struct {
	Capability       string         `json:"capability"`
	Args             map[string]any `json:"args"`
	Tier             int            `json:"tier"`
	Rationale        string         `json:"rationale"`
	ExpectedFact     string         `json:"expected_fact"`
	Provenance       string         `json:"provenance,omitempty"`
	Inferred         bool           `json:"inferred,omitempty"`
	GateReason       string         `json:"gate_reason"`
	Deps             []int64        `json:"deps,omitempty"`
	Anchors          []string       `json:"anchors,omitempty"`
	RequiresApproval bool           `json:"requires_approval"`
}

// EnsureIntent inserts an intent if its fingerprint is new. created=false means
// the identical intent already exists (the engine's derive step is idempotent).
func (s *Store) EnsureIntent(ctx context.Context, engagementID int64, spec IntentSpec) (Intent, bool, error) {
	fp := Fingerprint(engagementID, spec.Capability, spec.Args)
	args, err := json.Marshal(spec.Args)
	if err != nil {
		return Intent{}, false, err
	}
	var it Intent
	err = s.pool.QueryRow(ctx, `
		INSERT INTO intents
			(engagement_id, capability, args, tier, status, requires_approval, fingerprint,
			 rationale, expected_fact, provenance, inferred, gate_reason, deps)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (engagement_id, fingerprint) DO NOTHING
		RETURNING id, engagement_id, capability, args, tier, status, requires_approval,
		          approved, fingerprint, rationale, expected_fact, provenance, inferred,
		          gate_reason, trace, deps, created_at`,
		engagementID, spec.Capability, args, spec.Tier, StatusTodo, spec.RequiresApproval, fp,
		spec.Rationale, spec.ExpectedFact, spec.Provenance, spec.Inferred, spec.GateReason, nonNilIDs(spec.Deps)).
		Scan(&it.ID, &it.EngagementID, &it.Capability, &args, &it.Tier, &it.Status,
			&it.RequiresApproval, &it.Approved, &it.Fingerprint, &it.Rationale, &it.ExpectedFact,
			&it.Provenance, &it.Inferred, &it.GateReason, &it.Trace, &it.Deps, &it.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		existing, gerr := s.IntentByFingerprint(ctx, engagementID, fp)
		return existing, false, gerr
	}
	if err != nil {
		return Intent{}, false, fmt.Errorf("ledger: insert intent: %w", err)
	}
	_ = json.Unmarshal(args, &it.Args)

	for _, a := range spec.Anchors {
		var aid int64
		seed := AssetSeed{Kind: kindFromAnchor(a), Value: a}
		aid, uerr := upsertAsset(ctx, s.pool, engagementID, seed)
		if uerr != nil {
			return it, true, uerr
		}
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO edges (engagement_id, from_kind, from_id, to_kind, to_id, rel)
			VALUES ($1,'intent',$2,'asset',$3,$4) ON CONFLICT DO NOTHING`,
			engagementID, it.ID, aid, RelAnchors)
	}
	for _, dep := range spec.Deps {
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO edges (engagement_id, from_kind, from_id, to_kind, to_id, rel)
			VALUES ($1,'intent',$2,'intent',$3,$4) ON CONFLICT DO NOTHING`,
			engagementID, it.ID, dep, RelDependsOn)
	}
	return it, true, nil
}

// execer is the shared surface of *pgxpool.Pool and pgx.Tx for the helpers above.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// IntentByFingerprint finds an intent by its exact action fingerprint.
func (s *Store) IntentByFingerprint(ctx context.Context, engagementID int64, fp string) (Intent, error) {
	return s.scanIntent(s.pool.QueryRow(ctx, intentSelect+` WHERE engagement_id=$1 AND fingerprint=$2`, engagementID, fp))
}

// Intent loads one intent.
func (s *Store) Intent(ctx context.Context, engagementID, id int64) (Intent, error) {
	return s.scanIntent(s.pool.QueryRow(ctx, intentSelect+` WHERE engagement_id=$1 AND id=$2`, engagementID, id))
}

const intentSelect = `SELECT id, engagement_id, capability, args, tier, status, requires_approval,
	approved, fingerprint, rationale, expected_fact, provenance, inferred, gate_reason, trace, deps, created_at
	FROM intents`

func (s *Store) scanIntent(row pgx.Row) (Intent, error) {
	var it Intent
	var args []byte
	err := row.Scan(&it.ID, &it.EngagementID, &it.Capability, &args, &it.Tier, &it.Status,
		&it.RequiresApproval, &it.Approved, &it.Fingerprint, &it.Rationale, &it.ExpectedFact,
		&it.Provenance, &it.Inferred, &it.GateReason, &it.Trace, &it.Deps, &it.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Intent{}, ErrNotFound
	}
	if err != nil {
		return Intent{}, err
	}
	_ = json.Unmarshal(args, &it.Args)
	return it, nil
}

// ListIntents returns intents for an engagement, oldest first.
func (s *Store) ListIntents(ctx context.Context, engagementID int64) ([]Intent, error) {
	rows, err := s.pool.Query(ctx, intentSelect+` WHERE engagement_id=$1 ORDER BY id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Intent
	for rows.Next() {
		it, err := s.scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// SetIntentStatus moves an intent through its lifecycle.
func (s *Store) SetIntentStatus(ctx context.Context, engagementID, id int64, status string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE intents SET status=$1 WHERE engagement_id=$2 AND id=$3`, status, engagementID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AppendTrace adds a line to the intent's worker trace.
func (s *Store) AppendTrace(ctx context.Context, engagementID, id int64, line string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE intents SET trace = CASE WHEN trace = '' THEN $1 ELSE trace || E'\n' || $1 END
		 WHERE engagement_id=$2 AND id=$3`, line, engagementID, id)
	return err
}

// ApproveIntent records an operator approval and flips the intent's approved flag.
//
// Two things are load-bearing here: the approval row carries the intent's
// fingerprint (so it cannot authorise a different action), and the DB trigger
// refuses to set approved=true without such a row.
func (s *Store) ApproveIntent(ctx context.Context, engagementID, intentID int64, operator, basis, highAuthPath, highAuthNonce string) (Approval, error) {
	if strings.TrimSpace(operator) == "" {
		return Approval{}, fmt.Errorf("approval: operator is required")
	}
	if len([]rune(strings.TrimSpace(basis))) < 8 {
		return Approval{}, fmt.Errorf("approval: basis must say why this is authorised (>=8 chars)")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Approval{}, err
	}
	defer tx.Rollback(ctx)

	var fp string
	var tier int
	var status string
	err = tx.QueryRow(ctx,
		`SELECT fingerprint, tier, status FROM intents WHERE engagement_id=$1 AND id=$2 FOR UPDATE`,
		engagementID, intentID).Scan(&fp, &tier, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, err
	}
	if tier < 2 {
		return Approval{}, fmt.Errorf("approval: intent #%d is tier %d; tier-1 work runs unattended, approval is for proof-grade steps", intentID, tier)
	}

	var ap Approval
	err = tx.QueryRow(ctx, `
		INSERT INTO approvals (engagement_id, intent_id, fingerprint, operator, basis, high_auth_path, high_auth_nonce)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, intent_id, fingerprint, operator, basis, high_auth_path, high_auth_nonce, created_at`,
		engagementID, intentID, fp, operator, basis, highAuthPath, highAuthNonce).
		Scan(&ap.ID, &ap.IntentID, &ap.Fingerprint, &ap.Operator, &ap.Basis, &ap.HighAuthPath, &ap.HighAuthNonce, &ap.CreatedAt)
	if err != nil {
		return Approval{}, fmt.Errorf("approval: insert: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE intents SET approved=true WHERE engagement_id=$1 AND id=$2`, engagementID, intentID); err != nil {
		return Approval{}, fmt.Errorf("approval: flip approved: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Approval{}, err
	}
	return ap, nil
}

// PeekApproval returns the unconsumed approval for an intent WITHOUT consuming it.
//
// The execute route validates the operator and the high-authorisation record
// first, and only then consumes: a failed precondition must not burn the single
// approval a human granted.
func (s *Store) PeekApproval(ctx context.Context, engagementID, intentID int64) (Approval, error) {
	var ap Approval
	err := s.pool.QueryRow(ctx, `
		SELECT id, intent_id, fingerprint, operator, basis, high_auth_path, high_auth_nonce, created_at, consumed_at
		  FROM approvals
		 WHERE engagement_id=$1 AND intent_id=$2 AND consumed_at IS NULL
		 ORDER BY id DESC LIMIT 1`, engagementID, intentID).
		Scan(&ap.ID, &ap.IntentID, &ap.Fingerprint, &ap.Operator, &ap.Basis, &ap.HighAuthPath, &ap.HighAuthNonce, &ap.CreatedAt, &ap.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, fmt.Errorf("approval: intent #%d has no unconsumed approval", intentID)
	}
	if err != nil {
		return Approval{}, err
	}
	return ap, nil
}

// ConsumeApproval returns and consumes the single valid approval for an intent.
//
// "Single" is enforced by the UPDATE ... WHERE consumed_at IS NULL, which is
// atomic: two concurrent executions cannot both get an approval.
func (s *Store) ConsumeApproval(ctx context.Context, engagementID, intentID int64) (Approval, error) {
	var ap Approval
	err := s.pool.QueryRow(ctx, `
		UPDATE approvals SET consumed_at = now()
		 WHERE id = (
		   SELECT id FROM approvals
		    WHERE engagement_id=$1 AND intent_id=$2 AND consumed_at IS NULL
		    ORDER BY id DESC LIMIT 1)
		RETURNING id, intent_id, fingerprint, operator, basis, high_auth_path, high_auth_nonce, created_at, consumed_at`,
		engagementID, intentID).
		Scan(&ap.ID, &ap.IntentID, &ap.Fingerprint, &ap.Operator, &ap.Basis, &ap.HighAuthPath, &ap.HighAuthNonce, &ap.CreatedAt, &ap.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, fmt.Errorf("approval: intent #%d has no unconsumed approval", intentID)
	}
	if err != nil {
		return Approval{}, err
	}
	return ap, nil
}

// ListApprovals returns approvals for an intent, newest first.
func (s *Store) ListApprovals(ctx context.Context, engagementID, intentID int64) ([]Approval, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, intent_id, fingerprint, operator, basis, high_auth_path, high_auth_nonce, created_at, consumed_at
		  FROM approvals WHERE engagement_id=$1 AND intent_id=$2 ORDER BY id DESC`, engagementID, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.IntentID, &a.Fingerprint, &a.Operator, &a.Basis,
			&a.HighAuthPath, &a.HighAuthNonce, &a.CreatedAt, &a.ConsumedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- findings --------------------------------------------------------------

// VerifyFinding is the ONLY path from candidate to verified.
//
// It runs in one transaction that sets the operator verdict flag the trigger
// requires, so a future refactor cannot "accidentally" upgrade a finding.
func (s *Store) VerifyFinding(ctx context.Context, engagementID, findingID int64, operator, note string) (Finding, error) {
	if strings.TrimSpace(operator) == "" {
		return Finding{}, fmt.Errorf("verdict: operator is required")
	}
	if strings.TrimSpace(note) == "" {
		return Finding{}, fmt.Errorf("verdict: an operator note is required to verify a finding")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Finding{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SET LOCAL youkai.operator_verdict = 'confirmed'`); err != nil {
		return Finding{}, fmt.Errorf("verdict: set operator flag: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE findings SET state='verified', operator=$1, verdict_note=$2
		 WHERE engagement_id=$3 AND id=$4 AND state='candidate'`, operator, note, engagementID, findingID)
	if err != nil {
		return Finding{}, fmt.Errorf("verdict: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Finding{}, fmt.Errorf("verdict: finding #%d is not a candidate (or does not exist)", findingID)
	}
	if err := tx.Commit(ctx); err != nil {
		return Finding{}, err
	}
	return s.Finding(ctx, engagementID, findingID)
}

// Finding loads one finding.
func (s *Store) Finding(ctx context.Context, engagementID, id int64) (Finding, error) {
	rows, err := s.pool.Query(ctx, findingSelect+` WHERE engagement_id=$1 AND id=$2`, engagementID, id)
	if err != nil {
		return Finding{}, err
	}
	defer rows.Close()
	list, err := scanFindings(rows)
	if err != nil {
		return Finding{}, err
	}
	if len(list) == 0 {
		return Finding{}, ErrNotFound
	}
	return list[0], nil
}

const findingSelect = `SELECT id, engagement_id, title, severity, kind, where_, detail, state,
	evidence, tags, coalesce(operator,''), coalesce(verdict_note,''), verified_at, created_at FROM findings`

// ListFindings returns findings, newest first.
func (s *Store) ListFindings(ctx context.Context, engagementID int64, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx, findingSelect+` WHERE engagement_id=$1 ORDER BY id DESC LIMIT $2`, engagementID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

func scanFindings(rows pgx.Rows) ([]Finding, error) {
	var out []Finding
	for rows.Next() {
		var f Finding
		var ev []byte
		if err := rows.Scan(&f.ID, &f.EngagementID, &f.Title, &f.Severity, &f.Kind, &f.Where,
			&f.Detail, &f.State, &ev, &f.Tags, &f.Operator, &f.VerdictNote, &f.VerifiedAt, &f.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(ev, &f.Evidence)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---- runs ------------------------------------------------------------------

// CreateRun opens a run row.
func (s *Store) CreateRun(ctx context.Context, engagementID int64, cfg map[string]any) (Run, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		raw = []byte("{}")
	}
	var r Run
	err = s.pool.QueryRow(ctx, `
		INSERT INTO runs (engagement_id, config) VALUES ($1,$2)
		RETURNING id, engagement_id, status, stop_reason, steps, derived, config, started_at, ended_at`,
		engagementID, raw).
		Scan(&r.ID, &r.EngagementID, &r.Status, &r.StopReason, &r.Steps, &r.Derived, &raw, &r.StartedAt, &r.EndedAt)
	if err != nil {
		return Run{}, err
	}
	_ = json.Unmarshal(raw, &r.Config)
	return r, nil
}

// FinishRun closes a run with its stop reason.
func (s *Store) FinishRun(ctx context.Context, runID int64, status, stopReason string, steps, derived int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE runs SET status=$1, stop_reason=$2, steps=$3, derived=$4, ended_at=now() WHERE id=$5`,
		status, stopReason, steps, derived, runID)
	return err
}

// GetRun loads one run.
func (s *Store) GetRun(ctx context.Context, engagementID, runID int64) (Run, error) {
	var r Run
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, engagement_id, status, stop_reason, steps, derived, config, started_at, ended_at
		  FROM runs WHERE engagement_id=$1 AND id=$2`, engagementID, runID).
		Scan(&r.ID, &r.EngagementID, &r.Status, &r.StopReason, &r.Steps, &r.Derived, &raw, &r.StartedAt, &r.EndedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, err
	}
	_ = json.Unmarshal(raw, &r.Config)
	return r, nil
}

// ListRuns returns runs, newest first.
func (s *Store) ListRuns(ctx context.Context, engagementID int64, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, engagement_id, status, stop_reason, steps, derived, config, started_at, ended_at
		  FROM runs WHERE engagement_id=$1 ORDER BY id DESC LIMIT $2`, engagementID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		var raw []byte
		if err := rows.Scan(&r.ID, &r.EngagementID, &r.Status, &r.StopReason, &r.Steps, &r.Derived, &raw, &r.StartedAt, &r.EndedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &r.Config)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- graph view ------------------------------------------------------------

// GraphView is the read-only projection the UI and the timeline render.
type GraphView struct {
	Engagement Engagement `json:"engagement"`
	Assets     []Asset    `json:"assets"`
	Facts      []Fact     `json:"facts"`
	Findings   []Finding  `json:"findings"`
	Intents    []Intent   `json:"intents"`
	Edges      []Edge     `json:"edges"`
	Stats      GraphStats `json:"stats"`
}

// GraphStats is the summary strip.
type GraphStats struct {
	Assets         int `json:"assets"`
	Facts          int `json:"facts"`
	Findings       int `json:"findings"`
	CandidateCount int `json:"candidates"`
	Verified       int `json:"verified"`
	Intents        int `json:"intents"`
	NeedsApproval  int `json:"needs_approval"`
	Done           int `json:"done"`
	AuditAllowed   int `json:"audit_allowed"`
	AuditBlocked   int `json:"audit_blocked"`
	AuditError     int `json:"audit_error"`
}

// Graph assembles the whole exploration state for an engagement.
func (s *Store) Graph(ctx context.Context, engagementID int64) (GraphView, error) {
	var g GraphView
	e, err := s.engagementByID(ctx, engagementID)
	if err != nil {
		return g, err
	}
	g.Engagement = e

	if g.Assets, err = s.listAssets(ctx, engagementID); err != nil {
		return g, err
	}
	if g.Facts, err = s.listFacts(ctx, engagementID); err != nil {
		return g, err
	}
	if g.Findings, err = s.ListFindings(ctx, engagementID, 500); err != nil {
		return g, err
	}
	if g.Intents, err = s.ListIntents(ctx, engagementID); err != nil {
		return g, err
	}
	if g.Edges, err = s.listEdges(ctx, engagementID); err != nil {
		return g, err
	}
	g.Stats = GraphStats{
		Assets: len(g.Assets), Facts: len(g.Facts), Findings: len(g.Findings), Intents: len(g.Intents),
	}
	for _, f := range g.Findings {
		if f.State == FindingCandidate {
			g.Stats.CandidateCount++
		}
		if f.State == FindingVerified {
			g.Stats.Verified++
		}
	}
	for _, it := range g.Intents {
		if it.Status == StatusNeedsApproval {
			g.Stats.NeedsApproval++
		}
		if it.Status == StatusDone {
			g.Stats.Done++
		}
	}
	g.Stats.AuditAllowed, g.Stats.AuditBlocked, g.Stats.AuditError, _ = s.AuditStats(ctx, e.Name)
	return g, nil
}

func (s *Store) engagementByID(ctx context.Context, id int64) (Engagement, error) {
	var e Engagement
	err := s.pool.QueryRow(ctx, `SELECT id, name, scope, created_at FROM engagements WHERE id=$1`, id).
		Scan(&e.ID, &e.Name, &e.Scope, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Engagement{}, ErrNotFound
	}
	return e, err
}

func (s *Store) listAssets(ctx context.Context, engagementID int64) ([]Asset, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, engagement_id, kind, value, props, created_at FROM assets WHERE engagement_id=$1 ORDER BY id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var props []byte
		if err := rows.Scan(&a.ID, &a.EngagementID, &a.Kind, &a.Value, &props, &a.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(props, &a.Props)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) listFacts(ctx context.Context, engagementID int64) ([]Fact, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, engagement_id, statement, evidence, tags, state, run_id, created_at
		   FROM facts WHERE engagement_id=$1 ORDER BY id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fact
	for rows.Next() {
		var f Fact
		var ev []byte
		if err := rows.Scan(&f.ID, &f.EngagementID, &f.Statement, &ev, &f.Tags, &f.State, &f.RunID, &f.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(ev, &f.Evidence)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) listEdges(ctx context.Context, engagementID int64) ([]Edge, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT from_kind, from_id, to_kind, to_id, rel FROM edges WHERE engagement_id=$1 ORDER BY id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Edge
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.FromKind, &e.FromID, &e.ToKind, &e.ToID, &e.Rel); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- planner calls ---------------------------------------------------------

// PlannerCall is one archived LLM call, replayable.
type PlannerCall struct {
	Model         string          `json:"model"`
	Temperature   float64         `json:"temperature"`
	SystemPrompt  string          `json:"system_prompt"`
	Prompt        string          `json:"prompt"`
	RawCompletion string          `json:"raw_completion"`
	Parsed        json.RawMessage `json:"parsed,omitempty"`
	Rejected      json.RawMessage `json:"rejected,omitempty"`
	Error         string          `json:"error"`
}

// SavePlannerCall archives a planner invocation; without it an inferred intent is
// inadmissible.
func (s *Store) SavePlannerCall(ctx context.Context, engagementID int64, runID *int64, c PlannerCall) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO planner_calls
			(engagement_id, run_id, model, temperature, system_prompt, prompt, raw_completion, parsed, rejected, error)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		engagementID, runID, c.Model, c.Temperature, c.SystemPrompt, c.Prompt, c.RawCompletion,
		nullableJSON(c.Parsed), nullableJSON(c.Rejected), c.Error).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("ledger: save planner call: %w", err)
	}
	return id, nil
}

func nullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return []byte(raw)
}

// nonNilStrings keeps pgx from writing NULL into a NOT NULL text[] column.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// nonNilIDs is the same for BIGINT[].
func nonNilIDs(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}
