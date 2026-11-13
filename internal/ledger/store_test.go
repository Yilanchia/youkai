package ledger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"youkai/internal/discipline"
)

// TestDSN is the local integration database. The tests are skipped when it is
// not reachable: they prove database-level guarantees, so a fake is no substitute.
func testDSN() string {
	if v := os.Getenv("YOUKAI_TEST_DSN"); v != "" {
		return v
	}
	return "postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai_test?sslmode=disable"
}

func openStore(t *testing.T) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := Open(ctx, testDSN())
	if err != nil {
		t.Skipf("no PostgreSQL at YOUKAI_TEST_DSN (%v); skipping integration tests", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func uniqueName(t *testing.T) string {
	t.Helper()
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "t-" + t.Name()[:min(len(t.Name()), 20)] + "-" + hex.EncodeToString(b[:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func newEngagement(t *testing.T, s *Store) Engagement {
	t.Helper()
	scope := discipline.NewScope(discipline.Scope{
		Project: "lab", Include: []string{"127.0.0.1"}, AllowPrivate: true,
		Basis: "self-hosted lab", Operator: "tester",
	})
	e, err := s.CreateEngagement(context.Background(), uniqueName(t), scope)
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	return e
}

// TestMigrateIsIdempotent.
func TestMigrateIsIdempotent(t *testing.T) {
	s := openStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// TestIngestIdempotency: the same fact twice is one row, and the counters say so.
func TestIngestIdempotency(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()

	obs := Observation{
		Facts: []FactSeed{{
			Statement: "GET http://127.0.0.1/.git/config -> 200",
			Evidence:  map[string]any{"request_id": "R1"},
			Tags:      []string{"probe"},
			Anchors:   []string{"host:127.0.0.1"},
		}},
		Findings: []FindingSeed{{
			Title: "缺 CSP", Severity: "low", Kind: "header", Where: "http://127.0.0.1/",
			Evidence: map[string]any{"request_id": "R1"},
		}},
	}
	first, err := s.Ingest(ctx, e.ID, nil, nil, obs)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if first.NewFacts != 1 || len(first.FindingIDs) != 1 {
		t.Fatalf("first ingest = %+v", first)
	}
	second, err := s.Ingest(ctx, e.ID, nil, nil, obs)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if second.NewFacts != 0 || second.Deduped != 1 {
		t.Fatalf("second ingest not deduped: %+v", second)
	}

	g, err := s.Graph(ctx, e.ID)
	if err != nil {
		t.Fatalf("Graph: %v", err)
	}
	if len(g.Facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(g.Facts))
	}
	if len(g.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(g.Findings))
	}
	if len(g.Assets) != 1 || g.Assets[0].Value != "host:127.0.0.1" {
		t.Fatalf("asset anchoring failed: %+v", g.Assets)
	}
	// The fact must be anchored to the host asset.
	var anchored bool
	for _, ed := range g.Edges {
		if ed.FromKind == "fact" && ed.ToKind == "asset" && ed.Rel == RelAnchors {
			anchored = true
		}
	}
	if !anchored {
		t.Fatalf("no anchor edge: %+v", g.Edges)
	}
	if g.Findings[0].State != FindingCandidate {
		t.Fatalf("a new finding must be a candidate, got %q", g.Findings[0].State)
	}
}

// TestEnsureIntentDedupes: deriving the same next step twice does not fork.
func TestEnsureIntentDedupes(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()
	spec := IntentSpec{Capability: "probe", Args: map[string]any{"url": "http://127.0.0.1/x"}, Tier: 1, Rationale: "r"}

	a, created, err := s.EnsureIntent(ctx, e.ID, spec)
	if err != nil || !created {
		t.Fatalf("first: %v created=%v", err, created)
	}
	b, created, err := s.EnsureIntent(ctx, e.ID, spec)
	if err != nil || created {
		t.Fatalf("second: %v created=%v", err, created)
	}
	if a.ID != b.ID {
		t.Fatalf("dedupe returned %d then %d", a.ID, b.ID)
	}
	if list, _ := s.ListIntents(ctx, e.ID); len(list) != 1 {
		t.Fatalf("intents = %d", len(list))
	}
}

// TestApprovalRequiresTheApprovalRow is the database-level "never auto-approve"
// guarantee: flipping approved by hand is refused by the trigger.
func TestApprovalRequiresTheApprovalRow(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()

	it, _, err := s.EnsureIntent(ctx, e.ID, IntentSpec{
		Capability: "param", Args: map[string]any{"url": "http://127.0.0.1/s", "param": "q"},
		Tier: 2, RequiresApproval: true, Rationale: "existence probe",
	})
	if err != nil {
		t.Fatalf("EnsureIntent: %v", err)
	}

	// Direct flip: must fail.
	if _, err := s.Pool().Exec(ctx, `UPDATE intents SET approved=true WHERE id=$1`, it.ID); err == nil {
		t.Fatal("the database allowed approved=true without an operator approval")
	}

	// Tier-1 intents cannot be approved at all.
	tier1, _, _ := s.EnsureIntent(ctx, e.ID, IntentSpec{
		Capability: "probe", Args: map[string]any{"url": "http://127.0.0.1/y"}, Tier: 1, Rationale: "r",
	})
	if _, err := s.ApproveIntent(ctx, e.ID, tier1.ID, "alice", "lab authorisation", "", ""); err == nil {
		t.Fatal("tier-1 intent was approvable")
	}

	// The real path works.
	ap, err := s.ApproveIntent(ctx, e.ID, it.ID, "alice", "self-hosted lab, ticket 42", "", "")
	if err != nil {
		t.Fatalf("ApproveIntent: %v", err)
	}
	if ap.Fingerprint != it.Fingerprint {
		t.Fatalf("approval fingerprint %q != intent %q", ap.Fingerprint, it.Fingerprint)
	}
	got, _ := s.Intent(ctx, e.ID, it.ID)
	if !got.Approved {
		t.Fatal("approved flag did not flip")
	}

	// An approval is single-use.
	if _, err := s.ConsumeApproval(ctx, e.ID, it.ID); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.ConsumeApproval(ctx, e.ID, it.ID); err == nil {
		t.Fatal("an approval was consumed twice")
	}
}

// TestVerifiedRequiresOperatorVerdict is the database-level "never auto-upgrade".
func TestVerifiedRequiresOperatorVerdict(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()

	res, err := s.Ingest(ctx, e.ID, nil, nil, Observation{
		Findings: []FindingSeed{{Title: "reflection", Severity: "medium", Where: "http://127.0.0.1/s?q=1"}},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	fid := res.FindingIDs[0]

	// Direct UPDATE without the operator flag: the trigger refuses.
	if _, err := s.Pool().Exec(ctx, `UPDATE findings SET state='verified' WHERE id=$1`, fid); err == nil {
		t.Fatal("the database allowed candidate->verified without an operator verdict")
	}

	// Missing operator or note: refused in code as well.
	if _, err := s.VerifyFinding(ctx, e.ID, fid, "", "note"); err == nil {
		t.Fatal("verdict without an operator was accepted")
	}
	if _, err := s.VerifyFinding(ctx, e.ID, fid, "alice", ""); err == nil {
		t.Fatal("verdict without a note was accepted")
	}

	f, err := s.VerifyFinding(ctx, e.ID, fid, "alice", "reproduced in a browser, context confirmed")
	if err != nil {
		t.Fatalf("VerifyFinding: %v", err)
	}
	if f.State != FindingVerified || f.Operator != "alice" || f.VerifiedAt == nil {
		t.Fatalf("finding after verdict = %+v", f)
	}
	// A second verdict on a verified finding is refused (not a candidate anymore).
	if _, err := s.VerifyFinding(ctx, e.ID, fid, "alice", "again"); err == nil {
		t.Fatal("re-verified a finding that was already verified")
	}
}

// TestAuditIsAppendOnly is the "audit table cannot be rewritten" guarantee.
func TestAuditIsAppendOnly(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()

	if err := s.Record(ctx, discipline.AuditEvent{
		RequestID: "R-append-only-" + e.Name, Engagement: e.Name, TS: time.Now().UTC(),
		Method: "GET", URL: "http://127.0.0.1/", Host: "127.0.0.1",
		Status: 200, Bytes: 12, Verdict: discipline.VerdictAllowed, Purpose: "probe",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rid := "R-append-only-" + e.Name
	if _, err := s.Pool().Exec(ctx, `UPDATE audit_log SET status=999 WHERE request_id=$1`, rid); err == nil {
		t.Fatal("audit_log allowed an UPDATE")
	}
	if _, err := s.Pool().Exec(ctx, `DELETE FROM audit_log WHERE request_id=$1`, rid); err == nil {
		t.Fatal("audit_log allowed a DELETE")
	}
	rows, err := s.AuditTail(ctx, e.Name, 10)
	if err != nil {
		t.Fatalf("AuditTail: %v", err)
	}
	if len(rows) != 1 || rows[0].Status != 200 {
		t.Fatalf("audit row changed: %+v", rows)
	}
	allowed, blocked, errored, err := s.AuditStats(ctx, e.Name)
	if err != nil || allowed != 1 || blocked != 0 || errored != 0 {
		t.Fatalf("stats = %d/%d/%d err=%v", allowed, blocked, errored, err)
	}
}

// TestRunLifecycle.
func TestRunLifecycle(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()
	run, err := s.CreateRun(ctx, e.ID, map[string]any{"seed_urls": []string{"http://127.0.0.1"}})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if run.Status != "running" {
		t.Fatalf("status = %q", run.Status)
	}
	if err := s.FinishRun(ctx, run.ID, "needs_approval", "1 intent(s) need a human", 2, 3); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	got, err := s.GetRun(ctx, e.ID, run.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Status != "needs_approval" || got.Steps != 2 || got.Derived != 3 || got.EndedAt == nil {
		t.Fatalf("run = %+v", got)
	}
}

// TestGraphViewShape ensures the projection the UI consumes is complete.
func TestGraphViewShape(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()
	if _, err := s.Ingest(ctx, e.ID, nil, nil, Observation{
		Assets:   []AssetSeed{{Kind: "host", Value: "host:127.0.0.1", Props: map[string]any{"base": "http://127.0.0.1"}}},
		Facts:    []FactSeed{{Statement: "f", Evidence: map[string]any{"request_id": "R"}, Anchors: []string{"host:127.0.0.1"}}},
		Findings: []FindingSeed{{Title: "t", Severity: "high", Where: "w"}},
	}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	g, err := s.Graph(ctx, e.ID)
	if err != nil {
		t.Fatalf("Graph: %v", err)
	}
	if g.Engagement.ID != e.ID || g.Stats.Assets != 1 || g.Stats.Facts != 1 || g.Stats.Findings != 1 {
		t.Fatalf("graph = %+v", g.Stats)
	}
	if g.Stats.CandidateCount != 1 {
		t.Fatalf("candidate count = %d", g.Stats.CandidateCount)
	}
	// The scope round-trips as JSON so the UI can show the passport.
	var sc discipline.Scope
	if err := json.Unmarshal(g.Engagement.Scope, &sc); err != nil {
		t.Fatalf("scope json: %v", err)
	}
	if len(sc.Include) != 1 || !sc.AllowPrivate {
		t.Fatalf("scope round trip: %+v", sc)
	}
}

// TestPlannerCallArchive: every planner call is replayable, failures included.
func TestPlannerCallArchive(t *testing.T) {
	s := openStore(t)
	e := newEngagement(t, s)
	ctx := context.Background()
	id, err := s.SavePlannerCall(ctx, e.ID, nil, PlannerCall{
		Model: "test", Temperature: 0, SystemPrompt: "sys", Prompt: "p",
		RawCompletion: "{}", Parsed: json.RawMessage(`[{"capability":"scan"}]`), Error: "none",
	})
	if err != nil {
		t.Fatalf("SavePlannerCall: %v", err)
	}
	if id == 0 {
		t.Fatal("no id returned")
	}
	var got int
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM planner_calls WHERE engagement_id=$1`, e.ID).Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	if got != 1 {
		t.Fatalf("planner calls = %d", got)
	}
}

// TestNoScopeNoRows: an engagement created without a passport is inert.
func TestEmptyScopeIsStoredVerbatim(t *testing.T) {
	s := openStore(t)
	e, err := s.CreateEngagement(context.Background(), uniqueName(t), nil)
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	if len(e.Scope) == 0 {
		t.Fatal("scope column is null; the runtime expects JSON")
	}
	if strings.TrimSpace(string(e.Scope)) == "" {
		t.Fatal("empty scope not serialised")
	}
}
