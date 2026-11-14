package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"youkai/internal/config"
	"youkai/internal/discipline"
	"youkai/internal/engine"
	"youkai/internal/ledger"
	"youkai/internal/planner"
)

// ---- fixtures --------------------------------------------------------------

func testDSN() string {
	if v := os.Getenv("YOUKAI_TEST_DSN"); v != "" {
		return v
	}
	return "postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai_test?sslmode=disable"
}

type fakeDispatcher struct {
	calls int
	obs   ledger.Observation
	err   error
}

func (f *fakeDispatcher) Run(_ context.Context, _ int64, _ string, _ map[string]any) (ledger.Observation, error) {
	f.calls++
	return f.obs, f.err
}

type fixture struct {
	srv    *Server
	store  *ledger.Store
	disp   *fakeDispatcher
	client *http.Client
	token  string
	eng    ledger.Engagement
}

// newFixture builds the default server: no high-auth key, no RequireHighAuth.
func newFixture(t *testing.T, highAuthKey string) *fixture {
	t.Helper()
	return newFixtureWith(t, func(c *Config) { c.HighAuthKey = highAuthKey })
}

// newFixtureWith lets a test change the server configuration (the tier-2 gate in
// particular) without duplicating the whole setup.
func newFixtureWith(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := ledger.Open(ctx, testDSN())
	if err != nil {
		t.Skipf("no PostgreSQL (%v); skipping API integration tests", err)
	}
	t.Cleanup(store.Close)
	// Migrate FIRST: on a clean database (CI) the settings table does not exist
	// yet, and the per-test cleanup below would fail before anything ran.
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// One global settings row backs "the LLM configuration", so each test starts
	// from an empty one. Scoped to that key on purpose: other packages' tests may
	// hold settings rows of their own while this package runs in parallel.
	if _, err := store.Pool().Exec(ctx, `DELETE FROM settings WHERE key = $1`, config.KeyLLM); err != nil {
		t.Fatalf("clear settings: %v", err)
	}

	disp := &fakeDispatcher{obs: ledger.Observation{
		RequestIDs: []string{"R9000-aa"},
		Facts: []ledger.FactSeed{{
			Statement: "param probe hit ssti", Evidence: map[string]any{"request_id": "R9000-aa"},
		}},
		Findings: []ledger.FindingSeed{{Title: "SSTI 存在性", Severity: "high", Where: "http://127.0.0.1:9/s"}},
	}}
	// Runtime configuration: a settings store with a passphrase, and a planner
	// manager that starts disabled (tests install what they need).
	settings := config.New(store.Pool(), []byte("test-session-passphrase"))
	plannerMgr := planner.NewManager(store)

	cfg := Config{
		Addr: "127.0.0.1:0", Store: store, Dispatcher: disp,
		ArtifactDir: t.TempDir(), MaxSteps: 3,
		Settings: settings, Planner: plannerMgr,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	scope := discipline.NewScope(discipline.Scope{
		Project: "lab", Include: []string{"127.0.0.1"}, AllowPrivate: true,
		AllowActiveProbes: true, Basis: "self-hosted lab", Operator: "tester",
		RPS: 100,
	})
	name := fmt.Sprintf("api-%s-%d", t.Name()[:min(len(t.Name()), 16)], time.Now().UnixNano())
	eng, err := store.CreateEngagement(context.Background(), name, scope)
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	return &fixture{srv: srv, store: store, disp: disp, token: srv.Token(), eng: eng,
		client: &http.Client{Transport: &roundTripper{handler: srv.Handler()}}}
}

// roundTripper sends test requests straight to the handler.
type roundTripper struct{ handler http.Handler }

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	res := rec.Result()
	// Drain into memory so the caller can close it normally.
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(res.Body)
	res.Body = ioNopCloser{bytes.NewReader(buf.Bytes())}
	return res, nil
}

type ioNopCloser struct{ *bytes.Reader }

func (ioNopCloser) Close() error { return nil }

func (f *fixture) do(t *testing.T, method, path string, body any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req, err := http.NewRequest(method, "http://127.0.0.1"+path, &buf)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Youkai-Token", f.token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- auth ------------------------------------------------------------------

func TestTokenRequired(t *testing.T) {
	f := newFixture(t, "")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/api/engagements", nil)
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	// With the token it works.
	if code, _ := f.do(t, http.MethodGet, "/api/engagements", nil, nil); code != http.StatusOK {
		t.Fatalf("authorised request = %d", code)
	}
}

func TestForeignOriginRejected(t *testing.T) {
	f := newFixture(t, "")
	code, _ := f.do(t, http.MethodGet, "/api/engagements", nil, map[string]string{
		"Origin": "http://evil.example",
	})
	if code != http.StatusForbidden {
		t.Fatalf("foreign origin = %d, want 403", code)
	}
	// The loopback origin of the configured port is allowed (here: 127.0.0.1:0 ->
	// the port is 0, so send the exact allowed string).
	code, _ = f.do(t, http.MethodGet, "/api/engagements", nil, map[string]string{
		"Origin": "http://127.0.0.1:0",
	})
	if code != http.StatusOK {
		t.Fatalf("loopback origin = %d, want 200", code)
	}
}

func TestSPAShellIsPublicButDataIsNot(t *testing.T) {
	f := newFixture(t, "")
	// Shell: no token needed, no data inside.
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("shell = %d", res.StatusCode)
	}
	if csp := res.Header.Get("Content-Security-Policy"); csp == "" {
		t.Fatal("the shell has no CSP")
	}
	// Data: token required.
	req2, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/api/health", nil)
	res2, err := f.client.Do(req2)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("health without token = %d", res2.StatusCode)
	}
}

// ---- engagement validation -------------------------------------------------

func TestEngagementScopeIsValidated(t *testing.T) {
	f := newFixture(t, "")
	code, body := f.do(t, http.MethodPost, "/api/engagements", map[string]any{
		"name":  "bad-scope",
		"scope": map[string]any{"include": []string{"*"}, "basis": "self-hosted lab", "operator": "t"},
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("top-level wildcard accepted: %d %v", code, body)
	}
	code, _ = f.do(t, http.MethodPost, "/api/engagements", map[string]any{
		"name":  "no-basis",
		"scope": map[string]any{"include": []string{"127.0.0.1"}, "basis": "short", "operator": "t"},
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("short basis accepted: %d", code)
	}
}

// ---- the double condition --------------------------------------------------

func TestTierOneCannotBeApproved(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	it, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
		Capability: "probe", Args: map[string]any{"url": "http://127.0.0.1/x"}, Tier: 1, Rationale: "r",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/intents/%d/approve", f.eng.ID, it.ID),
		map[string]any{"operator": "alice", "basis": "self-hosted lab"}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("tier-1 approval = %d %v", code, body)
	}
}

// TestExecuteNeedsOnlyAnApprovalByDefault is the ADR-006 contract: one operator
// click, no signature, exactly one execution, and the evidence still lands as a
// candidate (a human step never self-verifies).
func TestExecuteNeedsOnlyAnApprovalByDefault(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()

	it, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
		Capability: "param",
		Args:       map[string]any{"url": "http://127.0.0.1:9/s?q=1", "param": "q"},
		Tier:       2, RequiresApproval: true, Rationale: "existence probe",
	})
	if err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	execPath := fmt.Sprintf("/api/engagements/%d/intents/%d/execute", f.eng.ID, it.ID)
	approvePath := fmt.Sprintf("/api/engagements/%d/intents/%d/approve", f.eng.ID, it.ID)

	// 1) no approval row -> refused, nothing dispatched. The approval row is the
	// human act; it is not optional, only the signature is.
	if code, _ := f.do(t, http.MethodPost, execPath, map[string]any{"operator": "alice"}, nil); code != http.StatusForbidden {
		t.Fatalf("execute without approval = %d, want 403", code)
	}
	if f.disp.calls != 0 {
		t.Fatalf("capability ran without approval (%d calls)", f.disp.calls)
	}

	// 2) one UI click: operator + basis, no high_auth_path, no key on the server.
	code, body := f.do(t, http.MethodPost, approvePath, map[string]any{
		"operator": "alice", "basis": "self-hosted lab, ticket 42",
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("approve = %d %v", code, body)
	}

	// 3) that approval is enough to run it - once.
	code, body = f.do(t, http.MethodPost, execPath, map[string]any{"operator": "alice"}, nil)
	if code != http.StatusOK {
		t.Fatalf("execute with an approval = %d %v, want 200", code, body)
	}
	if f.disp.calls != 1 {
		t.Fatalf("capability calls = %d, want 1", f.disp.calls)
	}

	// 4) consumed: a second execute is refused even with the same operator.
	if code, _ := f.do(t, http.MethodPost, execPath, map[string]any{"operator": "alice"}, nil); code != http.StatusForbidden {
		t.Fatalf("second execute = %d, want 403", code)
	}
	if f.disp.calls != 1 {
		t.Fatalf("capability ran twice (%d)", f.disp.calls)
	}

	// 5) evidence landed, as candidates.
	g, err := f.store.Graph(ctx, f.eng.ID)
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	if len(g.Facts) == 0 || len(g.Findings) == 0 {
		t.Fatalf("evidence not ingested: facts=%d findings=%d", len(g.Facts), len(g.Findings))
	}
	for _, fd := range g.Findings {
		if fd.State != ledger.FindingCandidate {
			t.Fatalf("a human step produced a non-candidate finding: %q", fd.State)
		}
	}
}

// TestExecuteWithHighAuthRequired keeps the ADR-005 door available for
// deployments that want it: same approval row, plus a verified signed record.
func TestExecuteWithHighAuthRequired(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	f := newFixtureWith(t, func(c *Config) {
		c.HighAuthKey = key
		c.RequireHighAuth = true
	})
	ctx := context.Background()

	it, _, err := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
		Capability: "param",
		Args:       map[string]any{"url": "http://127.0.0.1:9/s?q=1", "param": "q"},
		Tier:       2, RequiresApproval: true, Rationale: "existence probe",
	})
	if err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	execPath := fmt.Sprintf("/api/engagements/%d/intents/%d/execute", f.eng.ID, it.ID)
	approvePath := fmt.Sprintf("/api/engagements/%d/intents/%d/approve", f.eng.ID, it.ID)

	if code, body := f.do(t, http.MethodPost, approvePath, map[string]any{
		"operator": "alice", "basis": "self-hosted lab",
	}, nil); code != http.StatusCreated {
		t.Fatalf("approve = %d %v", code, body)
	}

	// Approval alone is refused in this mode.
	if code, _ := f.do(t, http.MethodPost, execPath, map[string]any{"operator": "alice"}, nil); code != http.StatusPreconditionRequired {
		t.Fatalf("execute without high-auth = %d, want 412", code)
	}
	if f.disp.calls != 0 {
		t.Fatal("capability ran without the high-auth condition")
	}

	// A record signed with the wrong key is refused.
	badPath := writeHighAuth(t, key, "mallory", "http://127.0.0.1:9", time.Hour, "wrong-key")
	if code, _ := f.do(t, http.MethodPost, execPath, map[string]any{
		"operator": "alice", "high_auth_path": badPath,
	}, nil); code != http.StatusForbidden {
		t.Fatalf("forged high-auth = %d, want 403", code)
	}
	if f.disp.calls != 0 {
		t.Fatal("capability ran with a bad high-auth record")
	}

	// A record that does not cover the target is refused.
	otherPath := writeHighAuth(t, key, "alice", "https://elsewhere.example", time.Hour, key)
	if code, _ := f.do(t, http.MethodPost, execPath, map[string]any{
		"operator": "alice", "high_auth_path": otherPath,
	}, nil); code != http.StatusForbidden {
		t.Fatalf("out-of-coverage high-auth = %d, want 403", code)
	}
	if f.disp.calls != 0 {
		t.Fatal("capability ran with an out-of-coverage record")
	}

	// Both conditions -> one execution, then the approval is spent.
	goodPath := writeHighAuth(t, key, "alice", "http://127.0.0.1:9", time.Hour, key)
	code, body := f.do(t, http.MethodPost, execPath, map[string]any{
		"operator": "alice", "high_auth_path": goodPath,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("execute with both conditions = %d %v", code, body)
	}
	if f.disp.calls != 1 {
		t.Fatalf("capability calls = %d, want 1", f.disp.calls)
	}
	if code, _ := f.do(t, http.MethodPost, execPath, map[string]any{
		"operator": "alice", "high_auth_path": goodPath,
	}, nil); code != http.StatusForbidden {
		t.Fatalf("second execute = %d, want 403", code)
	}
}

func TestExecuteRejectsAnOperatorWhoDidNotApprove(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	f := newFixture(t, key)
	ctx := context.Background()
	it, _, _ := f.store.EnsureIntent(ctx, f.eng.ID, ledger.IntentSpec{
		Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:9/s", "param": "q"},
		Tier: 2, RequiresApproval: true, Rationale: "r",
	})
	if code, _ := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/intents/%d/approve", f.eng.ID, it.ID),
		map[string]any{"operator": "alice", "basis": "self-hosted lab"}, nil); code != http.StatusCreated {
		t.Fatalf("approve = %d", code)
	}
	goodPath := writeHighAuth(t, key, "alice", "http://127.0.0.1:9", time.Hour, key)
	if code, _ := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/intents/%d/execute", f.eng.ID, it.ID),
		map[string]any{"operator": "bob", "high_auth_path": goodPath}, nil); code != http.StatusForbidden {
		t.Fatalf("bob executed alice's approval: %d", code)
	}
	if f.disp.calls != 0 {
		t.Fatal("capability ran for a non-approving operator")
	}
}

func TestVerdictRequiresExplicitConfirmation(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	res, err := f.store.Ingest(ctx, f.eng.ID, nil, nil, ledger.Observation{
		Findings: []ledger.FindingSeed{{Title: "reflection", Severity: "medium", Where: "http://127.0.0.1/s"}},
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	path := fmt.Sprintf("/api/engagements/%d/findings/%d/verdict", f.eng.ID, res.FindingIDs[0])

	if code, _ := f.do(t, http.MethodPost, path, map[string]any{"operator": "alice", "note": "n"}, nil); code != http.StatusBadRequest {
		t.Fatalf("verdict without confirm = %d", code)
	}
	if code, _ := f.do(t, http.MethodPost, path, map[string]any{
		"operator": "alice", "note": "n", "confirm": true,
	}, nil); code != http.StatusOK {
		t.Fatalf("confirmed verdict = %d", code)
	}
	g, _ := f.store.Graph(ctx, f.eng.ID)
	if g.Findings[0].State != ledger.FindingVerified {
		t.Fatalf("finding state = %q", g.Findings[0].State)
	}
}

// ---- report ----------------------------------------------------------------

func TestReportIsALedgerProjection(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	_, _ = f.store.Ingest(ctx, f.eng.ID, nil, nil, ledger.Observation{
		Facts:    []ledger.FactSeed{{Statement: "GET http://127.0.0.1 -> 200", Evidence: map[string]any{"request_id": "R1"}}},
		Findings: []ledger.FindingSeed{{Title: "缺失 CSP", Severity: "low", Where: "http://127.0.0.1/"}},
	})
	code, body := f.do(t, http.MethodGet, fmt.Sprintf("/api/engagements/%d/report", f.eng.ID), nil, nil)
	if code != http.StatusOK {
		t.Fatalf("report = %d", code)
	}
	if body["engagement"] != f.eng.Name {
		t.Fatalf("report engagement = %v", body["engagement"])
	}
	if body["exploit_provider"] == "" {
		t.Fatal("report does not state the provider status")
	}

	// markdown form
	req, _ := http.NewRequest(http.MethodGet,
		fmt.Sprintf("http://127.0.0.1/api/engagements/%d/report?format=md", f.eng.ID), nil)
	req.Header.Set("X-Youkai-Token", f.token)
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(res.Body)
	md := buf.String()
	if !bytes.Contains([]byte(md), []byte("# youkai 证据报告")) {
		t.Fatalf("markdown report missing title: %q", md[:min(len(md), 80)])
	}
}

// ---- helpers ---------------------------------------------------------------

// writeHighAuth creates a signed record the way the human's tooling does
// (JSON.stringify with sorted keys, no HTML escaping, HMAC-SHA256).
func writeHighAuth(t *testing.T, serverKey, approver, asset string, ttl time.Duration, signKey string) string {
	t.Helper()
	now := time.Now().UTC()
	payload := map[string]any{
		"schema":     discipline.HighAuthSchema,
		"tier":       "highest",
		"basis":      "self-hosted lab, api test",
		"approver":   approver,
		"assets":     []any{asset},
		"actions":    []any{"read-only"},
		"issued_at":  now.Format(time.RFC3339),
		"expires_at": now.Add(ttl).Format(time.RFC3339),
		"nonce":      "nonce-" + approver,
	}
	canonical := canonicalJSON(t, payload)
	mac := hmac.New(sha256.New, []byte(signKey))
	mac.Write([]byte(canonical))
	rec := map[string]any{
		"schema":    discipline.HighAuthSchema,
		"payload":   payload,
		"signature": hex.EncodeToString(mac.Sum(nil)),
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := t.TempDir() + "/high-auth.json"
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = serverKey
	return path
}

// canonicalJSON mirrors Fairy's JSON.stringify(payload, Object.keys(payload).sort()).
func canonicalJSON(t *testing.T, m map[string]any) string {
	t.Helper()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		var vb bytes.Buffer
		e2 := json.NewEncoder(&vb)
		e2.SetEscapeHTML(false)
		if err := e2.Encode(m[k]); err != nil {
			t.Fatalf("encode %q: %v", k, err)
		}
		buf.Write(bytes.TrimRight(vb.Bytes(), "\n"))
	}
	buf.WriteByte('}')
	return buf.String()
}

var _ engine.Dispatcher = (*fakeDispatcher)(nil)
