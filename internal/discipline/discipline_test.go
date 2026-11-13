package discipline

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- test doubles ----------------------------------------------------------

type memAuditor struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   bool
}

func (m *memAuditor) Record(_ context.Context, ev AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errAuditDown
	}
	m.events = append(m.events, ev)
	return nil
}

func (m *memAuditor) all() []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]AuditEvent(nil), m.events...)
}

func (m *memAuditor) count(verdict string) int {
	n := 0
	for _, e := range m.all() {
		if e.Verdict == verdict {
			n++
		}
	}
	return n
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errAuditDown = testErr("audit store is down")

// countingServer counts how many requests actually reached the target.
func countingServer(t *testing.T) (*httptest.Server, *int32Counter) {
	t.Helper()
	c := &int32Counter{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc()
		switch r.URL.Path {
		case "/big":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("A", 5000)))
		case "/redirect-out":
			http.Redirect(w, r, "http://example.invalid/elsewhere", http.StatusFound)
		case "/redirect-in":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			w.Header().Set("Set-Cookie", "sid=SECRETVALUE; Path=/; HttpOnly; Secure; SameSite=Strict")
			w.Header().Set("X-Frame-Options", "")
			_, _ = w.Write([]byte("ok"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

type int32Counter struct {
	mu sync.Mutex
	n  int
}

func (c *int32Counter) inc() { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *int32Counter) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func testScope(t *testing.T, include ...string) *Scope {
	t.Helper()
	if len(include) == 0 {
		include = []string{"127.0.0.1"}
	}
	return NewScope(Scope{
		Project:      "lab",
		Include:      include,
		Methods:      []string{"GET", "HEAD", "OPTIONS"},
		AllowPrivate: true,
		Basis:        "self-hosted lab",
		Operator:     "tester",
		RPS:          1000,
		MaxRequests:  100,
		MaxBytes:     1024,
		MaxRedirects: 3,
		ExpiresAt:    time.Now().Add(time.Hour),
	})
}

func newTestGuard(t *testing.T, scope *Scope) (*Guard, *memAuditor) {
	t.Helper()
	aud := &memAuditor{}
	g, err := NewGuard(scope, "lab", aud)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	// No real sleeping in tests.
	g.WithOptions(GuardOptions{Sleep: func(context.Context, time.Duration) error { return nil }})
	return g, aud
}

// ---- scope -----------------------------------------------------------------

func TestScopeCheck(t *testing.T) {
	sc := testScope(t, "127.0.0.1", "*.lab.invalid", "10.1.0.0/16", "https://api.example.com:8443")

	cases := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:9000/x", true},
		{"http://sub.lab.invalid/x", true},
		{"http://lab.invalid/x", false}, // wildcard does not cover the apex
		{"http://10.1.2.3/x", true},
		{"http://10.2.2.3/x", false},
		{"https://api.example.com:8443/x", true},
		{"https://api.example.com:9443/x", false},
		{"https://other.example.com/x", false},
		{"ftp://127.0.0.1/x", false},
	}
	for _, c := range cases {
		d, err := sc.Check(c.url)
		if c.want && err != nil {
			t.Fatalf("Check(%q) refused: %v", c.url, err)
		}
		if !c.want && err == nil {
			t.Fatalf("Check(%q) allowed (matched %s)", c.url, d.Matched)
		}
	}
}

func TestScopeExcludeWins(t *testing.T) {
	sc := testScope(t, "*.lab.invalid")
	sc.Exclude = []string{"admin.lab.invalid"}
	if _, err := sc.Check("http://admin.lab.invalid/x"); err == nil {
		t.Fatal("excluded host was allowed")
	}
	if _, err := sc.Check("http://www.lab.invalid/x"); err != nil {
		t.Fatalf("non-excluded host refused: %v", err)
	}
}

func TestScopeValidation(t *testing.T) {
	bad := []Scope{
		{Include: []string{"x"}, Basis: "short", Operator: "t"},
		{Include: []string{"x"}, Basis: "long enough basis", Operator: ""},
		{Include: nil, Basis: "long enough basis", Operator: "t"},
		{Include: []string{"*"}, Basis: "long enough basis", Operator: "t"},
		{Include: []string{"*.com"}, Basis: "long enough basis", Operator: "t"},
	}
	for i, b := range bad {
		if err := NewScope(b).Validate(); err == nil {
			t.Fatalf("case %d: invalid scope accepted", i)
		}
	}
	expired := new(Scope)
	*expired = *testScope(t)
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	if err := expired.Validate(); err == nil {
		t.Fatal("expired scope accepted")
	}
}

func TestPrivateTargetNeedsOptIn(t *testing.T) {
	sc := testScope(t, "127.0.0.1")
	sc.AllowPrivate = false
	if _, err := sc.Check("http://127.0.0.1:8080/"); err == nil {
		t.Fatal("loopback allowed without allow_private")
	}
}

// ---- guard: the happy path and the audit trail -----------------------------

func TestGuardAllowsAndAudits(t *testing.T) {
	srv, counter := countingServer(t)
	g, aud := newTestGuard(t, testScope(t))

	res, err := g.Do(context.Background(), Request{URL: srv.URL + "/ok", Purpose: "probe"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != 200 || res.RequestID == "" {
		t.Fatalf("bad response: %+v", res)
	}
	if counter.get() != 1 {
		t.Fatalf("target saw %d requests, want 1", counter.get())
	}
	ev := aud.all()
	if len(ev) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(ev))
	}
	if ev[0].RequestID != res.RequestID || ev[0].Verdict != VerdictAllowed {
		t.Fatalf("audit row mismatch: %+v", ev[0])
	}
	if ev[0].Purpose != "probe" || ev[0].Host != "127.0.0.1" {
		t.Fatalf("audit row missing context: %+v", ev[0])
	}
}

func TestGuardRefusesOutOfScopeWithoutSending(t *testing.T) {
	srv, counter := countingServer(t)
	sc := testScope(t, "example.invalid") // the test server is not in scope
	g, aud := newTestGuard(t, sc)

	if _, err := g.Do(context.Background(), Request{URL: srv.URL + "/ok"}); err == nil {
		t.Fatal("out-of-scope request succeeded")
	}
	if counter.get() != 0 {
		t.Fatalf("target received %d requests despite being out of scope", counter.get())
	}
	if aud.count(VerdictBlocked) != 1 {
		t.Fatalf("refusal was not audited: %+v", aud.all())
	}
}

func TestGuardRefusesWriteMethodsAndAudits(t *testing.T) {
	srv, counter := countingServer(t)
	g, aud := newTestGuard(t, testScope(t))
	if _, err := g.Do(context.Background(), Request{URL: srv.URL + "/ok", Method: "POST"}); err == nil {
		t.Fatal("POST was sent")
	}
	if counter.get() != 0 {
		t.Fatalf("write method reached the target")
	}
	if aud.count(VerdictBlocked) != 1 {
		t.Fatal("method refusal not audited")
	}
}

func TestGuardStopsRedirectLeavingScope(t *testing.T) {
	srv, _ := countingServer(t)
	g, aud := newTestGuard(t, testScope(t))

	_, err := g.Do(context.Background(), Request{URL: srv.URL + "/redirect-out", FollowRedirects: true})
	if err == nil {
		t.Fatal("redirect out of scope was followed")
	}
	var sawBlock bool
	for _, e := range aud.all() {
		if e.Verdict == VerdictBlocked && strings.Contains(e.Reason, "redirect") {
			sawBlock = true
		}
	}
	if !sawBlock {
		t.Fatalf("redirect refusal not audited: %+v", aud.all())
	}
}

func TestGuardFollowsInScopeRedirect(t *testing.T) {
	srv, _ := countingServer(t)
	g, aud := newTestGuard(t, testScope(t))
	res, err := g.Do(context.Background(), Request{URL: srv.URL + "/redirect-in", FollowRedirects: true})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("final status = %d", res.Status)
	}
	if len(res.Redirects) != 1 {
		t.Fatalf("redirects = %+v", res.Redirects)
	}
	if aud.count(VerdictAllowed) != 2 {
		t.Fatalf("each hop must be audited: %+v", aud.all())
	}
}

func TestGuardTruncatesBody(t *testing.T) {
	srv, _ := countingServer(t)
	sc := testScope(t)
	sc.MaxBytes = 64
	g, _ := newTestGuard(t, sc)
	res, err := g.Do(context.Background(), Request{URL: srv.URL + "/big"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !res.Truncated || len(res.Body) != 64 {
		t.Fatalf("body not minimised: truncated=%v len=%d", res.Truncated, len(res.Body))
	}
}

func TestGuardAuditFailureBlocksRequest(t *testing.T) {
	srv, counter := countingServer(t)
	aud := &memAuditor{fail: true}
	g, err := NewGuard(testScope(t), "lab", aud)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if _, err := g.Do(context.Background(), Request{URL: srv.URL + "/ok"}); err == nil {
		t.Fatal("request proceeded without an audit record")
	}
	// The bytes may have left (the row is written with the outcome), but the
	// response must not be handed back: no evidence without an audit trail.
	if counter.get() > 1 {
		t.Fatalf("guard retried while auditing was down (%d requests)", counter.get())
	}
}

func TestGuardRequestBudget(t *testing.T) {
	srv, _ := countingServer(t)
	sc := testScope(t)
	sc.MaxRequests = 2
	g, _ := newTestGuard(t, sc)
	for i := 0; i < 2; i++ {
		if _, err := g.Do(context.Background(), Request{URL: srv.URL + "/ok"}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, err := g.Do(context.Background(), Request{URL: srv.URL + "/ok"}); err == nil {
		t.Fatal("budget was not enforced")
	}
}

func TestGuardExpiredScopeReturnsErrExpired(t *testing.T) {
	srv, counter := countingServer(t)
	sc := testScope(t) // valid for one hour
	g, aud := newTestGuard(t, sc)

	// Advance the guard's clock past the passport's expiry.
	g.WithOptions(GuardOptions{Now: func() time.Time { return time.Now().Add(2 * time.Hour) }})
	_, err := g.Do(context.Background(), Request{URL: srv.URL + "/ok"})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired scope error = %v", err)
	}
	if counter.get() != 0 {
		t.Fatalf("an expired passport still sent %d request(s)", counter.get())
	}
	if aud.count(VerdictBlocked) != 1 {
		t.Fatalf("expiry refusal not audited: %+v", aud.all())
	}
}

// TestSetScopeRejectsAnExpiredPassport: swapping in an already-dead passport is
// refused at the door.
func TestSetScopeRejectsAnExpiredPassport(t *testing.T) {
	sc := testScope(t)
	g, _ := newTestGuard(t, sc)
	dead := *sc
	dead.ExpiresAt = time.Now().Add(-time.Minute)
	if err := g.SetScope(&dead); err == nil {
		t.Fatal("SetScope accepted an expired passport")
	}
}

// TestScopedDialerBlocksPrivateResolution is the SSRF half: a name that resolves
// into loopback must not be reachable when the passport does not allow it.
func TestScopedDialerBlocksPrivateResolution(t *testing.T) {
	sc := testScope(t, "public.example.invalid")
	sc.AllowPrivate = false
	d := newScopedDialer(sc, time.Second)
	// Exercise the control callback directly: it is what sees the resolved IP.
	host, port, _ := net.SplitHostPort("127.0.0.1:80")
	if host == "" || port == "" {
		t.Fatal("bad test setup")
	}
	if err := d.control("tcp", "127.0.0.1:1234", nil); err == nil {
		t.Fatal("dialer allowed a loopback address")
	}
	priv := testScope(t, "10.0.0.0/8")
	priv.AllowPrivate = true
	d2 := newScopedDialer(priv, time.Second)
	if err := d2.control("tcp", "10.1.2.3:80", nil); err != nil {
		t.Fatalf("dialer refused an explicitly included private address: %v", err)
	}
	if err := d2.control("tcp", "192.168.1.1:80", nil); err == nil {
		t.Fatal("dialer allowed a private address outside the include list")
	}
}

// ---- headers ---------------------------------------------------------------

func TestSanitizeHeadersKeepsCookieFlagsRedactsValue(t *testing.T) {
	h := http.Header{}
	h.Set("Set-Cookie", "sid=SUPERSECRET; Path=/; HttpOnly; Secure; SameSite=Strict")
	h.Set("Authorization", "Bearer SUPERSECRET")
	h.Set("Content-Security-Policy", "default-src 'none'")
	out := SanitizeHeaders(h)

	if strings.Contains(out["Set-Cookie"], "SUPERSECRET") {
		t.Fatalf("cookie value leaked: %q", out["Set-Cookie"])
	}
	for _, want := range []string{"sid=<redacted>", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(out["Set-Cookie"], want) {
			t.Fatalf("cookie flags lost: %q (missing %q)", out["Set-Cookie"], want)
		}
	}
	if out["Authorization"] != "<redacted>" {
		t.Fatalf("authorization not redacted: %q", out["Authorization"])
	}
	if out["Content-Security-Policy"] != "default-src 'none'" {
		t.Fatalf("security header mangled: %q", out["Content-Security-Policy"])
	}
}

// ---- high auth -------------------------------------------------------------

// signRecord reproduces Fairy's HMAC canonicalisation, so a record produced by the
// human's tooling verifies here.
func signRecord(t *testing.T, key string, payload map[string]any) *HighAuth {
	t.Helper()
	return signWith(t, key, payload)
}

func TestHighAuthVerify(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	payload := map[string]any{
		"schema":     HighAuthSchema,
		"tier":       "highest",
		"basis":      "self-hosted lab, ticket 42",
		"approver":   "alice",
		"assets":     []any{"127.0.0.1", "*.lab.invalid"},
		"actions":    []any{"read-only"},
		"issued_at":  time.Now().UTC().Format(time.RFC3339),
		"expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		"nonce":      "abc123",
	}
	rec := signRecord(t, key, payload)

	grant, err := rec.Verify(key, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if grant.Operator() != "alice" {
		t.Fatalf("approver lost: %q", grant.Approver)
	}
	if !grant.Covers("http://127.0.0.1:8080/x") {
		t.Fatal("grant does not cover the authorised host")
	}
	if grant.Covers("https://evil.invalid/x") {
		t.Fatal("grant covered an unauthorised host")
	}

	// Wrong key.
	if _, err := rec.Verify("ffffffffffffffffffffffffffffffff", time.Now()); err == nil {
		t.Fatal("signature verified with the wrong key")
	}
	// Tampered payload.
	tampered := *rec
	tampered.Payload = map[string]any{}
	for k, v := range payload {
		tampered.Payload[k] = v
	}
	tampered.Payload["approver"] = "mallory"
	if _, err := tampered.Verify(key, time.Now()); err == nil {
		t.Fatal("a modified payload verified")
	}
	// Expired.
	expired := map[string]any{}
	for k, v := range payload {
		expired[k] = v
	}
	expired["expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	recExpired := signRecord(t, key, expired)
	if _, err := recExpired.Verify(key, time.Now()); err == nil {
		t.Fatal("expired high-auth verified")
	}
	// Escalated action.
	wrongAction := map[string]any{}
	for k, v := range payload {
		wrongAction[k] = v
	}
	wrongAction["actions"] = []any{"read-only", "exploit"}
	if _, err := signRecord(t, key, wrongAction).Verify(key, time.Now()); err == nil {
		t.Fatal("a high-auth record claiming more than read-only verified")
	}
}

// Operator is a small helper used above; the grant field is Approver.
func (g *HighAuthGrant) Operator() string { return g.Approver }

// TestHighAuthCanonicalisationMatchesJS pins the exact canonical JSON, because the
// whole point is that a record signed by the human's Node tooling verifies here.
func TestHighAuthCanonicalisationMatchesJS(t *testing.T) {
	payload := map[string]any{
		"b": "2", "a": "1", "n": float64(3),
	}
	got, err := canonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	want := `{"a":"1","b":"2","n":3}`
	if got != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
	// Non-ASCII must not be escaped into \u form.
	got, _ = canonicalJSON(map[string]any{"中文": "靶场"})
	if !strings.Contains(got, "靶场") {
		t.Fatalf("canonical JSON escaped UTF-8: %s", got)
	}
}

// ---- helpers used by the ledger/API tests ----------------------------------

// HighAuthJSON is a test helper exported for other packages' tests.
func HighAuthJSON(t *testing.T, key string, payload map[string]any) []byte {
	t.Helper()
	rec := signWith(t, key, payload)
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal high-auth: %v", err)
	}
	return b
}

func signWith(t *testing.T, key string, payload map[string]any) *HighAuth {
	t.Helper()
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	mac := hmacNew(key, canonical)
	return &HighAuth{Schema: HighAuthSchema, Payload: payload, Signature: mac}
}

// hmacNew is the test-side signer: the same HMAC the human's tooling uses.
func hmacNew(key, canonical string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// ---- Authorize: the gate a non-guard sender (the browser) must pass ---------

func TestAuthorizeWritesTheAuditRowItGrants(t *testing.T) {
	srv, counter := countingServer(t)
	g, aud := newTestGuard(t, testScope(t))

	auth, err := g.Authorize(context.Background(), "GET", srv.URL+"/ok", "browser", map[string]any{"resource_type": "Document"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.RequestID == "" {
		t.Fatal("no request id issued")
	}
	events := aud.all()
	if len(events) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(events))
	}
	if events[0].RequestID != auth.RequestID || events[0].Verdict != VerdictAllowed {
		t.Fatalf("audit row does not match the grant: %+v", events[0])
	}
	if events[0].Detail["sent_by"] != "browser" {
		t.Fatalf("audit row does not say who sent it: %+v", events[0].Detail)
	}
	// Authorize does NOT send: the target must stay untouched.
	if counter.get() != 0 {
		t.Fatalf("Authorize sent %d request(s); it must only decide", counter.get())
	}
}

func TestAuthorizeRefusesOutOfScope(t *testing.T) {
	g, aud := newTestGuard(t, testScope(t, "example.invalid"))
	if _, err := g.Authorize(context.Background(), "GET", "https://evil.invalid/x", "browser", nil); err == nil {
		t.Fatal("out-of-scope request authorised")
	}
	if aud.count(VerdictBlocked) != 1 {
		t.Fatalf("blocked request not audited: %+v", aud.all())
	}
}

func TestAuthorizeRefusesWhenAuditingIsDown(t *testing.T) {
	aud := &memAuditor{fail: true}
	g, err := NewGuard(testScope(t), "lab", aud)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if _, aerr := g.Authorize(context.Background(), "GET", "http://127.0.0.1:9/x", "browser", nil); aerr == nil {
		t.Fatal("authorised a request while the audit store was down")
	}
}

func TestRefuseRecordsWithoutSending(t *testing.T) {
	g, aud := newTestGuard(t, testScope(t))
	g.Refuse(context.Background(), "POST", "http://127.0.0.1:9/evil", "browser", "blocked by the page gate", nil)
	if aud.count(VerdictBlocked) != 1 {
		t.Fatalf("refusal not recorded: %+v", aud.all())
	}
}

// TestCloneSharesBudgetButNotCookies is what makes per-identity sessions safe:
// accounts must not see each other's cookies, but they must draw from one budget.
func TestCloneSharesBudgetButNotCookies(t *testing.T) {
	srv, counter := countingServer(t)
	g, _ := newTestGuard(t, testScope(t))

	a := g.Clone()
	b := g.Clone()
	if a == b || a == g {
		t.Fatal("Clone returned the same guard")
	}
	if _, err := a.Do(context.Background(), Request{URL: srv.URL + "/ok"}); err != nil {
		t.Fatalf("clone request: %v", err)
	}
	if counter.get() != 1 {
		t.Fatalf("target saw %d requests", counter.get())
	}
	// The cookie from a's login lives only in a's jar.
	if got := a.SessionCookies(srv.URL); len(got) == 0 {
		t.Fatal("the clone that logged in has no cookies")
	}
	if got := b.SessionCookies(srv.URL); len(got) != 0 {
		t.Fatalf("a clone saw another clone's cookies: %+v", got)
	}
	if got := g.SessionCookies(srv.URL); len(got) != 0 {
		t.Fatalf("the parent guard saw a clone's cookies: %+v", got)
	}
	// Budget is shared: the parent's counter moved.
	if g.Used() != a.Used() {
		t.Fatalf("budget is not shared: parent=%d clone=%d", g.Used(), a.Used())
	}
}

func TestSessionCookieHeader(t *testing.T) {
	cookies := []*http.Cookie{{Name: "sid", Value: "abc"}, {Name: "role", Value: "user"}}
	if got := CookieHeader(cookies); got != "sid=abc; role=user" {
		t.Fatalf("CookieHeader = %q", got)
	}
}
