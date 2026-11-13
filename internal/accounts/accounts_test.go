package accounts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"youkai/internal/discipline"
)

// ---- fixtures --------------------------------------------------------------

type memAuditor struct {
	mu     sync.Mutex
	events []discipline.AuditEvent
}

func (m *memAuditor) Record(_ context.Context, ev discipline.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memAuditor) snapshot() []discipline.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]discipline.AuditEvent(nil), m.events...)
}

func (m *memAuditor) allowed() int {
	n := 0
	for _, ev := range m.snapshot() {
		if ev.Verdict == discipline.VerdictAllowed {
			n++
		}
	}
	return n
}

func (m *memAuditor) blocked() int {
	n := 0
	for _, ev := range m.snapshot() {
		if ev.Verdict == discipline.VerdictBlocked {
			n++
		}
	}
	return n
}

func testGuard(t *testing.T, auditor discipline.Auditor, mutate func(*discipline.Scope)) *discipline.Guard {
	t.Helper()
	scope := discipline.Scope{
		Project:      "acc-test",
		Include:      []string{"127.0.0.1"},
		Basis:        "unit test authorisation for a local httptest target",
		Operator:     "test",
		Methods:      []string{"GET", "POST"},
		AllowPrivate: true,
		RPS:          1000,
		MaxRequests:  500,
	}
	if mutate != nil {
		mutate(&scope)
	}
	g, err := discipline.NewGuard(discipline.NewScope(scope), "acc-test", auditor)
	if err != nil {
		t.Fatalf("build guard: %v", err)
	}
	return g
}

// writeManifest drops a manifest into a temp dir and returns its path.
func writeManifest(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// labServer is a tiny target: login sets a cookie, /orders/1 returns the owner's
// marker only to the owner's session, and /signup is a CAPTCHA page.
func labServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	var mu sync.Mutex
	logins := 0
	var orderID int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			mu.Lock()
			logins++
			mu.Unlock()
			_ = r.ParseForm()
			user := r.Form.Get("username")
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "sess-" + user, Path: "/"})
			http.Redirect(w, r, "/", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/orders/"):
			c, err := r.Cookie("sid")
			if err != nil || c.Value != "sess-alice" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "forbidden")
				return
			}
			_, _ = io.WriteString(w, "order-marker-ORD-1 owned by alice")
		case r.URL.Path == "/api/orders" && r.Method == "POST":
			c, err := r.Cookie("sid")
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			mu.Lock()
			orderID++
			id := orderID
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "marker": "ORD-" + itoa(id), "owner": c.Value})
		case r.URL.Path == "/signup" && r.Method == "POST":
			_, _ = io.WriteString(w, `<html><body>Please complete the CAPTCHA</body></html>`)
		case r.URL.Path == "/signup":
			_, _ = io.WriteString(w, `<html><body><form><input name="captcha"></form></body></html>`)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &logins
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ---- manifest --------------------------------------------------------------

func TestManifestValidation(t *testing.T) {
	good := `{"schema":"YoukaiAccounts/v1","accounts":[{"name":"alice","role":"user",
		"login":{"url":"http://127.0.0.1:1/login","password_env":"ALICE_PW"},
		"owns":[{"marker":"ORD-1","url":"http://127.0.0.1:1/orders/1"}]}]}`
	m, err := Load(writeManifest(t, good))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(m.Accounts) != 1 || m.Accounts[0].Name != "alice" {
		t.Fatalf("manifest = %+v", m)
	}
	if pairs := m.BolaPairs(); len(pairs) != 0 {
		t.Fatalf("a single account cannot form a pair: %+v", pairs)
	}

	bad := []string{
		`{"schema":"wrong","accounts":[]}`,
		`{"schema":"YoukaiAccounts/v1","accounts":[]}`,
		`{"schema":"YoukaiAccounts/v1","accounts":[{"name":"bad name","login":{"url":"x","password_env":"P"}}]}`,
		`{"schema":"YoukaiAccounts/v1","accounts":[{"name":"a","login":{"password_env":"P"}}]}`,
		`{"schema":"YoukaiAccounts/v1","accounts":[{"name":"a","login":{"url":"x"}}]}`,
		`{"schema":"YoukaiAccounts/v1","accounts":[{"name":"a","login":{"url":"x","password_env":"P"}},{"name":"a","login":{"url":"y","password_env":"P"}}]}`,
	}
	for i, body := range bad {
		if _, err := Load(writeManifest(t, body)); err == nil {
			t.Fatalf("case %d: invalid manifest accepted", i)
		}
	}
}

func TestBolaPairsUseDeclaredOwnershipOnly(t *testing.T) {
	body := `{"schema":"YoukaiAccounts/v1","base_url":"http://127.0.0.1:1","accounts":[
		{"name":"alice","role":"user","login":{"url":"http://127.0.0.1:1/login","password_env":"A"},
		 "owns":[{"marker":"ORD-1","url":"/orders/1"}]},
		{"name":"bob","role":"user","login":{"url":"http://127.0.0.1:1/login","password_env":"B"}}]}`
	m, err := Load(writeManifest(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pairs := m.BolaPairs()
	if len(pairs) != 1 {
		t.Fatalf("pairs = %+v", pairs)
	}
	p := pairs[0]
	if p.Owner != "alice" || p.Viewer != "bob" || p.Marker != "ORD-1" {
		t.Fatalf("pair = %+v", p)
	}
	if p.URL != "http://127.0.0.1:1/orders/1" {
		t.Fatalf("relative ownership URL not resolved: %q", p.URL)
	}
	if p.Action != "compare" || p.Args["session_a"] != "alice" || p.Args["session_b"] != "bob" {
		t.Fatalf("pair args = %+v", p.Args)
	}
}

// ---- session store ---------------------------------------------------------

func TestSessionStoreEncryptsAndHidesValues(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvSessionKey, "a-strong-session-key")
	store, err := NewSessionStore(dir)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	headers := map[string]string{"Cookie": "sid=SUPERSECRET"}
	if _, err := store.Save("alice", headers, "test"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "alice.json"))
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	if strings.Contains(string(raw), "SUPERSECRET") {
		t.Fatal("the cookie value is on disk in cleartext")
	}
	if !strings.Contains(string(raw), "aes-256-gcm") {
		t.Fatalf("session not marked encrypted: %s", string(raw))
	}

	// A wrong key must fail, not silently return garbage.
	store2, _ := NewSessionStore(dir)
	store2.key = []byte("another-key-entirely")
	if _, err := store2.Load("alice"); err == nil {
		t.Fatal("decryption succeeded with the wrong key")
	}

	// The right key round-trips.
	sess, err := store.Load("alice")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if sess.Headers["Cookie"] != "sid=SUPERSECRET" {
		t.Fatalf("session headers = %+v", sess.Headers)
	}

	// Listing never returns values.
	list, err := store.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].Name != "alice" || list[0].Enc != "aes-256-gcm" {
		t.Fatalf("listing entry = %+v", list[0])
	}
}

func TestSessionStoreWithoutKeyWarns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvSessionKey, "")
	t.Setenv(EnvSessionKeyCompat, "")
	store, err := NewSessionStore(dir)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if store.Keyed {
		t.Fatal("store claims to be encrypted with no key set")
	}
	if _, err := store.Save("bob", map[string]string{"Cookie": "sid=x"}, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "bob.json"))
	if !strings.Contains(string(raw), "warning") {
		t.Fatal("an unencrypted session must carry a warning on disk")
	}
}

// ---- provisioning ----------------------------------------------------------

func TestProvisionLogsInOnceAndRecordsOwnership(t *testing.T) {
	srv, logins := labServer(t)
	manifest := `{"schema":"YoukaiAccounts/v1","accounts":[
		{"name":"alice","role":"user","login":{"url":"` + srv.URL + `/login","fields":{"username":"alice"},"password_env":"ALICE_PW"},
		 "owns":[{"marker":"ORD-1","url":"` + srv.URL + `/orders/1"}]},
		{"name":"bob","role":"user","login":{"url":"` + srv.URL + `/login","fields":{"username":"bob"},"password_env":"BOB_PW"}}]}`
	path := writeManifest(t, manifest)
	t.Setenv("ALICE_PW", "alice-secret-pw")
	t.Setenv("BOB_PW", "bob-secret-pw")

	aud := &memAuditor{}
	g := testGuard(t, aud, nil)
	dir := t.TempDir()
	svc, err := Open(Env{Guard: g, ManifestPath: path, SessionDir: filepath.Join(dir, "sessions")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	obs, rep, err := svc.Provision(context.Background(), nil)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(rep.Provisioned) != 2 || len(rep.Failed) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if *logins != 2 {
		t.Fatalf("logins = %d, want exactly one per account", *logins)
	}
	if aud.allowed() != 2 {
		t.Fatalf("audited allowed = %d, want 2", aud.allowed())
	}
	// No credential may reach the observation.
	text := observationText(obs)
	for _, secret := range []string{"alice-secret-pw", "bob-secret-pw", "sess-alice", "sess-bob"} {
		if strings.Contains(text, secret) {
			t.Fatalf("observation leaked %q", secret)
		}
	}
	if !strings.Contains(text, "alice 拥有对象 ORD-1") {
		t.Fatalf("ownership fact missing: %s", text)
	}
	// Sessions are usable afterwards.
	sess, err := svc.Sessions.Load("alice")
	if err != nil {
		t.Fatalf("Load session: %v", err)
	}
	if !strings.Contains(sess.Headers["Cookie"], "sess-alice") {
		t.Fatalf("session cookie missing: %+v", sess.Headers)
	}
}

func TestProvisionFailsCleanlyWhenThePasswordIsMissing(t *testing.T) {
	srv, logins := labServer(t)
	manifest := `{"schema":"YoukaiAccounts/v1","accounts":[
		{"name":"alice","login":{"url":"` + srv.URL + `/login","fields":{"username":"alice"},"password_env":"MISSING_PW"}}]}`
	path := writeManifest(t, manifest)
	t.Setenv("MISSING_PW", "")

	aud := &memAuditor{}
	svc, err := Open(Env{Guard: testGuard(t, aud, nil), ManifestPath: path, SessionDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, rep, err := svc.Provision(context.Background(), nil)
	if err == nil {
		t.Fatal("provision reported success with no credential")
	}
	if len(rep.Failed) != 1 || !strings.Contains(rep.Failed[0].Error, "MISSING_PW") {
		t.Fatalf("failure not explained: %+v", rep.Failed)
	}
	if *logins != 0 || aud.allowed() != 0 {
		t.Fatal("a request was sent despite the missing credential")
	}
}

func TestShowNeverReturnsSecrets(t *testing.T) {
	srv, _ := labServer(t)
	manifest := `{"schema":"YoukaiAccounts/v1","accounts":[
		{"name":"alice","role":"admin","login":{"url":"` + srv.URL + `/login","fields":{"username":"alice"},"password_env":"ALICE_PW"},
		 "owns":[{"marker":"ORD-1","url":"` + srv.URL + `/orders/1"}]},
		{"name":"bob","login":{"url":"` + srv.URL + `/login","fields":{"username":"bob"},"password_env":"BOB_PW"}}]}`
	path := writeManifest(t, manifest)
	t.Setenv("ALICE_PW", "alice-secret-pw")
	t.Setenv(EnvSessionKey, "a-strong-session-key")

	svc, err := Open(Env{Guard: testGuard(t, &memAuditor{}, nil), ManifestPath: path, SessionDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, _, err := svc.Provision(context.Background(), []string{"alice"}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	view, err := svc.Show()
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	raw, _ := json.Marshal(view)
	text := string(raw)
	if strings.Contains(text, "alice-secret-pw") || strings.Contains(text, "sess-alice") || strings.Contains(text, "Cookie") {
		t.Fatalf("Show leaked a credential: %s", text)
	}
	if !strings.Contains(text, "\"session_ready\":true") {
		t.Fatalf("Show does not report readiness: %s", text)
	}
	if len(view.BolaPairs) != 1 {
		t.Fatalf("BOLA pairs = %+v", view.BolaPairs)
	}
}

// ---- seeding ---------------------------------------------------------------

func TestSeedRequiresAllThreeGates(t *testing.T) {
	srv, _ := labServer(t)
	manifest := `{"schema":"YoukaiAccounts/v1","accounts":[
		{"name":"alice","role":"user","login":{"url":"` + srv.URL + `/login","fields":{"username":"alice"},"password_env":"ALICE_PW"},
		 "seed":{"create":{"url":"` + srv.URL + `/api/orders","fields":{"item":"x"}},"extract":{"path":"id"},"item_url":"` + srv.URL + `/orders/{id}"}},
		{"name":"bob","login":{"url":"` + srv.URL + `/login","fields":{"username":"bob"},"password_env":"BOB_PW"}}]}`
	path := writeManifest(t, manifest)
	t.Setenv("ALICE_PW", "pw")
	t.Setenv("BOB_PW", "pw")

	// Gate 1: the passport must allow object seeding.
	aud := &memAuditor{}
	svc, _ := Open(Env{Guard: testGuard(t, aud, nil), ManifestPath: path, SessionDir: t.TempDir()})
	if _, _, err := svc.Seed(context.Background(), true, nil); err == nil {
		t.Fatal("seeding ran without allow_object_seeding")
	}

	// Gate 2: confirm is required.
	svc2, _ := Open(Env{
		Guard:        testGuard(t, aud, func(s *discipline.Scope) { s.AllowObjectSeeding = true }),
		ManifestPath: path, SessionDir: t.TempDir(),
	})
	if _, _, err := svc2.Seed(context.Background(), false, nil); err == nil {
		t.Fatal("seeding ran without confirm")
	}

	// Gate 3: the write method must be authorised.
	svc3, _ := Open(Env{
		Guard: testGuard(t, aud, func(s *discipline.Scope) {
			s.AllowObjectSeeding = true
			s.Methods = []string{"GET"}
		}),
		ManifestPath: path, SessionDir: t.TempDir(),
	})
	if _, _, err := svc3.Seed(context.Background(), true, nil); err == nil {
		t.Fatal("seeding ran without POST in the passport")
	}
	if aud.allowed() != 0 {
		t.Fatalf("refused seeding still sent %d request(s)", aud.allowed())
	}
	_ = svc
}

func TestSeedCreatesOneObjectPerAccount(t *testing.T) {
	srv, _ := labServer(t)
	manifest := `{"schema":"YoukaiAccounts/v1","accounts":[
		{"name":"alice","role":"user","login":{"url":"` + srv.URL + `/login","fields":{"username":"alice"},"password_env":"ALICE_PW"},
		 "seed":{"create":{"url":"` + srv.URL + `/api/orders","fields":{"item":"x"}},"extract":{"path":"id"},"item_url":"` + srv.URL + `/orders/{id}"}},
		{"name":"bob","role":"user","login":{"url":"` + srv.URL + `/login","fields":{"username":"bob"},"password_env":"BOB_PW"},
		 "seed":{"create":{"url":"` + srv.URL + `/api/orders","fields":{"item":"y"}},"extract":{"path":"id"},"item_url":"` + srv.URL + `/orders/{id}"}}]}`
	path := writeManifest(t, manifest)
	t.Setenv("ALICE_PW", "pw")
	t.Setenv("BOB_PW", "pw")

	aud := &memAuditor{}
	g := testGuard(t, aud, func(s *discipline.Scope) { s.AllowObjectSeeding = true })
	svc, _ := Open(Env{Guard: g, ManifestPath: path, SessionDir: t.TempDir()})
	if _, _, err := svc.Provision(context.Background(), nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	obs, rep, err := svc.Seed(context.Background(), true, nil)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if len(rep.Seeded) != 2 {
		t.Fatalf("seeded %d objects, want one per account: %+v", len(rep.Seeded), rep)
	}
	for _, s := range rep.Seeded {
		if s.Marker == "" || s.URL == "" || s.RequestID == "" {
			t.Fatalf("seeded entry incomplete: %+v", s)
		}
	}
	// The seeded objects become ownership facts and BOLA pairs.
	text := observationText(obs)
	if !strings.Contains(text, "自建对象") {
		t.Fatalf("seeding did not record ownership: %s", text)
	}
	if len(rep.BolaPairs) == 0 {
		t.Fatal("seeding produced no BOLA pairs")
	}
}

// ---- registration ----------------------------------------------------------

func TestRegisterStopsAtACaptcha(t *testing.T) {
	srv, _ := labServer(t)
	aud := &memAuditor{}
	g := testGuard(t, aud, func(s *discipline.Scope) { s.AllowAccountProvisioning = true })
	svc, err := Open(Env{Guard: g, ManifestPath: filepath.Join(t.TempDir(), "none.json"), SessionDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// A challenge field is refused before anything is submitted.
	_, rep, err := svc.Register(context.Background(), map[string]any{
		"signup_url": srv.URL + "/signup",
		"fields":     map[string]any{"email": "a@b.c", "captcha": "x"},
	})
	if err == nil || rep.Status != "needs_human" {
		t.Fatalf("captcha field not refused: %+v %v", rep, err)
	}
	if aud.allowed() != 0 {
		t.Fatal("a captcha form was submitted")
	}

	// A challenge in the response stops the flow with needs_human.
	obs, rep2, err := svc.Register(context.Background(), map[string]any{
		"signup_url": srv.URL + "/signup",
		"fields":     map[string]any{"email": "a@b.c"},
	})
	if !errorsIsNeedsHuman(err) || rep2.Status != "needs_human" {
		t.Fatalf("response challenge not detected: %+v %v", rep2, err)
	}
	if len(obs.Facts) == 0 {
		t.Fatal("needs_human left no evidence")
	}
	if aud.allowed() != 1 {
		t.Fatalf("expected exactly one submitted attempt, got %d", aud.allowed())
	}
}

func TestRegisterRequiresTheScopeSwitch(t *testing.T) {
	srv, _ := labServer(t)
	svc, _ := Open(Env{Guard: testGuard(t, &memAuditor{}, nil), ManifestPath: filepath.Join(t.TempDir(), "n.json"), SessionDir: t.TempDir()})
	if _, _, err := svc.Register(context.Background(), map[string]any{
		"verification_url": srv.URL + "/verify",
	}); err == nil {
		t.Fatal("registration ran without allow_account_provisioning")
	}
}

// ---- reachability ----------------------------------------------------------

func TestReachabilityNeedsHighAuthAndOnlyReads(t *testing.T) {
	srv, _ := labServer(t)
	manifest := `{"schema":"YoukaiAccounts/v1","accounts":[
		{"name":"alice","login":{"url":"` + srv.URL + `/login","fields":{"username":"alice"},"password_env":"ALICE_PW"}}]}`
	path := writeManifest(t, manifest)
	t.Setenv("ALICE_PW", "pw")
	key := "0123456789abcdef0123456789abcdef"
	t.Setenv(discipline.HighAuthKeyEnv, key)

	aud := &memAuditor{}
	svc, _ := Open(Env{Guard: testGuard(t, aud, nil), ManifestPath: path, SessionDir: t.TempDir()})
	if _, _, err := svc.Provision(context.Background(), nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Without a high-auth record: refused, nothing sent.
	before := aud.allowed()
	if _, _, err := svc.Reachability(context.Background(), []string{srv.URL + "/"}, nil, "", true); err == nil {
		t.Fatal("reachability ran without high-auth")
	}
	// With a record that does not cover the target: refused.
	other := writeHighAuth(t, key, "https://elsewhere.example", key)
	if _, _, err := svc.Reachability(context.Background(), []string{srv.URL + "/"}, nil, other, true); err == nil {
		t.Fatal("reachability accepted an out-of-coverage grant")
	}
	// Correctly scoped: two GETs (alice + anonymous).
	good := writeHighAuth(t, key, "127.0.0.1", key)
	obs, edges, err := svc.Reachability(context.Background(), []string{srv.URL + "/"}, nil, good, true)
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("edges = %+v", edges)
	}
	if aud.allowed()-before != 2 {
		t.Fatalf("reachability sent %d requests, want 2", aud.allowed()-before)
	}
	// Only the reachability phase is inspected: the login before it was a POST by
	// design, and that is tier 2.
	for _, ev := range aud.snapshot()[before:] {
		if ev.Method != "GET" {
			t.Fatalf("reachability used method %s", ev.Method)
		}
	}
	if len(obs.RequestIDs) != 2 {
		t.Fatalf("observation cites %d requests", len(obs.RequestIDs))
	}
}

// ---- helpers ---------------------------------------------------------------

func observationText(obs interface{}) string {
	raw, _ := json.Marshal(obs)
	return string(raw)
}

func errorsIsNeedsHuman(err error) bool {
	return err != nil && strings.Contains(err.Error(), "需要人工处理")
}

// writeHighAuth builds a signed record with the same canonicalisation Fairy uses.
func writeHighAuth(t *testing.T, key, asset, signKey string) string {
	t.Helper()
	now := Now()
	payload := map[string]any{
		"schema":     discipline.HighAuthSchema,
		"tier":       "highest",
		"basis":      "self-hosted lab reachability test",
		"approver":   "alice",
		"assets":     []any{asset},
		"actions":    []any{"read-only"},
		"issued_at":  now.Format("2006-01-02T15:04:05Z"),
		"expires_at": now.Add(2 * timeHour).Format("2006-01-02T15:04:05Z"),
		"nonce":      "nonce-1",
	}
	canonical := canonicalPayload(t, payload)
	rec := map[string]any{
		"schema": discipline.HighAuthSchema, "payload": payload,
		"signature": hmacHex(signKey, canonical),
	}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	path := filepath.Join(t.TempDir(), "high-auth.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write high-auth: %v", err)
	}
	_ = key
	return path
}

// ---- signing helpers (mirror discipline's canonicalisation) ----------------

const timeHour = time.Hour

func hmacHex(key, canonical string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// canonicalPayload reproduces JSON.stringify(payload, Object.keys(payload).sort()).
func canonicalPayload(t *testing.T, m map[string]any) string {
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
		var vb bytes.Buffer
		enc := json.NewEncoder(&vb)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(m[k]); err != nil {
			t.Fatalf("encode %q: %v", k, err)
		}
		buf.Write(bytes.TrimRight(vb.Bytes(), "\n"))
	}
	buf.WriteByte('}')
	return buf.String()
}
