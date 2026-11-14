package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"youkai/internal/config"
	"youkai/internal/discipline"
)

// fakeOpenAI is an OpenAI-compatible endpoint for the connectivity test.
func fakeOpenAI(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if status != http.StatusOK {
			http.Error(w, "upstream said no", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": "pong"}}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLLMConfigRoundTrip: save via the API, read it back, key never echoed.
func TestLLMConfigRoundTrip(t *testing.T) {
	f := newFixture(t, "")
	t.Setenv("MY_MODEL_KEY", "sk-env-secret-should-not-leak")

	code, body := f.do(t, http.MethodPut, "/api/config/llm", map[string]any{
		"enabled":      true,
		"base_url":     "https://api.example/v1",
		"model":        "m-1",
		"key_from_env": "MY_MODEL_KEY",
		"updated_by":   "alice",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d %v", code, body)
	}
	if strings.Contains(dumpJSON(body), "sk-env-secret") {
		t.Fatalf("the response echoed the key: %s", dumpJSON(body))
	}

	code, view := f.do(t, http.MethodGet, "/api/config/llm", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET = %d", code)
	}
	if view["enabled"] != true || view["model"] != "m-1" || view["base_url"] != "https://api.example/v1" {
		t.Fatalf("view = %v", view)
	}
	if view["key_present"] != true {
		t.Fatal("key_present should be true when the env var is set")
	}
	if view["key_from_env"] != "MY_MODEL_KEY" {
		t.Fatalf("key_from_env = %v", view["key_from_env"])
	}
	if strings.Contains(dumpJSON(view), "sk-env-secret") {
		t.Fatal("GET echoed the key")
	}
	if view["source"] != "settings" || view["updated_by"] != "alice" {
		t.Fatalf("provenance = %v / %v", view["source"], view["updated_by"])
	}

	// Hot swap: the server now hands a proposer to new runs.
	if f.srv.proposer() == nil {
		t.Fatal("the planner was not installed (no hot swap)")
	}
}

// TestLLMDirectKeyIsStoredEncrypted: a directly entered key is encrypted at rest
// and never appears in a response.
func TestLLMDirectKeyIsStoredEncrypted(t *testing.T) {
	f := newFixture(t, "")
	secret := "sk-direct-key-must-be-encrypted"

	code, body := f.do(t, http.MethodPut, "/api/config/llm", map[string]any{
		"enabled":  true,
		"base_url": "https://api.example/v1",
		"model":    "m-2",
		"key":      secret,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d %v", code, body)
	}
	if strings.Contains(dumpJSON(body), "sk-direct-key") {
		t.Fatal("the response echoed the key")
	}

	// The database must not hold the plaintext.
	var raw []byte
	if err := f.store.Pool().QueryRow(context.Background(),
		`SELECT value::text || coalesce(encode(secret_enc,'hex'),'') FROM settings WHERE key=$1`,
		config.KeyLLM).Scan(&raw); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if strings.Contains(string(raw), "sk-direct-key") {
		t.Fatalf("the key is stored in the clear: %s", raw)
	}

	// The server can still use it.
	key, err := f.srv.cfg.Settings.GetSecret(context.Background(), config.KeyLLM)
	if err != nil || key != secret {
		t.Fatalf("GetSecret = %q, %v", key, err)
	}

	// Clearing it works through the same endpoint.
	code, _ = f.do(t, http.MethodPut, "/api/config/llm", map[string]any{"key": ""}, nil)
	if code != http.StatusOK {
		t.Fatalf("clear key = %d", code)
	}
	if _, err := f.srv.cfg.Settings.GetSecret(context.Background(), config.KeyLLM); err == nil {
		t.Fatal("the key was not cleared")
	}
}

// TestLLMDirectKeyRefusedWithoutPassphrase.
func TestLLMDirectKeyRefusedWithoutPassphrase(t *testing.T) {
	f := newFixture(t, "")
	// Replace the settings store with one that has no passphrase.
	f.srv.cfg.Settings = config.New(f.store.Pool(), nil)

	code, body := f.do(t, http.MethodPut, "/api/config/llm", map[string]any{
		"enabled":  true,
		"base_url": "https://api.example/v1",
		"model":    "m-3",
		"key":      "sk-cannot-be-stored",
	}, nil)
	if code != http.StatusPreconditionRequired {
		t.Fatalf("PUT = %d (%v), want 428", code, body)
	}
	if !strings.Contains(strings.ToLower(dumpJSON(body)), "session_key") {
		t.Fatalf("the error does not say what to configure: %v", body)
	}
}

// TestLLMValidation.
func TestLLMValidation(t *testing.T) {
	f := newFixture(t, "")
	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"bad scheme", map[string]any{"enabled": true, "base_url": "ftp://x", "model": "m"}, http.StatusBadRequest},
		{"empty model", map[string]any{"enabled": true, "base_url": "https://x", "model": ""}, http.StatusBadRequest},
		{"both key sources", map[string]any{
			"enabled": true, "base_url": "https://x", "model": "m",
			"key_from_env": "K", "key": "sk-x",
		}, http.StatusBadRequest},
		{"bad temperature", map[string]any{
			"enabled": true, "base_url": "https://x", "model": "m", "temperature": 9.5,
		}, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, body := f.do(t, http.MethodPut, "/api/config/llm", c.body, nil)
			if code != c.want {
				t.Fatalf("%s: code = %d (%v), want %d", c.name, code, body, c.want)
			}
		})
	}
}

// TestLLMTestEndpoint: a working endpoint reports ok + latency, a failing one
// reports the error and never a model response body.
func TestLLMTestEndpoint(t *testing.T) {
	f := newFixture(t, "")

	good := fakeOpenAI(t, http.StatusOK)
	code, body := f.do(t, http.MethodPost, "/api/config/llm/test", map[string]any{
		"base_url": good.URL, "model": "m", "timeout_s": 10,
	}, nil)
	if code != http.StatusOK || body["ok"] != true {
		t.Fatalf("test good = %d %v", code, body)
	}
	if _, has := body["latency_ms"]; !has {
		t.Fatalf("no latency reported: %v", body)
	}
	if strings.Contains(dumpJSON(body), "pong") {
		t.Fatal("the test endpoint returned model output")
	}

	bad := fakeOpenAI(t, http.StatusInternalServerError)
	code, body = f.do(t, http.MethodPost, "/api/config/llm/test", map[string]any{
		"base_url": bad.URL, "model": "m", "timeout_s": 10,
	}, nil)
	if code != http.StatusOK || body["ok"] != false {
		t.Fatalf("test bad = %d %v", code, body)
	}
	if body["error"] == "" || body["error"] == nil {
		t.Fatalf("a failed test reported no error: %v", body)
	}
}

// TestLLMDisabledKeepsDeterministicLoop: no config means no proposer, and the
// engine must be handed nil rather than a broken client.
func TestLLMDisabledKeepsDeterministicLoop(t *testing.T) {
	f := newFixture(t, "")
	if f.srv.proposer() != nil {
		t.Fatal("a fresh server installed a proposer without configuration")
	}
	code, body := f.do(t, http.MethodPut, "/api/config/llm", map[string]any{"enabled": false}, nil)
	if code != http.StatusOK {
		t.Fatalf("disable = %d %v", code, body)
	}
	if f.srv.proposer() != nil {
		t.Fatal("disable left a proposer installed")
	}
}

// TestLLMChangeIsAudited: a configuration change lands in the append-only trail
// without any secret in it.
func TestLLMChangeIsAudited(t *testing.T) {
	f := newFixture(t, "")
	code, _ := f.do(t, http.MethodPut, "/api/config/llm", map[string]any{
		"enabled": true, "base_url": "https://api.example/v1", "model": "m-audit",
		"key": "sk-audit-secret", "updated_by": "auditor",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d", code)
	}
	var detail []byte
	if err := f.store.Pool().QueryRow(context.Background(),
		`SELECT detail::text FROM audit_log WHERE purpose='config' AND method='CONFIG' ORDER BY id DESC LIMIT 1`).
		Scan(&detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(detail), "m-audit") {
		t.Fatalf("the audit row does not record the change: %s", detail)
	}
	if strings.Contains(string(detail), "sk-audit-secret") {
		t.Fatalf("the audit row leaked the key: %s", detail)
	}
}

// ---- scope editing ---------------------------------------------------------

func TestScopeEditValidatesAndAudits(t *testing.T) {
	f := newFixture(t, "")
	path := "/api/engagements/" + itoa(f.eng.ID) + "/scope"

	// A top-level wildcard must be refused before it reaches the database.
	code, body := f.do(t, http.MethodPut, path, map[string]any{
		"scope": map[string]any{
			"include": []string{"*"}, "basis": "self-hosted lab", "operator": "tester",
		},
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("wildcard scope = %d %v", code, body)
	}

	// A real widening: add active probes and a write method.
	code, body = f.do(t, http.MethodPut, path, map[string]any{
		"updated_by": "alice",
		"scope": map[string]any{
			"project":             "lab",
			"include":             []string{"127.0.0.1", "lab.example"},
			"exclude":             []string{"admin.lab.example"},
			"methods":             []string{"GET", "HEAD", "OPTIONS", "POST"},
			"basis":               "self-hosted lab, ticket 42",
			"operator":            "tester",
			"allow_private":       true,
			"allow_active_probes": true,
			"allow_waf_probe":     true,
			"max_requests":        123,
			"rps":                 7,
			"expires_at":          "2099-01-01T00:00:00Z",
		},
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("scope PUT = %d %v", code, body)
	}
	if body["changed"] != true || body["widened"] != true {
		t.Fatalf("change not reported: %v", body)
	}

	// Reading the engagement returns the new passport.
	code, eng := f.do(t, http.MethodGet, "/api/engagements/"+itoa(f.eng.ID), nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET engagement = %d", code)
	}
	raw := dumpJSON(eng["scope"])
	for _, want := range []string{"allow_active_probes", "lab.example", "admin.lab.example", `"POST"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("stored scope is missing %q: %s", want, raw)
		}
	}

	// The change is audited.
	var detail []byte
	if err := f.store.Pool().QueryRow(context.Background(),
		`SELECT detail::text FROM audit_log WHERE purpose='config' AND url='config:scope' ORDER BY id DESC LIMIT 1`).
		Scan(&detail); err != nil {
		t.Fatalf("read scope audit: %v", err)
	}
	if !strings.Contains(string(detail), "allow_active_probes") || !strings.Contains(string(detail), "alice") {
		t.Fatalf("scope audit detail = %s", detail)
	}

	// The guard now sees the new passport on the next build.
	sc := discipline.NewScope(discipline.Scope{
		Project: "lab", Include: []string{"lab.example"},
		Basis: "self-hosted lab", Operator: "t", AllowPrivate: true,
	})
	if _, err := sc.Check("http://lab.example/x"); err != nil {
		t.Fatalf("new passport rejected its own target: %v", err)
	}
}

func TestScopeEditRejectsExpired(t *testing.T) {
	f := newFixture(t, "")
	code, body := f.do(t, http.MethodPut, "/api/engagements/"+itoa(f.eng.ID)+"/scope", map[string]any{
		"scope": map[string]any{
			"include": []string{"127.0.0.1"}, "basis": "self-hosted lab", "operator": "tester",
			"expires_at": "2000-01-01T00:00:00Z",
		},
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expired passport accepted: %d %v", code, body)
	}
}

func TestEngagementCreateAcceptsFullScope(t *testing.T) {
	f := newFixture(t, "")
	code, body := f.do(t, http.MethodPost, "/api/engagements", map[string]any{
		"name": "full-scope-" + itoa(time.Now().UnixNano()%1000000) + "-x",
		"scope": map[string]any{
			"project":         "lab2",
			"include":         []string{"127.0.0.1"},
			"exclude":         []string{"127.0.0.1:9"},
			"methods":         []string{"GET", "POST"},
			"basis":           "self-hosted lab, full passport",
			"operator":        "tester",
			"allow_private":   true,
			"allow_waf_probe": true,
			"max_requests":    55,
			"rps":             3.5,
			"expires_at":      "2099-06-01T00:00:00Z",
		},
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, body)
	}
	raw := dumpJSON(body)
	for _, want := range []string{"allow_waf_probe", "127.0.0.1:9", `"POST"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("created scope missing %q: %s", want, raw)
		}
	}
}

func dumpJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// itoa is local to avoid importing strconv just for ids in URLs.
func itoa(i int64) string {
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

var _ = os.Getenv
