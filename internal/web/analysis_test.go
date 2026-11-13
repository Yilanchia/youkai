package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"youkai/internal/discipline"
)

func TestParamSSTIHit(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch {
		case strings.Contains(q, "{{7*7}}"):
			fmt.Fprint(w, "result=49")
		case strings.Contains(q, "{{7*6}}"):
			fmt.Fprint(w, "result=42")
		default:
			fmt.Fprint(w, "hello world")
		}
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
		s.AllowActiveProbes = true
	})
	ctx := context.Background()

	obs, err := Run(ctx, env, "param", map[string]any{
		"url": srv.URL + "/?q=x", "param": "q", "classes": []any{"ssti"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	// baseline + payload + control.
	if got := recorder.count(); got != 3 {
		t.Fatalf("audit events = %d, want 3", got)
	}
	finding := findFinding(obs, "ssti")
	if finding == nil {
		t.Fatalf("missing ssti finding, got %+v", obs.Findings)
	}
	if finding.Severity != "high" {
		t.Fatalf("ssti severity = %q, want high (template evaluation)", finding.Severity)
	}
	if findFact(obs, "模板求值:") == nil {
		t.Fatalf("missing template-evaluation fact, got %+v", obs.Facts)
	}
	assertEvidence(t, obs)

	t.Run("adaptive encoding variants use the same checks", func(t *testing.T) {
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
			s.AllowActiveProbes = true
			s.AllowWAFProbe = true
		})
		obs, err := Run(ctx, env, "param_adaptive", map[string]any{
			"url": srv.URL + "/?q=x", "param": "q", "classes": []any{"ssti"},
		})
		if err != nil {
			t.Fatalf("param_adaptive: %v", err)
		}
		if got := recorder.count(); got > maxParamRequests {
			t.Fatalf("audit events = %d, want <= %d", got, maxParamRequests)
		}
		if findFinding(obs, "ssti") == nil {
			t.Fatalf("adaptive probe missed the ssti hit: %+v", obs.Findings)
		}
	})
}

func TestParamNoHitStillProducesEvidence(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello world")
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
		s.AllowActiveProbes = true
	})
	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": srv.URL + "/?q=x", "param": "q", "classes": []any{"ssti"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	// baseline + the ssti payload; no control request because 49 never appeared.
	if got := recorder.count(); got != 2 {
		t.Fatalf("audit events = %d, want 2", got)
	}
	if len(obs.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", obs.Findings)
	}
	if findFact(obs, "参数探测无命中") == nil {
		t.Fatalf("missing no-hit fact, got %+v", obs.Facts)
	}
	assertEvidence(t, obs)
}

func TestParamSQLiErrorSignature(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "'") {
			fmt.Fprint(w, "You have an error in your SQL syntax; check the manual")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
		s.AllowActiveProbes = true
	})
	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": srv.URL + "/?q=x", "param": "q", "classes": []any{"sqli"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	// baseline + the single quote probe; the boolean pair is skipped after a hit.
	if got := recorder.count(); got != 2 {
		t.Fatalf("audit events = %d, want 2", got)
	}
	finding := findFinding(obs, "sqli")
	if finding == nil {
		t.Fatalf("missing sqli finding, got %+v", obs.Findings)
	}
	if finding.Severity != "medium" {
		t.Fatalf("sqli severity = %q, want medium (error signature)", finding.Severity)
	}
	if findFact(obs, "SQL 错误签名") == nil {
		t.Fatalf("missing sqli fact, got %+v", obs.Facts)
	}
	assertEvidence(t, obs)
}

func TestParamRequiresUnlockedScope(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	before := recorder.count()
	if _, err := Run(context.Background(), env, "param", map[string]any{
		"url": srv.URL + "/?q=x", "param": "q",
	}); err == nil {
		t.Fatal("param must refuse when allow_active_probes is false")
	}
	if recorder.count() != before {
		t.Fatalf("param sent %d requests without authorisation", recorder.count()-before)
	}
	if _, err := Run(context.Background(), env, "param", map[string]any{
		"url": srv.URL + "/", "param": "q", "classes": []any{"xss"},
	}); err == nil {
		t.Fatal("param must reject unsupported classes")
	}
}

func TestProofContext(t *testing.T) {
	ctx := context.Background()

	t.Run("script context without CSP", func(t *testing.T) {
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body><script>var x = "%s";</script></body></html>`,
				r.URL.Query().Get("q"))
		}))
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
		obs, err := Run(ctx, env, "proof", map[string]any{
			"url": srv.URL + "/?q=x", "param": "q", "marker": "youkaiMARKER",
		})
		if err != nil {
			t.Fatalf("proof: %v", err)
		}
		if recorder.count() != 1 {
			t.Fatalf("audit events = %d, want 1", recorder.count())
		}
		fact := findFact(obs, "反射上下文:script")
		if fact == nil {
			t.Fatalf("missing script-context fact, got %+v", obs.Facts)
		}
		if !hasTag(fact.Tags, "xss-context") {
			t.Fatalf("script context without CSP must be tagged xss-context: %v", fact.Tags)
		}
		if !hasTag(fact.Tags, "no-csp") {
			t.Fatalf("missing no-csp tag: %v", fact.Tags)
		}
		assertEvidence(t, obs)
	})

	t.Run("CSP present lowers the signal", func(t *testing.T) {
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			fmt.Fprintf(w, `<html><body><script>var x = "%s";</script></body></html>`,
				r.URL.Query().Get("q"))
		}))
		env, _ := newTestEnv(t, []string{"127.0.0.1"}, nil)
		obs, err := Run(ctx, env, "proof", map[string]any{
			"url": srv.URL + "/?q=x", "param": "q", "marker": "youkaiMARKER",
		})
		if err != nil {
			t.Fatalf("proof: %v", err)
		}
		fact := findFact(obs, "反射上下文:script")
		if fact == nil {
			t.Fatalf("missing script-context fact, got %+v", obs.Facts)
		}
		if hasTag(fact.Tags, "xss-context") {
			t.Fatalf("CSP present must not raise the xss-context tag: %v", fact.Tags)
		}
		if !hasTag(fact.Tags, "csp-present") {
			t.Fatalf("missing csp-present tag: %v", fact.Tags)
		}
	})
}

func TestClassifyReflection(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"text", "<html><body>MARKER</body></html>", contextText},
		{"script", `<script>var a = "MARKER";</script>`, contextScript},
		{"style", `<style>.x{content:"MARKER"}</style>`, contextStyle},
		{"attribute", `<div title="MARKER">x</div>`, contextAttribute},
		{"event handler", `<button onclick="go('MARKER')">x</button>`, contextEventAttr},
		{"comment", `<!-- MARKER -->`, contextComment},
		{"not reflected", "<html>nothing here</html>", contextNotReflected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyReflection(tc.body, "MARKER"); got != tc.want {
				t.Fatalf("classifyReflection(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestLoginRedactsCredentials(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "supersecret", Path: "/", HttpOnly: true, Secure: true})
		w.Header().Set("Location", "/home")
		w.WriteHeader(http.StatusFound)
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
		s.Methods = []string{http.MethodGet, http.MethodPost}
	})
	obs, err := Run(context.Background(), env, "login", map[string]any{
		"url":     srv.URL + "/login",
		"session": "alice",
		"fields":  map[string]any{"username": "alice", "password": "s3cret"},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if recorder.count() != 1 {
		t.Fatalf("audit events = %d, want exactly one login attempt", recorder.count())
	}
	fact := findFact(obs, "登录尝试成功")
	if fact == nil {
		t.Fatalf("missing success fact, got %+v", obs.Facts)
	}
	if !strings.Contains(obs.Summary, "sid") {
		t.Fatalf("summary must return the cookie names, got %q", obs.Summary)
	}
	text := observationText(obs)
	for _, secret := range []string{"s3cret", "supersecret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("observation leaked credential %q: %s", secret, text)
		}
	}
	names, _ := fact.Evidence["cookie_names"].([]string)
	if len(names) != 1 || names[0] != "sid" {
		t.Fatalf("cookie_names = %v, want [sid]", fact.Evidence["cookie_names"])
	}

	t.Run("write method must be authorised", func(t *testing.T) {
		locked, lockedRecorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
		if _, err := Run(context.Background(), locked, "login", map[string]any{
			"url": srv.URL + "/login", "session": "alice",
			"fields": map[string]any{"username": "alice", "password": "s3cret"},
		}); err == nil {
			t.Fatal("login must refuse when the scope has not authorised POST")
		}
		if lockedRecorder.count() != 0 {
			t.Fatalf("login sent %d requests without a write authorisation", lockedRecorder.count())
		}
	})
}

func TestScanCookieFlags(t *testing.T) {
	ctx := context.Background()

	t.Run("http target: flags are judged, not guessed", func(t *testing.T) {
		// discipline keeps the attributes and redacts only the value, so the check
		// must produce real findings and must never reconstruct "secret".
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Add("Set-Cookie", "sid=secret; Path=/")
			fmt.Fprint(w, "<html><body>x</body></html>")
		}))
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
		obs, err := Run(ctx, env, "scan", map[string]any{"url": srv.URL + "/"})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if recorder.count() != 8 {
			t.Fatalf("audit events = %d, want 8", recorder.count())
		}
		// Missing HttpOnly (medium), missing Secure on http (info), missing SameSite (low).
		if got := countFindings(obs, "cookie"); got != 3 {
			t.Fatalf("cookie findings = %d, want 3: %+v", got, obs.Findings)
		}
		for _, want := range []string{"缺少 HttpOnly", "通过明文 HTTP 设置", "缺少 SameSite"} {
			if findFact(obs, want) == nil {
				t.Fatalf("missing cookie fact %q, got %+v", want, obs.Facts)
			}
		}
		if findFact(obs, "未判定") != nil {
			t.Fatalf("flag judgement must not be reported as skipped: %+v", obs.Facts)
		}
		text := observationText(obs)
		if strings.Contains(text, "secret") {
			t.Fatalf("cookie value leaked into the observation: %s", text)
		}
		finding := findFinding(obs, "cookie")
		if finding == nil {
			t.Fatal("missing cookie finding")
		}
		if finding.Evidence["cookie"] != "sid" {
			t.Fatalf("evidence cookie = %v, want the name only", finding.Evidence["cookie"])
		}
		if finding.Evidence["request_id"] == "" {
			t.Fatal("cookie finding carries no request_id")
		}
		assertEvidence(t, obs)
	})

	t.Run("SameSite=None without Secure", func(t *testing.T) {
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Add("Set-Cookie", "sid=secret; Path=/; HttpOnly; SameSite=None")
			fmt.Fprint(w, "<html><body>x</body></html>")
		}))
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
		obs, err := Run(ctx, env, "scan", map[string]any{"url": srv.URL + "/"})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if recorder.count() != 8 {
			t.Fatalf("audit events = %d, want 8", recorder.count())
		}
		// Plaintext info for the missing Secure plus the SameSite=None finding.
		if got := countFindings(obs, "cookie"); got != 2 {
			t.Fatalf("cookie findings = %d, want 2: %+v", got, obs.Findings)
		}
		mixed := findFact(obs, "SameSite=None 但未设置 Secure")
		if mixed == nil {
			t.Fatalf("missing SameSite=None finding, got %+v", obs.Facts)
		}
		if mixed.Evidence["attribute"] != "SameSite" {
			t.Fatalf("SameSite finding attribute = %v", mixed.Evidence["attribute"])
		}
		if findFact(obs, "缺少 HttpOnly") != nil {
			t.Fatal("HttpOnly is set; no finding expected")
		}
		if strings.Contains(observationText(obs), "secret") {
			t.Fatal("cookie value leaked into the observation")
		}
		assertEvidence(t, obs)
	})

	t.Run("https target: missing Secure is a medium finding", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Add("Set-Cookie", "sid=secret; Path=/; HttpOnly; SameSite=Lax")
			fmt.Fprint(w, "<html><body>x</body></html>")
		}))
		t.Cleanup(srv.Close)
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
		obs, err := Run(ctx, env, "scan", map[string]any{"url": srv.URL + "/"})
		if err != nil {
			t.Fatalf("scan over https: %v", err)
		}
		if recorder.count() != 8 {
			t.Fatalf("audit events = %d, want 8", recorder.count())
		}
		if got := countFindings(obs, "cookie"); got != 1 {
			t.Fatalf("cookie findings = %d, want 1: %+v", got, obs.Findings)
		}
		finding := findFinding(obs, "cookie")
		if !strings.Contains(finding.Title, "缺少 Secure") {
			t.Fatalf("finding title = %q, want missing Secure", finding.Title)
		}
		if finding.Severity != "medium" {
			t.Fatalf("severity = %q, want medium on https", finding.Severity)
		}
		if findFact(obs, "明文 HTTP") != nil {
			t.Fatal("https target must not be reported as plaintext")
		}
		if strings.Contains(observationText(obs), "secret") {
			t.Fatal("cookie value leaked into the observation")
		}
		assertEvidence(t, obs)
	})
}

func TestWAFProfile(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "<") || strings.Contains(q, "'") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Request blocked: ModSecurity")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
		s.AllowWAFProbe = true
	})
	obs, err := Run(context.Background(), env, "waf", map[string]any{
		"url": srv.URL + "/?q=x", "param": "q",
	})
	if err != nil {
		t.Fatalf("waf: %v", err)
	}
	// one baseline plus the default twelve probes.
	if got := recorder.count(); got != 13 {
		t.Fatalf("audit events = %d, want 13", got)
	}
	fact := findFact(obs, "WAF 画像")
	if fact == nil {
		t.Fatalf("missing WAF profile fact, got %+v", obs.Facts)
	}
	blocked, _ := fact.Evidence["blocked"].(int)
	if blocked == 0 {
		t.Fatalf("WAF profile recorded no blocking: %v", fact.Evidence)
	}
	finding := findFinding(obs, "waf")
	if finding == nil {
		t.Fatalf("missing WAF finding, got %+v", obs.Findings)
	}
	assertEvidence(t, obs)

	t.Run("requires allow_waf_probe", func(t *testing.T) {
		locked, lockedRecorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
		if _, err := Run(context.Background(), locked, "waf", map[string]any{
			"url": srv.URL + "/?q=x", "param": "q",
		}); err == nil {
			t.Fatal("waf must refuse when allow_waf_probe is false")
		}
		if lockedRecorder.count() != 0 {
			t.Fatalf("waf sent %d requests without authorisation", lockedRecorder.count())
		}
	})
}

func TestRoleMatrixFindsSharedContent(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Session") {
		case "admin", "viewer":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>%s</body></html>", strings.Repeat("A", 1000))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	obs, err := Run(context.Background(), env, "role_matrix", map[string]any{
		"urls": []any{srv.URL + "/admin"},
		"sessions": []any{
			map[string]any{"name": "admin", "headers": map[string]any{"X-Session": "admin"}},
			map[string]any{"name": "viewer", "headers": map[string]any{"X-Session": "viewer"}},
		},
	})
	if err != nil {
		t.Fatalf("role_matrix: %v", err)
	}
	// anonymous + admin + viewer.
	if recorder.count() != 3 {
		t.Fatalf("audit events = %d, want 3", recorder.count())
	}
	if findFact(obs, "权限矩阵") == nil {
		t.Fatalf("missing matrix fact, got %+v", obs.Facts)
	}
	finding := findFinding(obs, "authz")
	if finding == nil {
		t.Fatalf("missing authz finding, got %+v", obs.Findings)
	}
	if !strings.Contains(finding.Title, "/admin") {
		t.Fatalf("finding title %q does not name the path", finding.Title)
	}
	assertEvidence(t, obs)
}
