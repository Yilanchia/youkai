package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"youkai/internal/discipline"
	"youkai/internal/gate"
)

func TestProbe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><body>ok</body></html>")
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repo/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n")
	})
	srv := newTestServer(t, mux)
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	ctx := context.Background()

	cases := []struct {
		name    string
		path    string
		status  int
		gitFact bool
	}{
		{"ok", "/", 200, false},
		{"not-found", "/missing", 404, false},
		{"git-config", "/repo/.git/config", 200, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := recorder.count()
			target := srv.URL + tc.path
			obs, err := Run(ctx, env, "probe", map[string]any{"url": target})
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if got := recorder.count(); got != before+1 {
				t.Fatalf("audit events = %d, want %d (probe must go through the guard exactly once)", got, before+1)
			}
			want := fmt.Sprintf("GET %s -> %d", target, tc.status)
			if findFact(obs, want) == nil {
				t.Fatalf("missing fact %q, got %+v", want, obs.Facts)
			}
			if tc.gitFact {
				if findFact(obs, "git 配置可读:"+target) == nil {
					t.Fatalf("missing git-config fact, got %+v", obs.Facts)
				}
			} else if findFact(obs, "git 配置可读:") != nil {
				t.Fatalf("unexpected git-config fact for %s", target)
			}
			assertEvidence(t, obs)
			if len(obs.RequestIDs) != 1 {
				t.Fatalf("RequestIDs = %v, want exactly one", obs.RequestIDs)
			}
		})
	}

	t.Run("missing url", func(t *testing.T) {
		if _, err := Run(ctx, env, "probe", map[string]any{}); err == nil {
			t.Fatal("probe without url must fail")
		}
	})

	t.Run("write method is refused by scope", func(t *testing.T) {
		before := recorder.count()
		if _, err := Run(ctx, env, "probe", map[string]any{"url": srv.URL, "method": "POST"}); err == nil {
			t.Fatal("POST must be refused: the scope only authorises read methods")
		}
		events := recorder.snapshot()
		if len(events) != before+1 {
			t.Fatalf("audit events = %d, want %d", len(events), before+1)
		}
		if events[len(events)-1].Verdict != discipline.VerdictBlocked {
			t.Fatalf("refusal verdict = %q, want blocked", events[len(events)-1].Verdict)
		}
	})
}

func TestNoScopeRefused(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should never be reached")
	}))

	t.Run("nil guard", func(t *testing.T) {
		_, err := Run(ctx, &Env{}, "probe", map[string]any{"url": srv.URL})
		if !errors.Is(err, discipline.ErrNoScope) {
			t.Fatalf("err = %v, want ErrNoScope", err)
		}
	})

	t.Run("target outside the passport", func(t *testing.T) {
		env, recorder := newTestEnv(t, []string{"example.com"}, nil)
		_, err := Run(ctx, env, "probe", map[string]any{"url": srv.URL})
		if err == nil {
			t.Fatal("out-of-scope probe must fail")
		}
		events := recorder.snapshot()
		if len(events) != 1 {
			t.Fatalf("audit events = %d, want 1 (the refusal must be audited)", len(events))
		}
		if events[0].Verdict != discipline.VerdictBlocked {
			t.Fatalf("verdict = %q, want blocked", events[0].Verdict)
		}
		if !strings.Contains(events[0].Reason, "outside the authorised scope") {
			t.Fatalf("reason = %q, want an out-of-scope explanation", events[0].Reason)
		}
	})
}

func TestScanFindsMissingHeadersAndExposure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, "<html><body><h1>welcome</h1></body></html>")
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "DB_PASSWORD=hunter2\nAPI_KEY=abc123\n")
		default:
			http.NotFound(w, r)
		}
	})
	srv := newTestServer(t, handler)
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	ctx := context.Background()
	target := srv.URL + "/"

	obs, err := Run(ctx, env, "scan", map[string]any{"url": target})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// primary request + CORS probe + six exposure probes.
	const wantRequests = 8
	if got := recorder.count(); got != wantRequests {
		t.Fatalf("audit events = %d, want %d", got, wantRequests)
	}
	if got := len(obs.RequestIDs); got != wantRequests {
		t.Fatalf("RequestIDs = %d, want %d (%v)", got, wantRequests, obs.RequestIDs)
	}
	// 4 missing headers: HSTS is https-only and the target is plain http.
	if got := countFindings(obs, "header-missing"); got != 4 {
		t.Fatalf("header-missing findings = %d, want 4: %+v", got, obs.Findings)
	}
	if findFact(obs, "缺失安全响应头:CSP") == nil {
		t.Fatalf("missing CSP fact, got %+v", obs.Facts)
	}
	exposure := findFinding(obs, "exposure")
	if exposure == nil {
		t.Fatalf("missing exposure finding, got %+v", obs.Findings)
	}
	if !strings.HasSuffix(exposure.Where, "/.env") {
		t.Fatalf("exposure where = %q, want the .env URL", exposure.Where)
	}
	if got := countFindings(obs, "exposure"); got != 1 {
		t.Fatalf("exposure findings = %d, want 1", got)
	}
	// The scan must register the surface asset.
	foundSurface := false
	for _, asset := range obs.Assets {
		if asset.Kind == "surface" && asset.Value == "surface:"+target {
			foundSurface = true
		}
	}
	if !foundSurface {
		t.Fatalf("missing surface asset, got %+v", obs.Assets)
	}
	if findFact(obs, "scan 候选(high): ") == nil {
		t.Fatalf("expected scan candidate facts, got %+v", obs.Facts)
	}
	assertEvidence(t, obs)
}

func TestScanReflection(t *testing.T) {
	ctx := context.Background()

	t.Run("echoed parameter yields one candidate", func(t *testing.T) {
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>hello %s</body></html>", r.URL.Query().Get("q"))
		}))
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

		obs, err := Run(ctx, env, "scan", map[string]any{"url": srv.URL + "/?q=x"})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		// primary + CORS + one reflection probe + six exposure probes.
		if got := recorder.count(); got != 9 {
			t.Fatalf("audit events = %d, want 9", got)
		}
		if got := countFindings(obs, "reflection"); got != 1 {
			t.Fatalf("reflection findings = %d, want 1: %+v", got, obs.Findings)
		}
		finding := findFinding(obs, "reflection")
		if finding.Title != "参数 q 的值反射进响应" {
			t.Fatalf("title = %q", finding.Title)
		}
		if finding.Severity != "medium" {
			t.Fatalf("severity = %q, want medium", finding.Severity)
		}
		whereRx := regexp.MustCompile(`^GET http://127\.0\.0\.1:\d+/\?q=youkai[0-9a-f]{8} \(param: q\)$`)
		if !whereRx.MatchString(finding.Where) {
			t.Fatalf("where = %q, want the GET <url-with-marker> (param: q) shape", finding.Where)
		}
		candidate := findFact(obs, "参数反射待浏览器复核:")
		if candidate == nil {
			t.Fatalf("missing param-candidate fact, got %+v", obs.Facts)
		}
		if candidate.Statement != "参数反射待浏览器复核:"+finding.Where {
			t.Fatalf("candidate statement = %q", candidate.Statement)
		}
		if !hasTag(candidate.Tags, "reflects") || !hasTag(candidate.Tags, "param-candidate") {
			t.Fatalf("candidate tags = %v, want reflects + param-candidate", candidate.Tags)
		}
		if candidate.Evidence["where"] != finding.Where {
			t.Fatalf("candidate where = %v", candidate.Evidence["where"])
		}
		candidateURL, _ := candidate.Evidence["url"].(string)
		if !whereRx.MatchString("GET " + candidateURL + " (param: q)") {
			t.Fatalf("candidate url = %q, want the marker URL", candidateURL)
		}
		if candidate.Evidence["request_id"] != finding.Evidence["request_id"] ||
			candidate.Evidence["status"] != finding.Evidence["status"] {
			t.Fatalf("candidate evidence must cite the same request as the finding")
		}
		assertEvidence(t, obs)
	})

	t.Run("at most three parameters are probed", func(t *testing.T) {
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>static</body></html>")
		}))
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

		obs, err := Run(ctx, env, "scan", map[string]any{"url": srv.URL + "/?a=1&b=2&c=3&d=4&e=5"})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		// primary + CORS + three reflection probes + six exposure probes.
		if got := recorder.count(); got != 11 {
			t.Fatalf("audit events = %d, want 11 (reflection probes must be capped at 3)", got)
		}
		if got := countFindings(obs, "reflection"); got != 0 {
			t.Fatalf("reflection findings = %d, want 0 for a static page", got)
		}
		assertEvidence(t, obs)
	})
}

func TestHeadersThinCapability(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>x</body></html>")
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

	obs, err := Run(context.Background(), env, "headers", map[string]any{"url": srv.URL + "/"})
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	if recorder.count() != 1 {
		t.Fatalf("audit events = %d, want 1", recorder.count())
	}
	if got := countFindings(obs, "header-missing"); got != 4 {
		t.Fatalf("header-missing = %d, want 4", got)
	}
	if findFact(obs, "安全响应头检查未执行") != nil {
		t.Fatalf("header check should have run: %+v", obs.Facts)
	}
	assertEvidence(t, obs)
}

func TestCompare(t *testing.T) {
	ctx := context.Background()

	t.Run("marker visible to both accounts", func(t *testing.T) {
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>order ORDER-42 belongs to alice</body></html>")
		}))
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

		obs, err := Run(ctx, env, "compare", map[string]any{
			"url":       srv.URL + "/orders/1",
			"headers_a": map[string]any{"X-Account": "alice"},
			"headers_b": map[string]any{"X-Account": "bob"},
			"marker":    "ORDER-42",
		})
		if err != nil {
			t.Fatalf("compare: %v", err)
		}
		if recorder.count() != 2 {
			t.Fatalf("audit events = %d, want 2", recorder.count())
		}
		verdict := findFact(obs, "双账号比对")
		if verdict == nil || !strings.Contains(verdict.Statement, "marker-in-both") {
			t.Fatalf("missing marker-in-both verdict, got %+v", obs.Facts)
		}
		bola := findFact(obs, "越权候选")
		if bola == nil || !hasTag(bola.Tags, "bola") || !hasTag(bola.Tags, "idor") {
			t.Fatalf("missing BOLA fact, got %+v", obs.Facts)
		}
		finding := findFinding(obs, "bola")
		if finding == nil {
			t.Fatalf("missing bola finding, got %+v", obs.Findings)
		}
		if finding.Severity != "medium" {
			t.Fatalf("bola severity = %q, want medium", finding.Severity)
		}
		assertEvidence(t, obs)
	})

	t.Run("marker only in the first account", func(t *testing.T) {
		srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			if r.Header.Get("X-Account") == "alice" {
				fmt.Fprint(w, "<html><body>order ORDER-42</body></html>")
				return
			}
			fmt.Fprint(w, "<html><body>not found for you</body></html>")
		}))
		env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

		obs, err := Run(ctx, env, "compare", map[string]any{
			"url":       srv.URL + "/orders/1",
			"headers_a": map[string]any{"X-Account": "alice"},
			"headers_b": map[string]any{"X-Account": "bob"},
			"marker":    "ORDER-42",
		})
		if err != nil {
			t.Fatalf("compare: %v", err)
		}
		if recorder.count() != 2 {
			t.Fatalf("audit events = %d, want 2", recorder.count())
		}
		verdict := findFact(obs, "双账号比对")
		if verdict == nil || !strings.Contains(verdict.Statement, "marker-only-in-a") {
			t.Fatalf("missing marker-only-in-a verdict, got %+v", obs.Facts)
		}
		if findFinding(obs, "bola") != nil {
			t.Fatalf("unexpected bola finding when only A sees the marker: %+v", obs.Findings)
		}
		assertEvidence(t, obs)
	})
}

func TestCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/a">a</a><a href="/a">duplicate</a>
			<a href="https://elsewhere.invalid/out">external</a>
			<a href="#fragment">fragment</a>
		</body></html>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/">home</a><a href="/b">b</a></body></html>`)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>end</body></html>")
	})
	srv := newTestServer(t, mux)
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

	obs, err := Run(context.Background(), env, "crawl", map[string]any{
		"url":       srv.URL + "/",
		"max_pages": 5,
		"max_depth": 2,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	// seed + /a + /b; the external host and the duplicate are not fetched.
	if recorder.count() != 3 {
		t.Fatalf("audit events = %d, want 3", recorder.count())
	}
	for _, want := range []string{srv.URL + "/", srv.URL + "/a", srv.URL + "/b"} {
		if findFact(obs, "发现端点:"+want) == nil {
			t.Fatalf("missing endpoint fact for %s, got %+v", want, obs.Facts)
		}
	}
	if len(obs.Assets) != 3 {
		t.Fatalf("endpoint assets = %d, want 3: %+v", len(obs.Assets), obs.Assets)
	}
	if findFact(obs, "elsewhere.invalid") != nil {
		t.Fatal("crawl followed a cross-origin link")
	}
	assertEvidence(t, obs)
}

func TestRegistryMatchesGate(t *testing.T) {
	registry := Registry()
	if len(registry) != 20 {
		t.Fatalf("registry has %d capabilities, want 20", len(registry))
	}
	seen := map[string]bool{}
	for _, capability := range registry {
		if seen[capability.Name] {
			t.Fatalf("duplicate capability %q", capability.Name)
		}
		seen[capability.Name] = true
		if capability.Tier != gate.Classify(capability.Name, nil) {
			t.Fatalf("%s tier = %v, gate says %v", capability.Name,
				capability.Tier, gate.Classify(capability.Name, nil))
		}
		if capability.Tier == gate.TierDeep {
			t.Fatalf("%s is not on gate's allow-list", capability.Name)
		}
		if capability.Description == "" || capability.Run == nil {
			t.Fatalf("%s is incomplete", capability.Name)
		}
		if _, ok := Lookup(strings.ToUpper(capability.Name)); !ok {
			t.Fatalf("Lookup is not case-insensitive for %q", capability.Name)
		}
	}
	if _, ok := Lookup("nope"); ok {
		t.Fatal("Lookup found an unregistered capability")
	}
	if _, err := Run(context.Background(), nil, "nope", nil); err == nil {
		t.Fatal("Run accepted an unknown capability")
	}
}

func TestFingerprint(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div class="wp-content">x</div></body></html>`)
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

	obs, err := Run(context.Background(), env, "fingerprint", map[string]any{"url": srv.URL + "/"})
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if recorder.count() != 1 {
		t.Fatalf("audit events = %d, want 1", recorder.count())
	}
	for _, technology := range []string{"nginx", "PHP", "WordPress"} {
		if findFact(obs, "指纹:"+technology) == nil {
			t.Fatalf("missing fingerprint fact for %s, got %+v", technology, obs.Facts)
		}
	}
	if findFact(obs, "指纹:未识别") != nil {
		t.Fatal("fingerprint claimed no match while rules matched")
	}
	assertEvidence(t, obs)
}

func TestCORSAnyOriginWithCredentials(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		fmt.Fprint(w, "ok")
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

	obs, err := Run(context.Background(), env, "cors", map[string]any{"url": srv.URL + "/api"})
	if err != nil {
		t.Fatalf("cors: %v", err)
	}
	if recorder.count() != 1 {
		t.Fatalf("audit events = %d, want 1", recorder.count())
	}
	finding := findFinding(obs, "cors")
	if finding == nil {
		t.Fatalf("missing cors finding, got %+v", obs.Findings)
	}
	if finding.Severity != "high" {
		t.Fatalf("cors severity = %q, want high when credentials are allowed", finding.Severity)
	}
	assertEvidence(t, obs)
}

func TestRedirectCheck(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/next")
			w.WriteHeader(http.StatusFound)
		case "/next":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>done</body></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

	obs, err := Run(context.Background(), env, "redirect_check", map[string]any{"url": srv.URL + "/"})
	if err != nil {
		t.Fatalf("redirect_check: %v", err)
	}
	// The guard follows hops itself, re-checking scope and auditing each one.
	if recorder.count() != 2 {
		t.Fatalf("audit events = %d, want 2 (one per hop)", recorder.count())
	}
	if findFact(obs, "重定向链:") == nil {
		t.Fatalf("missing redirect-chain fact, got %+v", obs.Facts)
	}
	assertEvidence(t, obs)
}

func TestStubsRefuseWithoutRequests(t *testing.T) {
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	ctx := context.Background()
	before := recorder.count()

	for _, name := range []string{"reachability", "accounts_seed", "accounts_register", "object_seed"} {
		obs, err := Run(ctx, env, name, nil)
		if err == nil {
			t.Fatalf("%s should return a precise error", name)
		}
		if !obs.Empty() {
			t.Fatalf("%s returned an observation: %+v", name, obs)
		}
	}
	if _, err := Run(ctx, env, "browser", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("browser error = %v, want ErrUnavailable", err)
	}
	if recorder.count() != before {
		t.Fatalf("stubs sent %d requests, want 0", recorder.count()-before)
	}
}
