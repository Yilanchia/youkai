package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOAuthImplicitFlowAndWideScope: the well-known document alone is enough to
// report both configuration smells; no token is ever requested.
func TestOAuthImplicitFlowAndWideScope(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".well-known") {
			_, _ = w.Write([]byte(`{
			  "issuer": "https://issuer.example",
			  "authorization_endpoint": "https://issuer.example/authorize",
			  "token_endpoint": "https://issuer.example/token",
			  "response_types_supported": ["code", "token"],
			  "code_challenge_methods_supported": ["S256"],
			  "scopes_supported": ["openid","profile","admin","offline_access","write"]
			}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "oauth_audit", map[string]any{"url": lab.URL})
	if err != nil {
		t.Fatalf("oauth_audit: %v", err)
	}
	var implicit, scope bool
	for _, f := range obs.Findings {
		if strings.Contains(f.Title, "隐式流") {
			implicit = true
		}
		if strings.Contains(f.Title, "scope") {
			scope = true
		}
	}
	if !implicit || !scope {
		t.Fatalf("implicit=%v scope=%v findings=%+v", implicit, scope, obs.Findings)
	}
}

// TestOAuthWeakStateIsFlagged: a short or patterned state cannot bind the callback.
func TestOAuthWeakStateIsFlagged(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("consent page"))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "oauth_audit", map[string]any{
		"url":           lab.URL,
		"authorize_url": lab.URL + "/authorize?response_type=code&state=aaa&client_id=x",
	})
	if err != nil {
		t.Fatalf("oauth_audit: %v", err)
	}
	var found bool
	for _, f := range obs.Findings {
		if strings.Contains(f.Title, "state") {
			found = true
		}
	}
	if !found {
		t.Fatalf("weak state not flagged: %+v", obs.Findings)
	}
}

// TestHeaderReflectionProbeSeesTheMarker: the marker coming back in the body is the
// whole signal.
func TestHeaderReflectionProbeSeesTheMarker(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("host")
		_, _ = w.Write([]byte("<p>your host is " + v + "</p>"))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/echo?host=x", "param": "host", "classes": []string{"header"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	var hit bool
	for _, f := range obs.Findings {
		if f.Kind == "header-reflection" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("reflection not reported: %+v %+v", obs.Findings, obs.Facts)
	}
}
