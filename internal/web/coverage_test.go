package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"youkai/internal/discipline"
)

// ---- API schema ingestion ---------------------------------------------------

const openAPI3 = `{
  "openapi": "3.0.3",
  "info": {"title": "lab api", "version": "1"},
  "servers": [{"url": "SERVER"}],
  "paths": {
    "/api/users/{id}": {"get": {"summary": "read user"}},
    "/api/orders": {
      "get": {"summary": "list orders"},
      "post": {"summary": "create order"}
    },
    "/api/health": {"get": {}}
  }
}`

func specServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, strings.ReplaceAll(openAPI3, "SERVER", srv.URL))
	}))
	return srv
}

func TestAPISpecRegistersTheDocumentedSurface(t *testing.T) {
	srv := specServer(t)
	defer srv.Close()
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)

	obs, err := Run(context.Background(), env, "api_spec", map[string]any{"url": srv.URL + "/openapi.json"})
	if err != nil {
		t.Fatalf("api_spec: %v", err)
	}
	if len(obs.Assets) != 3 {
		t.Fatalf("assets = %d, want 3: %+v", len(obs.Assets), obs.Assets)
	}
	for _, a := range obs.Assets {
		if a.Kind != "endpoint" {
			t.Fatalf("asset kind = %q", a.Kind)
		}
	}
	text := observationText(obs)
	if !strings.Contains(text, "POST") || !strings.Contains(text, "写方法") {
		t.Fatalf("the write operation is not labelled: %s", text)
	}
	if !strings.Contains(text, "需样本 id") {
		t.Fatalf("a path-parameter endpoint is not flagged as needing a sample: %s", text)
	}
	// Tags live on the fact, not in its statement text.
	sawSource := false
	for _, f := range obs.Facts {
		for _, tag := range f.Tags {
			if tag == "source=openapi" {
				sawSource = true
			}
		}
	}
	if !sawSource {
		t.Fatalf("endpoints are not tagged with their source: %+v", obs.Facts)
	}
	// Exactly one request: the document itself. api_spec does not probe endpoints.
	if recorder.count() != 1 {
		t.Fatalf("api_spec sent %d requests, want 1 (only the document)", recorder.count())
	}
}

func TestAPISpecMarksOutOfScopeEndpoints(t *testing.T) {
	// A spec whose server points at a host the passport does not cover.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, strings.ReplaceAll(openAPI3, "SERVER", "https://not-in-scope.invalid"))
	}))
	defer srv.Close()
	env, _ := newTestEnv(t, []string{"127.0.0.1"}, nil)

	obs, err := Run(context.Background(), env, "api_spec", map[string]any{"url": srv.URL + "/openapi.json"})
	if err != nil {
		t.Fatalf("api_spec: %v", err)
	}
	if len(obs.Assets) != 0 {
		t.Fatalf("out-of-scope endpoints were registered as assets: %+v", obs.Assets)
	}
	text := observationText(obs)
	if !strings.Contains(text, "超出 scope") {
		t.Fatalf("out-of-scope endpoints were not reported: %s", text)
	}
}

func TestAPISpecAcceptsYAML(t *testing.T) {
	yamlSpec := `openapi: 3.0.0
info:
  title: yaml api
  version: "1"
paths:
  /api/thing:
    get:
      summary: read thing
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = fmt.Fprint(w, yamlSpec)
	}))
	defer srv.Close()
	env, _ := newTestEnv(t, []string{"127.0.0.1"}, nil)
	obs, err := Run(context.Background(), env, "api_spec", map[string]any{"url": srv.URL + "/openapi.yaml"})
	if err != nil {
		t.Fatalf("api_spec yaml: %v", err)
	}
	if len(obs.Assets) != 1 || !strings.Contains(obs.Assets[0].Value, "/api/thing") {
		t.Fatalf("yaml spec did not register its path: %+v", obs.Assets)
	}
}

// TestAPISpecTreatsTheDocumentAsData: garbage and hostile shapes must degrade to a
// fact, never to a panic, and must never cause another request.
func TestAPISpecTreatsTheDocumentAsData(t *testing.T) {
	cases := map[string]string{
		"not a spec":   `{"hello":"world"}`,
		"broken json":  `{"openapi":`,
		"cyclic ref":   `{"openapi":"3.0.0","paths":{"/a":{"get":{"$ref":"#/paths/~1a/get"}}}}`,
		"external ref": `{"openapi":"3.0.0","servers":[{"url":"http://127.0.0.1:1"}],"paths":{"/a":{"get":{"$ref":"https://evil.invalid/x.yaml#/y"}}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, body)
			}))
			defer srv.Close()
			env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
			obs, err := Run(context.Background(), env, "api_spec", map[string]any{"url": srv.URL + "/spec"})
			if err == nil && len(obs.Facts) == 0 && len(obs.Assets) == 0 {
				t.Fatalf("%s: silently produced nothing", name)
			}
			// One request for the document, and nothing for a $ref.
			if recorder.count() != 1 {
				t.Fatalf("%s: %d requests (an external $ref must never be fetched)", name, recorder.count())
			}
		})
	}
}

// ---- GraphQL ----------------------------------------------------------------

func TestGraphQLIntrospectionRegistersFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("introspection must be POST, got %s", r.Method)
		}
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !strings.Contains(req.Query, "__schema") {
			t.Errorf("unexpected query: %s", req.Query)
		}
		_, _ = fmt.Fprint(w, `{"data":{"__schema":{
			"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},
			"types":[
			  {"kind":"OBJECT","name":"Query","fields":[{"name":"user","args":[{"name":"id"}]}]},
			  {"kind":"OBJECT","name":"Mutation","fields":[{"name":"deleteUser","args":[{"name":"id"}]}]},
			  {"kind":"OBJECT","name":"User","fields":[{"name":"email"}]}
			]}}}`)
	}))
	defer srv.Close()
	// GraphQL introspection is a POST; the passport must authorise the method.
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
		s.Methods = append(s.Methods, "POST")
	})

	obs, err := Run(context.Background(), env, "graphql_introspect", map[string]any{"url": srv.URL + "/graphql"})
	if err != nil {
		t.Fatalf("graphql: %v", err)
	}
	text := observationText(obs)
	if !strings.Contains(text, "GraphQL query:Query.user") {
		t.Fatalf("query field not registered: %s", text)
	}
	mutationFact := false
	for _, f := range obs.Facts {
		if !strings.Contains(f.Statement, "GraphQL mutation:Mutation.deleteUser") {
			continue
		}
		mutationFact = true
		labelled := false
		for _, tag := range f.Tags {
			if tag == "tier-hint=proof" {
				labelled = true
			}
		}
		if !labelled {
			t.Fatalf("mutation fact is not labelled as a write: %+v", f.Tags)
		}
	}
	if !mutationFact {
		t.Fatalf("mutation not registered: %+v", obs.Facts)
	}
	if strings.Contains(text, "User.email") {
		t.Fatalf("non-root types were registered as operations: %s", text)
	}
	if len(obs.Findings) != 1 || obs.Findings[0].Kind != "exposure" {
		t.Fatalf("expected one exposure finding, got %+v", obs.Findings)
	}
	if recorder.count() != 1 {
		t.Fatalf("introspection sent %d requests, want exactly 1", recorder.count())
	}
}

func TestGraphQLIntrospectionDisabledDegradesHonestly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"introspection disabled"}]}`)
	}))
	defer srv.Close()
	env, _ := newTestEnv(t, []string{"127.0.0.1"}, func(s *discipline.Scope) {
		s.Methods = append(s.Methods, "POST")
	})
	obs, err := Run(context.Background(), env, "graphql_introspect", map[string]any{"url": srv.URL + "/graphql"})
	if err != nil {
		t.Fatalf("graphql: %v", err)
	}
	if len(obs.Findings) != 0 {
		t.Fatalf("a refused introspection produced findings: %+v", obs.Findings)
	}
	if !strings.Contains(observationText(obs), "introspection 不可用") {
		t.Fatalf("the refusal is not stated: %s", observationText(obs))
	}
}

// ---- JWT --------------------------------------------------------------------

func makeJWT(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	enc := func(v map[string]any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return enc(header) + "." + enc(claims) + ".c2lnbmF0dXJl"
}

func TestJWTAuditFindsConfigRisksWithoutTheToken(t *testing.T) {
	token := makeJWT(t,
		map[string]any{"alg": "none", "typ": "JWT", "kid": "k1"},
		map[string]any{"sub": "alice", "role": "admin"})
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	env.SessionName = "alice"
	env.SessionHeaders = map[string]string{"Cookie": "sid=" + token}

	obs, err := Run(context.Background(), env, "jwt_audit", map[string]any{
		"session": "alice", "request_id": "R-LOGIN-1",
	})
	if err != nil {
		t.Fatalf("jwt_audit: %v", err)
	}
	text := observationText(obs)
	for _, want := range []string{"alg=none", "缺少 exp", "敏感授权 claim", "kid"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected a finding about %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, token) || strings.Contains(text, "c2lnbmF0dXJl") {
		t.Fatal("the token or its signature reached the observation")
	}
	if strings.Contains(text, "admin\"") || strings.Contains(text, `"alice"`) {
		t.Fatalf("a claim VALUE reached the observation: %s", text)
	}
	// With a caller-supplied anchor, no request is made at all.
	if recorder.count() != 0 {
		t.Fatalf("jwt_audit sent %d requests, want 0", recorder.count())
	}
	if countFindings(obs, "jwt") < 3 {
		t.Fatalf("jwt findings = %d", countFindings(obs, "jwt"))
	}
}

func TestJWTAuditNeedsAnAnchor(t *testing.T) {
	token := makeJWT(t, map[string]any{"alg": "RS256"}, map[string]any{"exp": 9999999999})
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	env.SessionName = "alice"
	env.SessionHeaders = map[string]string{"Authorization": "Bearer " + token}

	if _, err := Run(context.Background(), env, "jwt_audit", map[string]any{"session": "alice"}); err == nil {
		t.Fatal("jwt_audit ran without a request anchor")
	}
	if recorder.count() != 0 {
		t.Fatal("a refused audit still sent a request")
	}
}

func TestJWTAuditUsesOneReadOnlyRequestWhenGivenAURL(t *testing.T) {
	token := makeJWT(t, map[string]any{"alg": "HS256"}, map[string]any{"exp": 9999999999})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("the anchor request must be GET, got %s", r.Method)
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	env.SessionName = "alice"
	env.SessionHeaders = map[string]string{"Cookie": "sid=" + token}

	obs, err := Run(context.Background(), env, "jwt_audit", map[string]any{
		"session": "alice", "url": srv.URL + "/me",
	})
	if err != nil {
		t.Fatalf("jwt_audit: %v", err)
	}
	if recorder.count() != 1 {
		t.Fatalf("anchor requests = %d, want 1", recorder.count())
	}
	if len(obs.RequestIDs) != 1 {
		t.Fatalf("the finding is not anchored to a request: %v", obs.RequestIDs)
	}
}

func TestJWTAuditIgnoresANonJWTSession(t *testing.T) {
	env, _ := newTestEnv(t, []string{"127.0.0.1"}, nil)
	env.SessionName = "alice"
	env.SessionHeaders = map[string]string{"Cookie": "sid=plain-session-id"}
	if _, err := Run(context.Background(), env, "jwt_audit", map[string]any{
		"session": "alice", "request_id": "R-1",
	}); err == nil {
		t.Fatal("jwt_audit accepted a session without a JWT")
	}
}

// ---- OAuth ------------------------------------------------------------------

func TestOAuthAuditFlagsMissingStateAndPkce(t *testing.T) {
	var authorizeHits int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q}`,
				srv.URL, srv.URL+"/authorize", srv.URL+"/token")
		case "/authorize":
			authorizeHits++
			// A lax server: accepts any redirect_uri and redirects back to it.
			w.Header().Set("Location", r.URL.Query().Get("redirect_uri")+"?code=XYZ")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	env, recorder := newTestEnv(t, []string{"127.0.0.1"}, nil)
	obs, err := Run(context.Background(), env, "oauth_audit", map[string]any{
		"url":           srv.URL,
		"authorize_url": srv.URL + "/authorize?response_type=code&client_id=app&redirect_uri=" + srv.URL + "/cb",
	})
	if err != nil {
		t.Fatalf("oauth_audit: %v", err)
	}
	text := observationText(obs)
	for _, want := range []string{"缺少 state", "缺少 PKCE", "redirect_uri 校验疑似宽松"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected a finding about %q:\n%s", want, text)
		}
	}
	// Two authorisation requests only (the original and the one redirect_uri
	// observation). No code exchange, no token endpoint.
	if authorizeHits != 2 {
		t.Fatalf("authorize hits = %d, want 2", authorizeHits)
	}
	if strings.Contains(text, "/token") && strings.Contains(text, "code=XYZ") {
		t.Fatal("the audit looks like it completed a flow")
	}
	if recorder.count() > 4 {
		t.Fatalf("oauth_audit sent %d requests; the audit must stay tiny", recorder.count())
	}
}

func TestOAuthAuditDoesNotFollowTheRedirect(t *testing.T) {
	var cbHit bool
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":%q}`, srv.URL)
		case "/authorize":
			w.Header().Set("Location", srv.URL+"/cb?code=ABC")
			w.WriteHeader(http.StatusFound)
		case "/cb":
			cbHit = true
		}
	}))
	defer srv.Close()
	env, _ := newTestEnv(t, []string{"127.0.0.1"}, nil)
	if _, err := Run(context.Background(), env, "oauth_audit", map[string]any{
		"url":           srv.URL,
		"authorize_url": srv.URL + "/authorize?response_type=code&state=s&code_challenge=c&redirect_uri=" + srv.URL + "/cb",
	}); err != nil {
		t.Fatalf("oauth_audit: %v", err)
	}
	if cbHit {
		t.Fatal("the audit followed the authorisation redirect (that would complete a flow)")
	}
}
