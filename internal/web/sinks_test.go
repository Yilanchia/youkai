package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// probeEnv builds a guard scoped to one loopback lab, with active probing allowed.
// POST is unlocked too: the XXE and upload probes submit bodies.
func probeEnv(t *testing.T, host string) *Env {
	t.Helper()
	env, _ := newTestEnv(t, []string{host}, func(s *discipline.Scope) {
		s.AllowActiveProbes = true
		s.AllowPrivate = true
		s.Methods = []string{
			http.MethodGet, http.MethodHead, http.MethodOptions,
			http.MethodPost, http.MethodPut,
		}
	})
	return env
}

// TestSSRFProbeHitsTheCanary: the lab fetches whatever URL it is given, so the
// probe sees its own canary called back and reports existence.
func TestSSRFProbeHitsTheCanary(t *testing.T) {
	var labURL string
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable by construction: fetch the caller-supplied URL.
		if target := r.URL.Query().Get("next"); target != "" {
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			if res, err := http.DefaultClient.Do(req); err == nil {
				_ = res.Body.Close()
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer lab.Close()
	labURL = lab.URL

	env := probeEnv(t, strings.TrimPrefix(labURL, "http://"))
	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": labURL + "/fetch?next=nothing", "param": "next", "classes": []string{"ssrf"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	var hit bool
	for _, f := range obs.Findings {
		if f.Kind == "ssrf" {
			hit = true
			if f.Evidence["request_id"] == nil || f.Evidence["request_id"] == "" {
				t.Fatalf("an ssrf finding without a request id: %+v", f)
			}
			// The canary must never carry what the target sent.
			for k := range f.Evidence {
				if strings.Contains(strings.ToLower(k), "body") || strings.Contains(strings.ToLower(k), "content") {
					t.Fatalf("the ssrf evidence carries target content: %s", k)
				}
			}
		}
	}
	if !hit {
		t.Fatalf("canary was not reached; findings=%+v facts=%+v", obs.Findings, obs.Facts)
	}
}

// TestSSRFProbeSaysUndetermined: no callback means "could not judge", not "safe".
func TestSSRFProbeSaysUndetermined(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ignored"))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/fetch?next=nothing", "param": "next", "classes": []string{"ssrf"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	if len(obs.Findings) != 0 {
		t.Fatalf("a finding appeared without a callback: %+v", obs.Findings)
	}
	var said bool
	for _, f := range obs.Facts {
		if strings.Contains(f.Statement, "未能判定") {
			said = true
		}
	}
	if !said {
		t.Fatalf("the probe did not say it could not judge: %+v", obs.Facts)
	}
}

// TestPathTraversalProbeFindsTheMarker: the lab resolves ../../ and returns the
// marker file, which is exactly the signal the probe looks for.
func TestPathTraversalProbeFindsTheMarker(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "..") || strings.Contains(file, "....//") {
			_, _ = w.Write([]byte("youkai-path-marker"))
			return
		}
		http.NotFound(w, r)
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/download?file=public.txt", "param": "file",
		"classes": []string{"path"}, "marker": "youkai-path-marker",
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	var hit bool
	for _, f := range obs.Findings {
		if f.Kind == "path-traversal" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("path traversal not detected: %+v %+v", obs.Findings, obs.Facts)
	}
	// The evidence says "marker appeared", not "here is the file".
	for _, f := range obs.Findings {
		if strings.Contains(f.Detail, "youkai-path-marker\n") {
			t.Fatalf("the finding copied file content: %q", f.Detail)
		}
	}
}

// TestCMDIProbeMeasuresDelayOnly: the injected command is a sleep, and the finding
// carries timing, never output.
func TestCMDIProbeMeasuresDelayOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing probe")
	}
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if strings.Contains(host, "sleep 2") {
			time.Sleep(2100 * time.Millisecond)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/ping?host=127.0.0.1", "param": "host", "classes": []string{"cmdi"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	var hit *ledger.FindingSeed
	for i := range obs.Findings {
		if obs.Findings[i].Kind == "cmdi" {
			hit = &obs.Findings[i]
		}
	}
	if hit == nil {
		t.Fatalf("delay not detected: %+v %+v", obs.Findings, obs.Facts)
	}
	if strings.Contains(hit.Detail, "uid=") || strings.Contains(hit.Detail, "root:") {
		t.Fatalf("the finding contains command output: %q", hit.Detail)
	}
	if _, ok := hit.Evidence["payload_shape"]; !ok {
		t.Fatalf("the timing evidence is missing: %+v", hit.Evidence)
	}
}

// TestDeserializeIsRefusedNotProbed is the third red line: no active probe exists,
// and asking for one must fail loudly.
func TestDeserializeIsRefusedNotProbed(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	_, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/q?x=1", "param": "x", "classes": []string{"deserialize"},
	})
	if err == nil {
		t.Fatal("a deserialize probe was accepted")
	}
	if !strings.Contains(err.Error(), "反序列化") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
}

// TestUploadProbeSendsATextMarkerOnly: the body must be plain text, and the finding
// must never claim execution.
func TestUploadProbeSendsATextMarkerOnly(t *testing.T) {
	var sawBody string
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		sawBody = string(buf[:n])
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/upload?f=x", "param": "f", "classes": []string{"upload"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	if strings.Contains(sawBody, "<?php") || strings.Contains(sawBody, "<script") {
		t.Fatalf("the upload body contains executable content: %q", sawBody)
	}
	var hit bool
	for _, f := range obs.Findings {
		if f.Kind == "upload" {
			hit = true
			if strings.Contains(f.Detail, "执行") && !strings.Contains(f.Detail, "没有尝试运行") {
				t.Fatalf("the upload finding implies execution: %q", f.Detail)
			}
		}
	}
	if !hit {
		t.Fatalf("accepted upload not reported: %+v", obs.Facts)
	}
}

// TestCanaryKeepsNoBody: whatever the target sends stays out of the record.
func TestCanaryKeepsNoBody(t *testing.T) {
	c := canaryOf()
	url, token, err := c.Token()
	if err != nil {
		t.Fatalf("canary: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader("SECRET-PAYLOAD-123"))
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatalf("hit: %v", err)
	}
	if c.Hits(token) != 1 {
		t.Fatalf("hits = %d", c.Hits(token))
	}
	if remote := c.RemoteOf(token); strings.Contains(remote, "SECRET") {
		t.Fatalf("the canary recorded content: %q", remote)
	}
}
