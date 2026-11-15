package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoSQLProbeSeesAnOperatorShift: an operator-shaped value that changes the
// response is a lead; the probe must not fetch any records.
func TestNoSQLProbeSeesAnOperatorShift(t *testing.T) {
	plain := "<html>" + strings.Repeat("a", 50) + "</html>"
	shifted := "<html>" + strings.Repeat("b", 400) + "</html>"
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("user")
		if strings.Contains(v, "$ne") || strings.Contains(v, "$gt") {
			_, _ = w.Write([]byte(shifted))
			return
		}
		_, _ = w.Write([]byte(plain))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/users?user=alice", "param": "user", "classes": []string{"nosql"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	var hit bool
	for _, f := range obs.Findings {
		if f.Kind == "nosql" {
			hit = true
			if strings.Contains(f.Detail, plain) || strings.Contains(f.Detail, shifted) {
				t.Fatal("the finding copied response content")
			}
		}
	}
	if !hit {
		t.Fatalf("operator shift not reported: %+v %+v", obs.Findings, obs.Facts)
	}
}

// TestCRLFProbeSeesItsOwnHeader: the injected header name coming back is the whole
// signal; nothing else about the response matters.
func TestCRLFProbeSeesItsOwnHeader(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("next")
		// Echo whatever header name the probe injected: the probe generates a fresh
		// random suffix per run, so a fixed name could never match.
		if i := strings.Index(v, "X-Youkai-Probe-"); i >= 0 {
			rest := v[i:]
			if j := strings.Index(rest, ":"); j > 0 {
				w.Header().Set(rest[:j], "1")
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))

	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/go?next=/home", "param": "next", "classes": []string{"crlf"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	var hit bool
	for _, f := range obs.Findings {
		if f.Kind == "crlf" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("header injection not reported: %+v %+v", obs.Findings, obs.Facts)
	}
}

// TestNoSQLNoFalsePositiveOnPlainParams: an ordinary parameter must stay quiet.
func TestNoSQLNoFalsePositiveOnPlainParams(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>stable</html>"))
	}))
	defer lab.Close()
	env := probeEnv(t, strings.TrimPrefix(lab.URL, "http://"))
	obs, err := Run(context.Background(), env, "param", map[string]any{
		"url": lab.URL + "/users?user=alice", "param": "user", "classes": []string{"nosql"},
	})
	if err != nil {
		t.Fatalf("param: %v", err)
	}
	if len(obs.Findings) != 0 {
		t.Fatalf("a stable response produced a finding: %+v", obs.Findings)
	}
}
