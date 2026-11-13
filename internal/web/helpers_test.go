package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// The tests use httptest servers as the *target*, never as an egress: every byte
// the capabilities send still goes through a real discipline.Guard with a real
// scope passport and a recording auditor. Asserting len(events) after each call
// is what proves the guard was actually in the path.

type auditRecorder struct {
	mu     sync.Mutex
	events []discipline.AuditEvent
}

func (a *auditRecorder) Record(_ context.Context, ev discipline.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *auditRecorder) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

func (a *auditRecorder) snapshot() []discipline.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]discipline.AuditEvent, len(a.events))
	copy(out, a.events)
	return out
}

// newTestEnv builds a guard over 127.0.0.1 with a fast token bucket so tests do
// not sleep. mutate can unlock tier-2 flags or add write methods per test.
func newTestEnv(t *testing.T, include []string, mutate func(*discipline.Scope)) (*Env, *auditRecorder) {
	t.Helper()
	recorder := &auditRecorder{}
	scope := discipline.Scope{
		Project:      "web-test",
		Include:      include,
		Basis:        "unit test authorisation for a local httptest target",
		Operator:     "test",
		Methods:      []string{http.MethodGet, http.MethodHead, http.MethodOptions},
		AllowPrivate: true,
		RPS:          1000,
		MaxRequests:  500,
		MaxRedirects: 3,
	}
	if mutate != nil {
		mutate(&scope)
	}
	guard, err := discipline.NewGuard(discipline.NewScope(scope), "web-test", recorder)
	if err != nil {
		t.Fatalf("build guard: %v", err)
	}
	return &Env{Guard: guard, EngagementID: 1, Engagement: "web-test"}, recorder
}

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// findFact returns the first fact whose statement contains substr.
func findFact(obs ledger.Observation, substr string) *ledger.FactSeed {
	for i := range obs.Facts {
		if strings.Contains(obs.Facts[i].Statement, substr) {
			return &obs.Facts[i]
		}
	}
	return nil
}

// findFinding returns the first finding of a kind.
func findFinding(obs ledger.Observation, kind string) *ledger.FindingSeed {
	for i := range obs.Findings {
		if obs.Findings[i].Kind == kind {
			return &obs.Findings[i]
		}
	}
	return nil
}

func countFindings(obs ledger.Observation, kind string) int {
	n := 0
	for _, f := range obs.Findings {
		if f.Kind == kind {
			n++
		}
	}
	return n
}

// assertEvidence proves every fact and finding names an audited request, and that
// the observation's RequestIDs are exactly the ids it claims.
func assertEvidence(t *testing.T, obs ledger.Observation) {
	t.Helper()
	if len(obs.RequestIDs) == 0 {
		t.Fatalf("observation claims no requests")
	}
	known := map[string]bool{}
	for _, id := range obs.RequestIDs {
		if id == "" {
			t.Fatalf("empty request id in RequestIDs")
		}
		known[id] = true
	}
	for i, f := range obs.Facts {
		id := requestIDOf(f.Evidence)
		if id == "" {
			t.Errorf("fact[%d] %q carries no request_id", i, f.Statement)
			continue
		}
		if !known[id] {
			t.Errorf("fact[%d] %q cites request %q not in RequestIDs", i, f.Statement, id)
		}
	}
	for i, f := range obs.Findings {
		id := requestIDOf(f.Evidence)
		if id == "" {
			t.Errorf("finding[%d] %q carries no request_id", i, f.Title)
			continue
		}
		if !known[id] {
			t.Errorf("finding[%d] %q cites request %q not in RequestIDs", i, f.Title, id)
		}
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// observationText flattens an observation for "this secret must not appear"
// assertions.
func observationText(obs ledger.Observation) string {
	var b strings.Builder
	for _, f := range obs.Facts {
		fmt.Fprintf(&b, "%s %v\n", f.Statement, f.Evidence)
	}
	for _, f := range obs.Findings {
		fmt.Fprintf(&b, "%s %s %s %v\n", f.Title, f.Detail, f.Where, f.Evidence)
	}
	fmt.Fprintf(&b, "%s\n", obs.Summary)
	return b.String()
}
