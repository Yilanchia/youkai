package engine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"youkai/internal/ledger"
)

// mandateFor builds an in-force mandate covering one class on one target.
func mandateFor(class, target string, max int) ledger.Mandate {
	return ledger.Mandate{
		ID: 7, Assets: []string{target}, Classes: []string{class},
		MaxRequests: max, ExpiresAt: time.Now().Add(time.Hour),
		ActivatedAt: time.Now().Add(-time.Minute),
	}
}

// TestNoMandateStillParksTier2 is the control: without a mandate nothing changed.
func TestNoMandateStillParksTier2(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 30})
	eng.cfg.PairSource = nil
	f.seedIntent(ledger.IntentSpec{Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:9/s?q=1"}})

	rep, err := eng.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Stop != StopNeedsApproval {
		t.Fatalf("stop = %q, want needs_approval", rep.Stop)
	}
	if got := f.intentByCapability("param"); got == nil || got.Status != ledger.StatusNeedsApproval {
		t.Fatalf("param intent = %+v", got)
	}
}

// TestMandateLetsTheCoveredClassRun: a signed mandate naming "param" for this
// target is what turns that one class into autonomous work.
func TestMandateLetsTheCoveredClassRun(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.mandate = mandateFor("param", "127.0.0.1:9", 500)
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 30})
	f.seedIntent(ledger.IntentSpec{Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:9/s?q=1"}})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := f.intentByCapability("param"); got == nil || got.Status != ledger.StatusDone {
		t.Fatalf("param under mandate = %+v, want done", got)
	}
	if n := disp.count("param"); n != 1 {
		t.Fatalf("param ran %d times, want 1 (calls: %v)", n, disp.all())
	}
	if line := f.traceFor("param"); line == "" || !contains(line, "under=mandate") {
		t.Fatalf("trace does not record the mandate: %q", line)
	}
}

// TestMandateDoesNotCoverOtherClasses: a mandate for param must not smuggle waf.
func TestMandateDoesNotCoverOtherClasses(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.mandate = mandateFor("param", "127.0.0.1:9", 500)
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 30})
	f.seedIntent(ledger.IntentSpec{Capability: "waf", Args: map[string]any{"url": "http://127.0.0.1:9/s?q=1"}})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := f.intentByCapability("waf"); got == nil || got.Status != ledger.StatusNeedsApproval {
		t.Fatalf("uncovered class ran: %+v", got)
	}
	if n := disp.count("waf"); n != 0 {
		t.Fatalf("waf ran %d times without a mandate covering it (calls: %v)", n, disp.all())
	}
}

// TestMandateDoesNotCoverOtherTargets: the same class against a different host.
func TestMandateDoesNotCoverOtherTargets(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1", "example.com"))
	f.mandate = mandateFor("param", "127.0.0.1:9", 500)
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 30})
	f.seedIntent(ledger.IntentSpec{Capability: "param", Args: map[string]any{"url": "http://example.com/s?q=1"}})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := f.intentByCapability("param"); got == nil || got.Status != ledger.StatusNeedsApproval {
		t.Fatalf("out-of-mandate target ran: %+v", got)
	}
	if n := disp.count("param"); n != 0 {
		t.Fatalf("param ran %d times off-mandate (calls: %v)", n, disp.all())
	}
}

// TestMandateBudgetExhaustionParks: the budget is measured from the audit log.
func TestMandateBudgetExhaustionParks(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.mandate = mandateFor("param", "127.0.0.1:9", 10)
	f.mandateUse = 10
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 30})
	f.seedIntent(ledger.IntentSpec{Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:9/s?q=1"}})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := f.intentByCapability("param"); got == nil || got.Status != ledger.StatusNeedsApproval {
		t.Fatalf("spent mandate still ran: %+v", got)
	}
	if n := disp.count("param"); n != 0 {
		t.Fatalf("param ran %d times past the budget (calls: %v)", n, disp.all())
	}
}

// TestExpiredMandateParks: expiry is enforced by the clock, not by cleanup.
func TestExpiredMandateParks(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	m := mandateFor("param", "127.0.0.1:9", 500)
	m.ExpiresAt = time.Now().Add(-time.Minute)
	f.mandate = m
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 30})
	f.seedIntent(ledger.IntentSpec{Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:9/s?q=1"}})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := f.intentByCapability("param"); got == nil || got.Status != ledger.StatusNeedsApproval {
		t.Fatalf("expired mandate still ran: %+v", got)
	}
}

// TestMandateReadFailureFailsClosed: a store error must not look like a mandate.
func TestMandateReadFailureFailsClosed(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.mandateErr = errors.New("database is down")
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 30})
	f.seedIntent(ledger.IntentSpec{Capability: "param", Args: map[string]any{"url": "http://127.0.0.1:9/s?q=1"}})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if n := disp.count("param"); n != 0 {
		t.Fatalf("a failed mandate read granted autonomy (%d param calls)", n)
	}
	if got := f.intentByCapability("param"); got == nil || got.Status != ledger.StatusNeedsApproval {
		t.Fatalf("intent = %+v", got)
	}
}

// mustStore builds the fake store with a passport, so the engine has a scope.
func mustStore(t *testing.T, scope json.RawMessage) *fakeStore {
	t.Helper()
	f := newFakeStore()
	f.scope = scope
	return f
}

// seedIntent puts one todo intent in the store, as the derive step would.
func (f *fakeStore) seedIntent(spec ledger.IntentSpec) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextIntent++
	f.intents = append(f.intents, ledger.Intent{
		ID: f.nextIntent, EngagementID: 1, Capability: spec.Capability,
		Args: spec.Args, Tier: spec.Tier, Status: ledger.StatusTodo,
		Fingerprint: ledger.Fingerprint(1, spec.Capability, spec.Args),
	})
}

// traceFor returns the first trace line recorded for a capability.
func (f *fakeStore) traceFor(capability string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.intents {
		if f.intents[i].Capability == capability && len(f.intents[i].Trace) > 0 {
			return f.intents[i].Trace
		}
	}
	return ""
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		(len(haystack) > len(needle) && indexOf(haystack, needle) >= 0))
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
