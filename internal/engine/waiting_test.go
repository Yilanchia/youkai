package engine

import (
	"context"
	"testing"

	"youkai/internal/ledger"
)

// TestRunExplainsADependencyWaitingOnApproval is the "it did nothing" fix at the
// engine level: a run whose only remaining work waits on an unapproved tier-2 step
// must say so, naming the step - not report a silent idle.
func TestRunExplainsADependencyWaitingOnApproval(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 6})

	// Step 1: tier 2, parked. Step 2: tier 1 but waits for step 1.
	login, _, err := f.EnsureIntent(context.Background(), 1, ledger.IntentSpec{
		Capability: "accounts_provision", Args: map[string]any{"session": "alice"},
		Tier: 2, RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("seed login: %v", err)
	}
	scan, _, err := f.EnsureIntent(context.Background(), 1, ledger.IntentSpec{
		Capability: "scan", Args: map[string]any{"url": "http://127.0.0.1/api"},
		Tier: 1, Deps: []int64{login.ID},
	})
	if err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	rep, err := eng.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Stop != StopNeedsApproval {
		t.Fatalf("stop = %q, want needs_approval (not idle)", rep.Stop)
	}
	if rep.Reason == "" || !containsAll(rep.Reason, "#", login.Capability, scan.Capability) {
		t.Fatalf("the reason does not name the blocking step: %q", rep.Reason)
	}
}

// TestWaitingOnApprovalIsEmptyWhenNothingIsParked: a genuinely idle run still says
// idle, not "waiting".
func TestWaitingOnApprovalIsEmptyWhenNothingIsParked(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 4})
	if got := eng.waitingOnApproval(ledger.GraphView{}); len(got) != 0 {
		t.Fatalf("empty graph produced %v", got)
	}
}

func containsAll(hay string, needles ...string) bool {
	for _, n := range needles {
		if !contains(hay, n) {
			return false
		}
	}
	return true
}
