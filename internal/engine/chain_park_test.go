package engine

import (
	"context"
	"testing"

	"youkai/internal/ledger"
)

// TestChainNeverRunsItsOwnTierTwoNodes is the line the reviewer said they would
// check hardest: assembling a chain must not turn into "build it and run it".
//
// After a run with a full chain assembled, both login steps must still be waiting
// for a human, and the comparison - which depends on them - must not have run.
func TestChainNeverRunsItsOwnTierTwoNodes(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.assets = []ledger.Asset{{ID: 1, Kind: "code-endpoint", Value: "code:GET /orders/:id"}}
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{
		MaxSteps:   10,
		PairSource: fakePairs{pairs: []AccessPair{{Owner: "alice", Viewer: "bob", Marker: "ORD-1", URL: "/orders/1"}}},
	})
	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}

	var logins, compares int
	for _, it := range f.intents {
		switch it.Capability {
		case "accounts_provision":
			logins++
			if it.Status != ledger.StatusNeedsApproval {
				t.Fatalf("a chain login step is not waiting for a human: %+v", it)
			}
		case "compare":
			compares++
			if it.Status == ledger.StatusDone {
				t.Fatalf("the comparison ran before its dependencies were approved: %+v", it)
			}
			if len(it.Deps) != 2 {
				t.Fatalf("the comparison has no dependencies: %+v", it)
			}
		}
	}
	if logins != 2 || compares != 1 {
		t.Fatalf("logins=%d compares=%d, want 2/1", logins, compares)
	}
	// And the dispatcher must not have been asked to log anyone in.
	for _, c := range disp.all() {
		if c == "accounts_provision" || c == "compare" {
			t.Fatalf("a chain node executed autonomously: %v", disp.all())
		}
	}
}

// TestChainCriticalStepRanksFirst: the step others wait for is ordered ahead.
func TestChainCriticalStepRanksFirst(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 8})
	dep := ledger.Intent{ID: 1, Capability: "accounts_provision", Tier: 2,
		Args: map[string]any{"session": "alice"}}
	other := ledger.Intent{ID: 2, Capability: "scan", Tier: 1,
		Args: map[string]any{"url": "http://127.0.0.1/"}}
	waiter := ledger.Intent{ID: 3, Capability: "compare", Tier: 1,
		Args: map[string]any{"url": "/orders/1"}, Deps: []int64{1}}
	eng.lastGraph = ledger.GraphView{Intents: []ledger.Intent{dep, other, waiter}}

	scored := eng.orderWork([]ledger.Intent{other, dep})
	if scored[0].Intent.ID != 1 {
		t.Fatalf("the blocking step did not lead: %+v", scored)
	}
	var said bool
	for _, why := range scored[0].Why {
		if why == "链上关键步,别的步骤在等它(+4)" {
			said = true
		}
	}
	if !said {
		t.Fatalf("the reason is not stated: %v", scored[0].Why)
	}
}
