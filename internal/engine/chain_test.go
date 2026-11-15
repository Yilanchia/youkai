package engine

import (
	"context"
	"testing"

	"youkai/internal/ledger"
)

type fakePairs struct{ pairs []AccessPair }

func (f fakePairs) BolaPairs(context.Context) ([]AccessPair, error) { return f.pairs, nil }

// TestChainAssemblesWithDependencies: a code-side lead plus two owned identities
// produce a three-step chain whose last step waits for both logins.
func TestChainAssemblesWithDependencies(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.assets = []ledger.Asset{{ID: 1, Kind: "code-endpoint", Value: "code:GET /orders/:id"}}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{
		MaxSteps:   8,
		PairSource: fakePairs{pairs: []AccessPair{{Owner: "alice", Viewer: "bob", Marker: "ORD-1", URL: "/orders/1"}}},
	})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}

	var logins int
	var cmp *ledger.Intent
	for i := range f.intents {
		switch f.intents[i].Capability {
		case "accounts_provision":
			logins++
		case "compare":
			cmp = &f.intents[i]
		}
	}
	if logins != 2 {
		t.Fatalf("logins = %d, want 2 (one per identity)", logins)
	}
	if cmp == nil {
		t.Fatalf("no comparison step was assembled: %+v", f.intents)
	}
	if len(cmp.Deps) != 2 {
		t.Fatalf("compare deps = %v, want the two logins", cmp.Deps)
	}
	// The chain must not run the compare before its dependencies are done.
	if cmp.Status != ledger.StatusTodo {
		t.Fatalf("compare status = %q, want todo-but-blocked-by-deps", cmp.Status)
	}
	for _, id := range cmp.Deps {
		got := f.intentByID(id)
		if got == nil {
			t.Fatalf("dependency %d does not exist", id)
		}
		// The provision steps are tier 2: they must be parked, not executed.
		if got.Status != ledger.StatusNeedsApproval && got.Status != ledger.StatusDone {
			t.Fatalf("dep %d status = %q", id, got.Status)
		}
	}
}

// TestChainNeedsBothHalves: identities without a lead, or a lead without
// identities, must not produce a chain.
func TestChainNeedsBothHalves(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.assets = []ledger.Asset{{ID: 1, Kind: "code-endpoint", Value: "code:GET /orders/:id"}}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 6}) // no PairSource
	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, it := range f.intents {
		if it.Capability == "compare" || it.Capability == "accounts_provision" {
			t.Fatalf("a chain was built without identities: %+v", it)
		}
	}

	f2 := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng2 := newEngine(t, f2, &fakeDispatcher{}, Config{
		MaxSteps:   6,
		PairSource: fakePairs{pairs: []AccessPair{{Owner: "alice", Viewer: "bob", URL: "/orders/1"}}},
	})
	if _, err := eng2.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	// The plain BOLA rule may still derive a comparison; what must NOT happen is a
	// chain: no provision steps, and no dependencies attached to the comparison.
	for _, it := range f2.intents {
		if it.Capability == "accounts_provision" {
			t.Fatalf("a chain was built without a code-side lead: %+v", it)
		}
		if it.Capability == "compare" && len(it.Deps) > 0 {
			t.Fatalf("a comparison was chained without a lead: %+v", it)
		}
	}
}

// intentByID and statusOf live on the shared fake store where possible; these
// helpers keep the chain test readable.
func (f *fakeStore) intentByID(id int64) *ledger.Intent {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.intents {
		if f.intents[i].ID == id {
			return &f.intents[i]
		}
	}
	return nil
}
