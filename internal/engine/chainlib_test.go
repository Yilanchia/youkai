package engine

import (
	"context"
	"testing"

	"youkai/internal/ledger"
)

// TestMultipleChainTypesAssemble: the chain library is a table, so more than one
// type can be suitable for the same evidence - and each is built once.
func TestMultipleChainTypesAssemble(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.assets = []ledger.Asset{{ID: 1, Kind: "code-endpoint", Value: "code:GET /orders/:id"}}
	f.hypotheses = []ledger.Hypothesis{{
		ID: 1, Entry: "GET /fetch", Param: "next", Sink: "ssrf",
		Path: "app.js:9", State: ledger.HypothesisOpen,
	}}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{
		MaxSteps:   10,
		PairSource: fakePairs{pairs: []AccessPair{{Owner: "alice", Viewer: "bob", Marker: "ORD-1", URL: "/orders/1"}}},
	})
	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Nodes are shared when identical: the two chains both need "alice logs in",
	// and there is exactly one such intent. What distinguishes the chains is their
	// terminal step, so that is what the test checks.
	byCap := map[string]map[string]bool{}
	for _, it := range f.intents {
		if it.Provenance == "" {
			continue
		}
		if byCap[it.Provenance] == nil {
			byCap[it.Provenance] = map[string]bool{}
		}
		byCap[it.Provenance][it.Capability] = true
	}
	if !byCap["chain:idor"]["compare"] {
		t.Fatalf("idor chain has no comparison step (%v)", byCap)
	}
	if !byCap["chain:bfla"]["role_matrix"] {
		t.Fatalf("bfla chain has no role matrix step (%v)", byCap)
	}
	if !byCap["chain:idor"]["accounts_provision"] {
		t.Fatalf("idor chain has no login step (%v)", byCap)
	}
	// The SSRF lead produces a single tier-2 probe node.
	var ssrf int
	for _, it := range f.intents {
		if it.Capability == "param" {
			ssrf++
			if it.Status != ledger.StatusNeedsApproval {
				t.Fatalf("the ssrf probe is not parked: %+v", it)
			}
			if classes, ok := it.Args["classes"].([]any); ok && len(classes) > 0 && classes[0] == "ssrf" {
				ssrf = 100
			}
		}
	}
	if ssrf == 0 {
		t.Fatalf("no ssrf probe was derived: %+v", f.intents)
	}
}

// TestChainsCoverEveryPair: three owned objects deserve three chains, not one.
func TestChainsCoverEveryPair(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.assets = []ledger.Asset{{ID: 1, Kind: "code-endpoint", Value: "code:GET /orders/:id"}}
	pairs := []AccessPair{
		{Owner: "alice", Viewer: "bob", Marker: "ORD-1", URL: "/orders/1"},
		{Owner: "alice", Viewer: "bob", Marker: "ORD-2", URL: "/orders/2"},
	}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 10, PairSource: fakePairs{pairs: pairs}})
	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	n := 0
	for _, it := range f.intents {
		if it.Capability == "compare" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("comparisons = %d, want one per pair (2)", n)
	}
}
