package engine

import (
	"testing"

	"youkai/internal/ledger"
)

// TestScoringPrefersEvidenceBackedWork: a probe derived from a whitebox lead must
// outrank a generic surface step.
func TestScoringPrefersEvidenceBackedWork(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 10})

	withLead := ledger.Intent{ID: 2, Capability: "param", Tier: 2,
		Args: map[string]any{"url": "http://127.0.0.1/search", "hypothesis_id": float64(7)}}
	generic := ledger.Intent{ID: 1, Capability: "headers", Tier: 1,
		Args: map[string]any{"url": "http://127.0.0.1/"}}

	leadScore, leadWhy := eng.scoreIntent(withLead)
	genScore, genWhy := eng.scoreIntent(generic)
	if leadScore <= genScore {
		t.Fatalf("hypothesis-backed score %d does not beat generic %d (%v vs %v)",
			leadScore, genScore, leadWhy, genWhy)
	}

	scored := eng.orderWork([]ledger.Intent{generic, withLead})
	if scored[0].Intent.ID != withLead.ID {
		t.Fatalf("order kept the generic step first: %+v", scored)
	}
	// The reasons must be legible, not a bare number.
	if len(scored[0].Why) == 0 {
		t.Fatal("the first step has no stated reason")
	}
}

// TestOrderingIsDeterministic: same inputs, same order, always.
func TestOrderingIsDeterministic(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 10})
	a := ledger.Intent{ID: 5, Capability: "scan", Tier: 1, Args: map[string]any{"url": "http://127.0.0.1/"}}
	b := ledger.Intent{ID: 3, Capability: "scan", Tier: 1, Args: map[string]any{"url": "http://127.0.0.1/x"}}
	first := eng.orderWork([]ledger.Intent{a, b})
	for i := 0; i < 5; i++ {
		again := eng.orderWork([]ledger.Intent{a, b})
		if again[0].Intent.ID != first[0].Intent.ID {
			t.Fatalf("order changed between runs: %d vs %d", again[0].Intent.ID, first[0].Intent.ID)
		}
	}
	// Equal scores break on intent id, so the smaller id wins.
	if first[0].Intent.ID != 3 {
		t.Fatalf("tie-break is not by id: %+v", first)
	}
}
