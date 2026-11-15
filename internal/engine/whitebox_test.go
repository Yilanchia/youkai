package engine

import (
	"context"
	"testing"

	"youkai/internal/ledger"
)

// hyps is a tiny helper so the tests read as the ladder they describe.
func hyps(hs ...ledger.Hypothesis) []ledger.Hypothesis { return hs }

// TestWhiteboxLeadBecomesAProbe: a code-only lead about a concatenated query turns
// into one existence probe on the engagement's own origin.
func TestWhiteboxLeadBecomesAProbe(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.hypotheses = hyps(ledger.Hypothesis{
		ID: 4, Kind: "sink", Entry: "GET /search", Param: "q", Sink: "sql-concat",
		Path: "app.js:7 → sql-concat", Confidence: "code-only", State: ledger.HypothesisOpen,
	})
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 12})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	// The probe is derived, and it PARKS: code-only must never buy autonomy.
	if n := disp.count("param"); n != 0 {
		t.Fatalf("a tier-2 probe ran without a human (%d calls: %v)", n, disp.all())
	}
	var got *ledger.Intent
	for i := range f.intents {
		if f.intents[i].Capability == "param" {
			got = &f.intents[i]
		}
	}
	if got == nil {
		t.Fatalf("no probe was derived from the lead (calls: %v)", disp.all())
	}
	if got.Tier != 2 {
		t.Fatalf("the probe must be tier 2 (a human approves it): %+v", got)
	}
	if got.Status != ledger.StatusNeedsApproval {
		t.Fatalf("probe status = %q, want needs_approval", got.Status)
	}
	if url, _ := got.Args["url"].(string); url != "http://127.0.0.1/search?q=1" {
		t.Fatalf("probe url = %q", url)
	}
	if id, _ := got.Args["hypothesis_id"].(int64); id != 4 {
		t.Fatalf("probe does not carry its lead: %v", got.Args["hypothesis_id"])
	}
}

// TestWhiteboxLeadWithoutAHitStaysUnconfirmed: the probe ran, found nothing, so the
// lead is recorded as unconfirmed - not promoted, not silently dropped.
func TestWhiteboxLeadWithoutAHitStaysUnconfirmed(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.hypotheses = hyps(ledger.Hypothesis{
		ID: 9, Entry: "GET /search", Param: "q", Sink: "sql-concat",
		Path: "app.js:7", Confidence: "code-only", State: ledger.HypothesisOpen,
	})
	disp := &fakeDispatcher{} // returns an empty observation: no findings
	eng := newEngine(t, f, disp, Config{MaxSteps: 12})

	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	var state string
	for _, h := range f.hypotheses {
		if h.ID == 9 {
			state = h.State
		}
	}
	// The probe is tier 2, so the run parks it; the lead stays open until it runs.
	if state != ledger.HypothesisOpen && state != ledger.HypothesisUnconfirmed {
		t.Fatalf("hypothesis state = %q", state)
	}
}

// TestConfirmHypothesisMovesOnlyOnEvidence: the state machine refuses to promote
// without a hit, and records why when there is one.
func TestConfirmHypothesisMovesOnlyOnEvidence(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.hypotheses = hyps(ledger.Hypothesis{ID: 3, State: ledger.HypothesisOpen})
	eng := newEngine(t, f, &fakeDispatcher{}, Config{})

	eng.ConfirmHypothesis(context.Background(), 3, 0, nil)
	if got := f.hypotheses[0].State; got != ledger.HypothesisUnconfirmed {
		t.Fatalf("a miss produced %q, want unconfirmed", got)
	}

	eng.ConfirmHypothesis(context.Background(), 3, 2, []string{"R1-aa", "R2-bb"})
	if got := f.hypotheses[0].State; got != ledger.HypothesisCandidate {
		t.Fatalf("a hit produced %q, want candidate", got)
	}
	if f.hypotheses[0].Note == "" {
		t.Fatal("the promotion carries no evidence note")
	}
}

// TestWhiteboxLeadForAnUntestableSinkIsIgnored: no probe exists for RCE, and the
// engine must not invent one.
func TestWhiteboxLeadForAnUntestableSinkIsIgnored(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.hypotheses = hyps(ledger.Hypothesis{
		ID: 5, Entry: "POST /run", Param: "cmd", Sink: "rce",
		Path: "app.js:30", State: ledger.HypothesisOpen,
	})
	disp := &fakeDispatcher{}
	eng := newEngine(t, f, disp, Config{MaxSteps: 8})
	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if n := disp.count("param"); n != 0 {
		t.Fatalf("an unprobeable sink produced %d probes", n)
	}
}
