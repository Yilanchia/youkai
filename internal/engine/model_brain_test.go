package engine

import (
	"context"
	"strings"
	"testing"

	"youkai/internal/ledger"
)

// recordingProposer proposes exactly what the test tells it to, and remembers the
// request so the test can assert what the model was allowed to see.
type recordingProposer struct {
	specs   []ledger.IntentSpec
	got     ProposeRequest
	calls   int
	failErr error
}

func (r *recordingProposer) Propose(_ context.Context, req ProposeRequest) ([]ledger.IntentSpec, error) {
	r.calls++
	r.got = req
	if r.failErr != nil {
		return nil, r.failErr
	}
	return r.specs, nil
}

// TestModelPlansBeforeRules is ADR-007 in one test: the proposer is asked first,
// its intents are what the run executes, and the rule table is a fallback.
func TestModelPlansBeforeRules(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.assets = []ledger.Asset{{ID: 1, Kind: "surface", Value: "http://127.0.0.1"}}
	p := &recordingProposer{specs: []ledger.IntentSpec{{
		Capability: "headers",
		Args:       map[string]any{"url": "http://127.0.0.1/from-the-model"},
		Rationale:  "模型认为该先看响应头",
		Provenance: "planner:call-1",
	}}}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 2, Proposer: p})
	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.calls == 0 {
		t.Fatal("the model was never asked to plan")
	}
	var fromModel bool
	for _, it := range f.intents {
		if it.Args["url"] == "http://127.0.0.1/from-the-model" {
			fromModel = true
			if !it.Inferred {
				t.Fatalf("a model-proposed intent is not marked inferred: %+v", it)
			}
		}
	}
	if !fromModel {
		t.Fatalf("the model's proposal never became work: %+v", f.intents)
	}
}

// TestModelProposalStillPassesTheGate: the model cannot make tier-2 work run itself.
func TestModelProposalStillPassesTheGate(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	p := &recordingProposer{specs: []ledger.IntentSpec{{
		Capability: "param",
		Args:       map[string]any{"url": "http://127.0.0.1/sql?q=1", "param": "q"},
		Rationale:  "模型想探一下这个参数",
		Provenance: "planner:call-2",
		// The model would love to declare this autonomous:
		Tier: 1, RequiresApproval: false,
	}}}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 2, Proposer: p})
	rep, err := eng.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Stop != StopNeedsApproval {
		t.Fatalf("stop = %q, want needs_approval", rep.Stop)
	}
	for _, it := range f.intents {
		if it.Capability == "param" {
			if it.Tier != 2 {
				t.Fatalf("the gate did not re-classify the model's intent: tier=%d", it.Tier)
			}
			if it.Status != ledger.StatusNeedsApproval {
				t.Fatalf("a tier-2 proposal ran without approval: %+v", it)
			}
		}
	}
}

// TestRulesStillRunWithoutAModel: no model, no stall.
func TestRulesStillRunWithoutAModel(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 3})
	rep, err := eng.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rep.Steps) == 0 {
		t.Fatalf("without a model the rule fallback produced no work: %+v", rep)
	}
}

// TestBrokenModelFallsBackToRules: a model that errors must not stop the platform.
func TestBrokenModelFallsBackToRules(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	p := &recordingProposer{failErr: context.DeadlineExceeded}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{MaxSteps: 3, Proposer: p})
	rep, err := eng.Run(context.Background(), 1)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rep.Steps) == 0 {
		t.Fatalf("a broken model stalled the run: %+v", rep)
	}
	if !strings.Contains(eng.lastPlanNote, "模型不可用") {
		t.Fatalf("the fallback was not recorded: %q", eng.lastPlanNote)
	}
}

// TestModelSeesTheFullSanitisedPicture: the request carries hypotheses, identities
// and per-tool tiers - and no response body field exists to carry.
func TestModelSeesTheFullSanitisedPicture(t *testing.T) {
	f := mustStore(t, scopeJSON(t, "127.0.0.1"))
	f.hypotheses = []ledger.Hypothesis{{
		ID: 1, Entry: "GET /search", Param: "q", Sink: "sqli", Path: "app.js:3",
		State: ledger.HypothesisOpen,
	}}
	p := &recordingProposer{}
	eng := newEngine(t, f, &fakeDispatcher{}, Config{
		MaxSteps: 2, Proposer: p,
		PairSource:   fakePairs{pairs: []AccessPair{{Owner: "alice", Viewer: "bob", URL: "/orders/1", Marker: "ORD-1"}}},
		AllowedTools: []string{"scan", "param"},
	})
	if _, err := eng.Run(context.Background(), 1); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(p.got.Hypotheses) == 0 {
		t.Fatalf("the model never saw the whitebox leads")
	}
	if len(p.got.Pairs) == 0 {
		t.Fatalf("the model never saw the identities")
	}
	var sawTier2 bool
	for _, tool := range p.got.Tools {
		if tool.Name == "param" && tool.Tier == 2 {
			sawTier2 = true
		}
	}
	if !sawTier2 {
		t.Fatalf("tools are not labelled with their tier: %+v", p.got.Tools)
	}
}
