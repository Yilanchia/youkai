package planner

import (
	"strings"
	"testing"

	"youkai/internal/gate"
)

// TestPlanCardCarriesReasoningAndStops: the card the operator sees describes the
// thought (reasoning), the order (after) and where it will stop (stops_at).
func TestPlanCardCarriesReasoningAndStops(t *testing.T) {
	raw := `{"reply":"我有想法","cards":[{
	  "type":"plan",
	  "reasoning":"看到 /orders 的代码入口 + 两个已声明身份,所以先各登录一次再比对",
	  "steps":[
	    {"capability":"scan","args":{"url":"https://example.com"},"why":"先铺面"},
	    {"capability":"compare","args":{"url":"https://example.com/orders/1"},"why":"再看越权","after":[0]}
	  ]
	}]}`
	reply, rejected, err := parseChat(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rejected) != 0 {
		t.Fatalf("rejected: %v", rejected)
	}
	card := reply.Cards[0]
	if !strings.Contains(card.Reasoning, "两个已声明身份") {
		t.Fatalf("reasoning lost: %q", card.Reasoning)
	}
	if len(card.Steps) != 2 || len(card.Steps[1].After) != 1 || card.Steps[1].After[0] != 0 {
		t.Fatalf("dependency lost: %+v", card.Steps)
	}
	// stops_at is derived from the gate, not from the model.
	wantStops := 0
	for _, st := range card.Steps {
		if !gate.Classify(st.Capability, st.Args).AutonomousOK() {
			wantStops++
		}
	}
	if len(card.StopsAt) != wantStops {
		t.Fatalf("stops_at = %v, want %d entries", card.StopsAt, wantStops)
	}
}

// TestPlanDependencyMustPointBackwards: a forward or dangling index would make a
// cycle the engine can never satisfy.
func TestPlanDependencyMustPointBackwards(t *testing.T) {
	raw := `{"reply":"x","cards":[{"type":"plan","steps":[
	  {"capability":"scan","args":{"url":"https://e.com"},"after":[1]},
	  {"capability":"compare","args":{"url":"https://e.com/o/1"},"after":[5]}
	]}]}`
	reply, rejected, err := parseChat(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rejected) < 2 {
		t.Fatalf("bad dependency indices were accepted: %+v (rejected=%v)", reply.Cards, rejected)
	}
	for _, st := range reply.Cards[0].Steps {
		for _, a := range st.After {
			if a < 0 || a >= len(reply.Cards[0].Steps) {
				t.Fatalf("an out-of-range dependency survived: %v", st.After)
			}
		}
	}
}

// TestPlanStillCannotSmuggleTierTwo: the v0.11 red line still holds after the
// schema grew.
func TestPlanStillCannotSmuggleTierTwo(t *testing.T) {
	raw := `{"reply":"x","cards":[{"type":"plan","steps":[
	  {"capability":"param","args":{"url":"https://e.com/?q=1"}}
	]}]}`
	reply, rejected, err := parseChat(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(reply.Cards) != 0 {
		t.Fatalf("a tier-2 capability slipped into a plan: %+v", reply.Cards)
	}
	if len(rejected) == 0 {
		t.Fatal("the rejection was not reported")
	}
}
