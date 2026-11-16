package planner

import (
	"strings"
	"testing"

	"youkai/internal/engine"
	"youkai/internal/ledger"
)

// TestPromptGivesTheModelTheBrainRole: the prompt must read like a planner brief,
// not a form to fill in.
func TestPromptGivesTheModelTheBrainRole(t *testing.T) {
	req := engine.ProposeRequest{
		Engagement: "lab",
		Graph: ledger.GraphView{
			Facts: []ledger.Fact{{ID: 1, Statement: "参数 q 反射进响应"}},
		},
		Allowed: []string{"scan", "param"},
		Tools: []engine.ToolInfo{
			{Name: "scan", Tier: 1}, {Name: "param", Tier: 2},
		},
	}
	got := buildPrompt(req, req.Allowed)
	if !strings.Contains(got, "规划大脑") {
		t.Fatalf("the prompt does not establish the role:\n%s", got)
	}
	if !strings.Contains(got, "档 2") || !strings.Contains(got, "停下") {
		t.Fatalf("the prompt does not state the tier boundary:\n%s", got)
	}
	if !strings.Contains(got, "param (tier 2)") {
		t.Fatalf("the prompt does not show per-tool tiers:\n%s", got)
	}
	if !strings.Contains(got, "参数 q 反射进响应") {
		t.Fatalf("the prompt dropped the evidence:\n%s", got)
	}
}

// TestPromptDoesNotCarryBodies: the request struct has no field for a response body,
// and the rendered prompt must not contain one either.
func TestPromptDoesNotCarryBodies(t *testing.T) {
	req := engine.ProposeRequest{
		Engagement: "lab",
		Graph: ledger.GraphView{
			Facts: []ledger.Fact{{ID: 1, Statement: "git 配置可读", Evidence: map[string]any{
				"request_id": "R0001-aa", "status": 200,
			}}},
		},
		Allowed: []string{"scan"},
	}
	got := buildPrompt(req, req.Allowed)
	for _, banned := range []string{"HTTP/1.1", "Content-Type:", "Set-Cookie", "Bearer "} {
		if strings.Contains(got, banned) {
			t.Fatalf("the prompt leaked %q:\n%s", banned, got)
		}
	}
	// The evidence pointer survives: that is what makes a proposal replayable.
	if !strings.Contains(got, "R0001-aa") {
		t.Fatalf("the prompt lost the evidence pointer:\n%s", got)
	}
}

// TestPromptShowsHypothesesAndIdentities: planning an authorisation check needs the
// identities; planning from code needs the leads.
func TestPromptShowsHypothesesAndIdentities(t *testing.T) {
	req := engine.ProposeRequest{
		Engagement: "lab",
		Allowed:    []string{"compare", "param"},
		Hypotheses: []ledger.Hypothesis{{
			Entry: "GET /search", Param: "q", Sink: "sqli", Path: "app.js:3",
		}},
		Pairs: []engine.AccessPair{{
			Owner: "alice", Viewer: "bob", URL: "/orders/1", Marker: "ORD-1",
		}},
	}
	got := buildPrompt(req, req.Allowed)
	if !strings.Contains(got, "白盒线索") || !strings.Contains(got, "sink=sqli") {
		t.Fatalf("hypotheses missing:\n%s", got)
	}
	if !strings.Contains(got, "alice") || !strings.Contains(got, "ORD-1") {
		t.Fatalf("identities missing:\n%s", got)
	}
	if !strings.Contains(got, "未证实") {
		t.Fatalf("the prompt does not say the leads are unconfirmed:\n%s", got)
	}
}
