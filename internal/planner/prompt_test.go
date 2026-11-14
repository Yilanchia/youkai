package planner

import (
	"strings"
	"testing"

	"youkai/internal/engine"
	"youkai/internal/ledger"
)

// TestPromptCarriesPriorWork: the model must see what already ran, otherwise it
// spends its budget re-proposing the same check.
func TestPromptCarriesPriorWork(t *testing.T) {
	req := engine.ProposeRequest{
		Engagement: "lab",
		PriorWork: []ledger.TraceHit{
			{Capability: "probe", Target: "127.0.0.1:18080/.git/config",
				Summary: "capability=probe ok=true tier=1 facts=1 findings=1", Status: "done"},
			{Capability: "scan", Target: "127.0.0.1:18080/search",
				Summary: "capability=scan ok=true tier=1 facts=9 findings=7", Status: "done"},
		},
	}
	prompt := buildPrompt(req, []string{"probe", "scan"})
	if !strings.Contains(prompt, "已执行过的步骤") {
		t.Fatal("prompt has no prior-work section")
	}
	for _, want := range []string{"probe 127.0.0.1:18080/.git/config", "scan 127.0.0.1:18080/search", "facts=9"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prior-work section is missing %q:\n%s", want, prompt)
		}
	}
	// The instruction must say "do not repeat", not merely list the work.
	if !strings.Contains(prompt, "不要重复") {
		t.Fatalf("prior-work section does not tell the model not to repeat:\n%s", prompt)
	}
}

func TestPromptWithoutPriorWorkHasNoSection(t *testing.T) {
	prompt := buildPrompt(engine.ProposeRequest{Engagement: "lab"}, []string{"probe"})
	if strings.Contains(prompt, "已执行过的步骤") {
		t.Fatal("an empty trail still rendered a section")
	}
}

// TestPromptIsBoundedAndOrdered keeps a long trail from eating the whole budget and
// keeps the newest entries.
func TestPromptIsBoundedAndOrdered(t *testing.T) {
	var prior []ledger.TraceHit
	for i := 0; i < 80; i++ {
		prior = append(prior, ledger.TraceHit{
			Capability: "probe", Target: "h/x", Summary: "capability=probe ok=true",
		})
	}
	prior[len(prior)-1].Target = "newest/endpoint"
	prompt := buildPrompt(engine.ProposeRequest{Engagement: "lab", PriorWork: prior}, []string{"probe"})
	if got := strings.Count(prompt, "- probe "); got > 40 {
		t.Fatalf("prompt lists %d prior steps, want <= 40", got)
	}
	if !strings.Contains(prompt, "newest/endpoint") {
		t.Fatal("the bounded section dropped the newest entry")
	}
}
