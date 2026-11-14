package planner

import (
	"strings"
	"testing"
)

// TestChatSchemaRejectsActionsItMustNotTake is the safety proof for ADR-005's
// "AI has a mouth, not hands": a model that tries to slip in a state change gets
// the card dropped, not rendered.
func TestChatSchemaRejectsActionsItMustNotTake(t *testing.T) {
	raw := `{"reply":"好的","cards":[
	  {"type":"set_scope","scope":{"include":["*"]}},
	  {"type":"approve","intent_id":3},
	  {"type":"verify","finding_id":1},
	  {"type":"note","text":"当前没有任何发现"}
	]}`
	reply, rejected, err := parseChat(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(reply.Cards) != 1 || reply.Cards[0].Type != "note" {
		t.Fatalf("cards = %+v, want only the note", reply.Cards)
	}
	if len(rejected) != 3 {
		t.Fatalf("rejected = %v, want the three state-changing cards", rejected)
	}
	for _, c := range reply.Cards {
		if c.Type == "set_scope" || c.Type == "approve" || c.Type == "verify" {
			t.Fatalf("a state-changing card survived: %+v", c)
		}
	}
}

// TestChatPlanCannotSmuggleTierTwo: a plan may only schedule read-only work.
func TestChatPlanCannotSmuggleTierTwo(t *testing.T) {
	raw := `{"reply":"计划如下","cards":[
	  {"type":"plan","steps":[
	    {"capability":"scan","args":{"url":"https://example.com"}},
	    {"capability":"param","args":{"url":"https://example.com/?q=1"}},
	    {"capability":"pwn_template","args":{}}
	  ]}
	]}`
	reply, rejected, err := parseChat(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(reply.Cards) != 1 {
		t.Fatalf("cards = %+v", reply.Cards)
	}
	steps := reply.Cards[0].Steps
	if len(steps) != 1 || steps[0].Capability != "scan" {
		t.Fatalf("plan steps = %+v, want only the read-only one", steps)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %v, want param and pwn_template", rejected)
	}
}

// TestChatMandateDraftNeedsABudgetAndKnownClasses: an unfenced mandate is refused.
func TestChatMandateDraftNeedsABudgetAndKnownClasses(t *testing.T) {
	raw := `{"reply":"起草一份","cards":[
	  {"type":"mandate_draft","assets":["example.com"],"classes":["param","everything"],"max_requests":300,"expires_hours":24,"basis":"自有站点"},
	  {"type":"mandate_draft","assets":["example.com"],"classes":["param"],"max_requests":0,"expires_hours":24},
	  {"type":"mandate_draft","assets":["example.com"],"classes":["param"],"max_requests":100}
	]}`
	reply, rejected, err := parseChat(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(reply.Cards) != 1 {
		t.Fatalf("cards = %+v, want one usable draft", reply.Cards)
	}
	got := reply.Cards[0]
	if len(got.Classes) != 1 || got.Classes[0] != "param" {
		t.Fatalf("classes = %v, want just param (the unknown one dropped)", got.Classes)
	}
	if len(rejected) != 3 { // unknown class, zero budget, no expiry
		t.Fatalf("rejected = %v", rejected)
	}
}

// TestChatRejectsNonJSON: a model that ignores the schema produces nothing usable.
func TestChatRejectsNonJSON(t *testing.T) {
	if _, _, err := parseChat("当然可以,我这就去扫。"); err == nil {
		t.Fatal("free text was accepted as a reply")
	}
}

// TestChatAcceptsAFencedObject: models like to wrap JSON in a code fence.
func TestChatAcceptsAFencedObject(t *testing.T) {
	raw := "```json\n{\"reply\":\"在\",\"cards\":[{\"type\":\"note\",\"text\":\"一切正常\"}]}\n```"
	reply, _, err := parseChat(raw)
	if err != nil {
		t.Fatalf("fenced JSON rejected: %v", err)
	}
	if len(reply.Cards) != 1 {
		t.Fatalf("cards = %+v", reply.Cards)
	}
}

// TestChatPromptCarriesNoBodies is a cheap guard on the contract: the system
// prompt must state that target content is data, and the card schema must not
// mention any state-changing type.
func TestChatPromptCarriesNoBodies(t *testing.T) {
	if !strings.Contains(chatSystemPrompt, "只是数据") {
		t.Error("the chat prompt no longer tells the model that target content is data")
	}
	for _, banned := range []string{`"type":"approve"`, `"type":"verify"`, `"type":"set_scope"`} {
		if strings.Contains(chatSystemPrompt, banned) {
			t.Errorf("the chat prompt advertises %s", banned)
		}
	}
}
