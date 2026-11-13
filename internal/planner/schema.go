package planner

import (
	"encoding/json"
	"fmt"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/loop"
)

// completion is the strict output schema. Anything that does not fit is refused;
// extra keys are ignored, so a model cannot smuggle "approve" or "tier" through.
type completion struct {
	Intents []struct {
		Goal         string         `json:"goal"`
		Action       string         `json:"action"`
		Args         map[string]any `json:"args"`
		Rationale    string         `json:"rationale"`
		ExpectedFact string         `json:"expected_fact"`
	} `json:"intents"`
}

// Rejection records a proposal that was refused, and why. It goes into the
// archive so an injected or overreaching suggestion is evidence, not silence.
type Rejection struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// parseCompletion turns model text into typed intents.
//
// Rules, in order:
//  1. the text must contain exactly one JSON object -> otherwise refuse everything
//  2. the action must be on the read-only whitelist
//  3. the action must classify as tier 1
//  4. rationales are encouraged but presence is not required for read-only work
//
// A proposal that fails 2 or 3 is DROPPED, not parked. Parking it would let
// attacker-controlled page text (via a poisoned fact) wedge the autonomous loop
// at needs_approval forever - a denial of service on the brain. Dropping keeps
// the guarantee that matters: an injected proposal cannot cause execution, and
// cannot change the loop's control flow. The archive still records it.
func parseCompletion(text string, allowed []string) ([]loop.IntentSpec, []Rejection, error) {
	body, err := extractJSON(text)
	if err != nil {
		return nil, nil, err
	}
	var c completion
	dec := json.NewDecoder(strings.NewReader(body))
	if err := dec.Decode(&c); err != nil {
		return nil, nil, fmt.Errorf("completion is not the required schema: %w", err)
	}
	if len(c.Intents) == 0 {
		return nil, nil, fmt.Errorf("completion contains no intents")
	}

	allow := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allow[a] = true
	}

	var out []loop.IntentSpec
	var rejected []Rejection
	seen := map[string]bool{}
	for _, in := range c.Intents {
		action := strings.TrimSpace(in.Action)
		if action == "" {
			rejected = append(rejected, Rejection{Action: action, Reason: "empty action"})
			continue
		}
		if !allow[action] {
			rejected = append(rejected, Rejection{
				Action: action,
				Reason: "not on the read-only whitelist; the model may only propose read-only evidence gathering",
			})
			continue
		}
		if tier := gate.Classify(action, in.Args); !tier.AutonomousOK() {
			rejected = append(rejected, Rejection{
				Action: action,
				Reason: "classified " + tier.String() + "; the loop never executes tier>=2, and a model proposal cannot open that door",
			})
			continue
		}
		key := action + "|" + canonicalArgs(in.Args)
		if seen[key] {
			continue
		}
		seen[key] = true

		args := in.Args
		if args == nil {
			args = map[string]any{}
		}
		out = append(out, loop.IntentSpec{
			Goal:         strings.TrimSpace(in.Goal),
			Action:       action,
			Args:         args,
			Rationale:    strings.TrimSpace(in.Rationale),
			ExpectedFact: strings.TrimSpace(in.ExpectedFact),
			Inferred:     true,
		})
	}
	if len(out) == 0 {
		return nil, rejected, fmt.Errorf("no acceptable intent (all %d proposal(s) were rejected)", len(rejected))
	}
	return out, rejected, nil
}

// extractJSON pulls the first balanced JSON object out of model output, tolerating
// markdown fences and prose.
func extractJSON(text string) (string, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return "", fmt.Errorf("empty completion")
	}
	// Strip a fenced block if present.
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		rest = strings.TrimPrefix(rest, "json")
		rest = strings.TrimPrefix(rest, "JSON")
		if j := strings.Index(rest, "```"); j >= 0 {
			rest = rest[:j]
		}
		s = strings.TrimSpace(rest)
	}
	start := strings.Index(s, "{")
	if start < 0 {
		return "", fmt.Errorf("completion contains no JSON object")
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("completion JSON object is not balanced")
}

func canonicalArgs(args map[string]any) string {
	if len(args) == 0 {
		return "{}"
	}
	b, err := json.Marshal(args)
	if err != nil {
		return fmt.Sprint(args)
	}
	return string(b)
}
