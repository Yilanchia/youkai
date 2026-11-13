package planner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// completion is the strict output schema. Anything that does not fit is refused;
// extra keys are ignored, so a model cannot smuggle "approve" or "tier" through.
type completion struct {
	Intents []struct {
		Goal         string         `json:"goal"`
		Capability   string         `json:"capability"`
		Action       string         `json:"action"` // tolerated alias
		Args         map[string]any `json:"args"`
		Rationale    string         `json:"rationale"`
		ExpectedFact string         `json:"expected_fact"`
	} `json:"intents"`
}

// Rejection records a proposal that was refused, and why. It is archived so an
// injected or overreaching suggestion becomes evidence, not silence.
type Rejection struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

// parseCompletion turns model text into typed intents.
//
//  1. the text must contain one JSON object -> otherwise refuse everything
//  2. the capability must be on the read-only whitelist
//  3. it must classify as tier 1
//
// A proposal that fails 2 or 3 is DROPPED, not parked. Parking it would let
// attacker-controlled page text (via a poisoned fact) wedge the autonomous engine
// at needs_approval forever - a denial of service on the brain. Dropping keeps
// the guarantee that matters: an injected proposal cannot cause execution and
// cannot change the engine's control flow. The archive still records it.
func parseCompletion(text string, allowed []string) ([]ledger.IntentSpec, []Rejection, error) {
	body, err := extractJSON(text)
	if err != nil {
		return nil, nil, err
	}
	var c completion
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		return nil, nil, fmt.Errorf("completion is not the required schema: %w", err)
	}
	if len(c.Intents) == 0 {
		return nil, nil, fmt.Errorf("completion contains no intents")
	}
	allow := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allow[a] = true
	}

	var out []ledger.IntentSpec
	var rejected []Rejection
	seen := map[string]bool{}
	for _, in := range c.Intents {
		capability := strings.TrimSpace(in.Capability)
		if capability == "" {
			capability = strings.TrimSpace(in.Action)
		}
		if capability == "" {
			rejected = append(rejected, Rejection{Reason: "empty capability"})
			continue
		}
		if !allow[capability] {
			rejected = append(rejected, Rejection{
				Capability: capability,
				Reason:     "not on the read-only whitelist; the model may only propose read-only evidence gathering",
			})
			continue
		}
		dec := gate.Explain(capability, in.Args)
		if !dec.Tier.AutonomousOK() {
			rejected = append(rejected, Rejection{
				Capability: capability,
				Reason:     "classified " + dec.Tier.String() + ": the engine never runs tier>=2, and a model proposal cannot open that door",
			})
			continue
		}
		key := capability + "|" + ledger.CanonicalArgs(in.Args)
		if seen[key] {
			continue
		}
		seen[key] = true
		args := in.Args
		if args == nil {
			args = map[string]any{}
		}
		out = append(out, ledger.IntentSpec{
			Capability:   capability,
			Args:         args,
			Tier:         int(dec.Tier),
			Rationale:    strings.TrimSpace(in.Rationale),
			ExpectedFact: strings.TrimSpace(in.ExpectedFact),
			GateReason:   dec.Reason,
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
	depth, inString, escaped := 0, false, false
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

func env(key string) string { return os.Getenv(key) }
