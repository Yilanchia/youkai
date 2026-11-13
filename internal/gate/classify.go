// Package gate is youkai's capability wall.
//
// Every capability is classified before anything runs:
//
//	tier 1  read-only evidence gathering   -> the autonomous engine may run it
//	tier 2  proof-grade / write / active    -> the engine STOPS and a human decides
//	tier 3  automatic exploitation          -> does not exist in this build
//
// The classification fails closed: anything not on the list is tier 3. The engine
// asks this package at dispatch time (not at planning time), so a capability
// cannot talk its way past the wall by being mislabelled in an intent.
package gate

import (
	"fmt"
	"strings"
)

// Tier is a capability's capability class (yes, the pun is load-bearing).
type Tier int

const (
	// TierReadOnly may be executed unattended.
	TierReadOnly Tier = 1
	// TierProof needs a human: high-auth plus a single confirm, one step at a time.
	TierProof Tier = 2
	// TierDeep is automatic exploitation. Not in this repository.
	TierDeep Tier = 3
)

// String renders the tier for logs, reports, and the UI.
func (t Tier) String() string {
	switch t {
	case TierReadOnly:
		return "tier1:read-only"
	case TierProof:
		return "tier2:proof"
	case TierDeep:
		return "tier3:deep"
	default:
		return fmt.Sprintf("tier%d", int(t))
	}
}

// AutonomousOK reports whether the unattended engine may run this tier.
func (t Tier) AutonomousOK() bool { return t == TierReadOnly }

// NeedsHuman reports whether a human must authorise the action.
func (t Tier) NeedsHuman() bool { return t >= TierProof }

// Decision is a classification plus why.
type Decision struct {
	Capability string `json:"capability"`
	Tier       Tier   `json:"tier"`
	Reason     string `json:"reason"`
}

// Allowed is the short form.
func (d Decision) Allowed() bool { return d.Tier.AutonomousOK() }

// Explain classifies a capability and explains itself.
func Explain(capability string, args map[string]any) Decision {
	c := strings.TrimSpace(strings.ToLower(capability))
	if c == "" {
		return Decision{Capability: c, Tier: TierDeep, Reason: "empty capability name: failing closed"}
	}
	if d, handled := explainByArgs(c, args); handled {
		return d
	}
	if t, ok := table[c]; ok {
		return Decision{Capability: c, Tier: t, Reason: reasonFor(c, t)}
	}
	for prefix, t := range prefixTable {
		if strings.HasPrefix(c, prefix) {
			return Decision{Capability: c, Tier: t, Reason: reasonFor(c, t)}
		}
	}
	return Decision{
		Capability: c,
		Tier:       TierDeep,
		Reason:     "unknown capability: not on the allow-list, failing closed to tier3",
	}
}

// Classify is the terse form.
func Classify(capability string, args map[string]any) Tier { return Explain(capability, args).Tier }

// AutonomousOK answers the engine's single question.
func AutonomousOK(capability string, args map[string]any) bool {
	return Classify(capability, args).AutonomousOK()
}

// table is the explicit allow-list. Absence means tier 3.
var table = map[string]Tier{
	// ---- web: read-only evidence (module 3 tier 1) ----------------------
	"probe":        TierReadOnly,
	"scan":         TierReadOnly,
	"crawl":        TierReadOnly,
	"compare":      TierReadOnly,
	"role_matrix":  TierReadOnly,
	"reachability": TierReadOnly,
	"proof":        TierReadOnly,
	"fingerprint":  TierReadOnly,
	"browser":      TierReadOnly,
	"headers":      TierReadOnly,
	// Account layer: the read-only view of identities is tier 1; anything that
	// authenticates or writes on the target is tier 2.
	"accounts_show":  TierReadOnly,
	"cors":           TierReadOnly,
	"exposures":      TierReadOnly,
	"redirect_check": TierReadOnly,

	// ---- web: proof-grade (module 3 tier 2) -----------------------------
	"param":              TierProof,
	"param_adaptive":     TierProof,
	"waf":                TierProof,
	"login":              TierProof,
	"accounts_provision": TierProof,
	"accounts_seed":      TierProof,
	"accounts_register":  TierProof,
	"object_seed":        TierProof,

	// ---- binary: read-only static analysis (module 4 tier 1) ------------
	"artifact_identify": TierReadOnly,
	"artifact_register": TierReadOnly,
	"strings":           TierReadOnly,
	"checksec":          TierReadOnly,
	"symbols":           TierReadOnly,
	"disasm":            TierReadOnly,
	"decompile":         TierReadOnly,
	"mobile_unpack":     TierReadOnly,
	"firmware_extract":  TierReadOnly,
	"secrets":           TierReadOnly,
	"dataflow":          TierReadOnly,
	"sarif":             TierReadOnly,
	"doctor":            TierReadOnly,

	// ---- binary: proof-grade --------------------------------------------
	"pwn_template":  TierProof,
	"pwn_gdbscript": TierProof,
	"web_poc":       TierProof,
	"impact_proof":  TierProof,
	"frida_script":  TierProof,
	// Fetching attacker-controlled bytes onto disk is a human decision.
	"download": TierProof,
}

// prefixTable keeps whole families closed even if a new name appears.
var prefixTable = map[string]Tier{
	"pwn_":           TierProof,
	"impact_":        TierProof,
	"exploit_":       TierDeep,
	"shell_":         TierDeep,
	"lateral_":       TierDeep,
	"exfil_":         TierDeep,
	"persist_":       TierDeep,
	"youkai_exploit": TierDeep,
}

func reasonFor(c string, t Tier) string {
	switch t {
	case TierReadOnly:
		return "read-only capability: the autonomous engine may run it"
	case TierProof:
		return "proof-grade capability: the engine must stop; a human approves one step at a time"
	default:
		return "exploitation-class capability: never executed by youkai"
	}
}

// explainByArgs handles capabilities whose tier depends on how they are invoked.
func explainByArgs(c string, args map[string]any) (Decision, bool) {
	switch c {
	case "probe", "headers", "cors", "exposures", "redirect_check":
		m := strings.ToUpper(str(args, "method"))
		if m == "" {
			return Decision{Capability: c, Tier: TierReadOnly, Reason: "probe defaults to GET"}, true
		}
		switch m {
		case "GET", "HEAD", "OPTIONS":
			return Decision{Capability: c, Tier: TierReadOnly, Reason: "read-only HTTP method " + m}, true
		default:
			return Decision{
				Capability: c, Tier: TierProof,
				Reason: "write HTTP method " + m + ": the engine never sends write methods unattended",
			}, true
		}
	case "download":
		return Decision{
			Capability: c, Tier: TierProof,
			Reason: "downloading a sample puts attacker-controlled bytes on disk; a human approves it",
		}, true
	}
	return Decision{}, false
}

func str(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	if s, ok := args[key].(string); ok {
		return s
	}
	return ""
}

// ReadOnlyCapabilities lists every tier-1 capability, for the planner whitelist.
func ReadOnlyCapabilities() []string {
	out := make([]string, 0, len(table))
	for c, t := range table {
		if t == TierReadOnly {
			out = append(out, c)
		}
	}
	// Stable order so prompts and UI lists do not flicker.
	sortStrings(out)
	return out
}

// ProofCapabilities lists every tier-2 capability.
func ProofCapabilities() []string {
	out := make([]string, 0, len(table))
	for c, t := range table {
		if t == TierProof {
			out = append(out, c)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	// tiny insertion sort: the list is ~30 items and this avoids an import churn
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
