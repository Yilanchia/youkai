// Package gate is youkai's load-bearing wall.
//
// Every action the brain wants to take is classified into a tier before any
// worker touches a hand:
//
//	tier 1  read-only evidence gathering  -> the autonomous loop may execute it
//	tier 2  proof-grade / write / active  -> the loop STOPS and hands it to a human
//	tier 3  automatic exploitation        -> does not exist in the OSS build, and
//	                                         the loop refuses it regardless
//
// The classification is data-driven and fails closed: anything not in the table
// is tier 3. Youkai never sends a target request itself (Fairy does that, and
// re-checks its own scope), but this wall is what keeps the loop from *asking*
// Fairy for the wrong thing.
package gate

import (
	"fmt"
	"strings"
)

// Tier is an action's capability class.
type Tier int

const (
	// TierReadOnly is read-only evidence gathering: probes, comparisons,
	// browsing, local ledger bookkeeping, static binary analysis.
	TierReadOnly Tier = 1
	// TierProof is proof-grade activity: active parameter probes, logins,
	// account seeding, write methods, exploit-text generation. Human-gated.
	TierProof Tier = 2
	// TierDeep is automatic exploitation (shells, lateral movement, exfil).
	// Not in this repository; the loop never executes it either way.
	TierDeep Tier = 3
)

// String renders the tier for logs and the human hand-off.
func (t Tier) String() string {
	switch t {
	case TierReadOnly:
		return "tier1:read-only"
	case TierProof:
		return "tier2:proof"
	case TierDeep:
		return "tier3:deep"
	default:
		return fmt.Sprintf("tier%d:unknown", int(t))
	}
}

// AutonomousOK reports whether the unattended loop is allowed to execute an
// action of this tier. Exactly one tier qualifies. This is checked by the gate
// itself, by the loop before dispatch, and by the worker before calling a hand:
// three independent chances to be wrong in the safe direction.
func (t Tier) AutonomousOK() bool { return t == TierReadOnly }

// NeedsHuman reports whether a human must authorise the action.
func (t Tier) NeedsHuman() bool { return t >= TierProof }

// Decision is a classification with the reason it chose that tier, so the
// human hand-off can say *why* the loop stopped.
type Decision struct {
	Action string `json:"action"`
	Tier   Tier   `json:"tier"`
	Reason string `json:"reason"`
}

// Allowed is the short form used in conditionals.
func (d Decision) Allowed() bool { return d.Tier.AutonomousOK() }

// Explain classifies an action and explains itself.
func Explain(action string, args map[string]any) Decision {
	action = canonical(strings.TrimSpace(action))
	if action == "" {
		return Decision{Action: action, Tier: TierDeep, Reason: "empty action name: failing closed"}
	}

	// Argument-sensitive rules come first: the same tool can be read-only or a
	// write depending on how it is called.
	if d, handled := explainByArgs(action, args); handled {
		return d
	}

	if t, ok := table[action]; ok {
		return Decision{Action: action, Tier: t, Reason: reasonFor(action, t)}
	}
	for prefix, t := range prefixTable {
		if strings.HasPrefix(action, prefix) {
			return Decision{Action: action, Tier: t, Reason: reasonFor(action, t)}
		}
	}
	return Decision{
		Action: action,
		Tier:   TierDeep,
		Reason: "unknown action: not on the allow-list, failing closed to tier3",
	}
}

// Classify is the terse form required by the design doc.
func Classify(action string, args map[string]any) Tier { return Explain(action, args).Tier }

// AutonomousOK is the loop's single question.
func AutonomousOK(action string, args map[string]any) bool {
	return Classify(action, args).AutonomousOK()
}

// aliases exist because the design doc and the hands use slightly different
// spellings. youkai records the canonical (real) tool name, and accepts the
// documented alias when planning.
var aliases = map[string]string{
	"fairy_probe":   "web_probe",
	"fairy_scan":    "web_scan",
	"fairy_compare": "web_compare",
}

func canonical(action string) string {
	if c, ok := aliases[action]; ok {
		return c
	}
	return action
}

// table is the explicit allow-list. Absence from this table means tier 3.
var table = map[string]Tier{
	// ---- Fairy: local bookkeeping / read-only inspection ----------------
	"fairy_scope_show":         TierReadOnly,
	"fairy_ledger_show":        TierReadOnly,
	"fairy_ledger_add":         TierReadOnly, // writes the local ledger, no target traffic
	"fairy_ledger_ingest":      TierReadOnly,
	"fairy_memory_show":        TierReadOnly,
	"fairy_disclose":           TierReadOnly,
	"fairy_report_bundle":      TierReadOnly,
	"fairy_chain_plan":         TierReadOnly, // produces a plan, sends nothing
	"fairy_planner_tick":       TierReadOnly, // reads the ledger, may materialise intents
	"fairy_chain_materialize":  TierReadOnly,
	"fairy_ingest":             TierReadOnly, // normalises results already in hand
	"fairy_accounts_show":      TierReadOnly,
	"fairy_mission":            TierReadOnly, // no login, no active probes by default
	"fairy_proof":              TierReadOnly, // one DOM context judgement
	"har_ingest":               TierReadOnly,
	"fairy_handoff":            TierReadOnly, // register-only unless url+confirm (see byArgs)
	"fairy_scope_init":         TierProof,    // declaring authorisation is a human act
	"fairy_ledger_init":        TierProof,
	"fairy_auto_run":           TierProof, // handing control to another automaton
	"fairy_accounts_provision": TierProof,
	"fairy_accounts_register":  TierProof,
	"fairy_accounts_seed":      TierProof,

	// ---- Fairy: read-only web traffic -----------------------------------
	"web_probe":          TierReadOnly, // GET/HEAD/OPTIONS only; write methods are byArgs tier 2
	"web_scan":           TierReadOnly,
	"web_browser":        TierReadOnly, // no credential use, no write-method intent
	"web_compare":        TierReadOnly,
	"web_role_matrix":    TierReadOnly,
	"web_reachability":   TierReadOnly,
	"fairy_reachability": TierReadOnly,
	"web_crawl":          TierReadOnly,
	"web_dom_context":    TierReadOnly,
	"web_report":         TierReadOnly,
	"web_session":        TierReadOnly, // list/show; create/delete is byArgs tier 2
	"web_replay":         TierReadOnly, // GET/HEAD replay; allow_write is byArgs tier 2

	// ---- Fairy: proof-grade ---------------------------------------------
	"web_param":          TierProof,
	"web_param_adaptive": TierProof,
	"web_waf":            TierProof,
	"web_login":          TierProof,

	// ---- Verdex: read-only static analysis ------------------------------
	"assets":           TierReadOnly,
	"map":              TierReadOnly,
	"scan":             TierReadOnly,
	"osint":            TierReadOnly,
	"report":           TierReadOnly,
	"diff":             TierReadOnly,
	"explain":          TierReadOnly,
	"bin_dossier":      TierReadOnly,
	"bin_info":         TierReadOnly,
	"bin_symbols":      TierReadOnly,
	"bin_strings":      TierReadOnly,
	"bin_disasm":       TierReadOnly,
	"bin_decompile":    TierReadOnly,
	"reconstruct":      TierReadOnly,
	"har_analyze":      TierReadOnly,
	"web_recon":        TierReadOnly,
	"dex_decompile":    TierReadOnly,
	"wxapkg_unpack":    TierReadOnly,
	"mobile_unpack":    TierReadOnly,
	"secrets":          TierReadOnly,
	"fw_extract":       TierReadOnly,
	"fw_scan":          TierReadOnly,
	"js_deobfuscate":   TierReadOnly,
	"dotnet_decompile": TierReadOnly,
	"asar_unpack":      TierReadOnly,
	"analyze_target":   TierReadOnly,

	// ---- Verdex: produces executable text / proof -----------------------
	"pwn_template":  TierProof,
	"pwn_gdbscript": TierProof,
	"pwn_checksec":  TierProof,
	"pwn_gadgets":   TierProof,
	"pwn_cyclic":    TierProof,
	"pwn_libc":      TierProof,
	"web_poc":       TierProof,
	"impact_proof":  TierProof,
	"frida_script":  TierProof,
}

// prefixTable catches whole families (and keeps the wall closed for anything new
// that borrows a known dangerous prefix).
var prefixTable = map[string]Tier{
	"pwn_":          TierProof,
	"impact_":       TierProof,
	"exploit_":      TierDeep,
	"shell_":        TierDeep,
	"lateral_":      TierDeep,
	"exfil_":        TierDeep,
	"fairy_exploit": TierDeep,
}

func reasonFor(action string, t Tier) string {
	switch t {
	case TierReadOnly:
		return "read-only action: the autonomous loop may execute it"
	case TierProof:
		return "proof-grade action: the loop must stop and hand this to a human (Fairy high-auth + single confirm)"
	default:
		return "exploitation-class action: never executed by youkai"
	}
}

// explainByArgs handles the tools whose tier depends on how they are invoked.
// Returning handled=false falls through to the static table.
func explainByArgs(action string, args map[string]any) (Decision, bool) {
	switch action {
	case "web_probe":
		m := strings.ToUpper(str(args, "method"))
		if m == "" {
			return Decision{Action: action, Tier: TierReadOnly, Reason: "probe defaults to GET"}, true
		}
		switch m {
		case "GET", "HEAD", "OPTIONS":
			return Decision{Action: action, Tier: TierReadOnly, Reason: "read-only HTTP method " + m}, true
		default:
			return Decision{
				Action: action, Tier: TierProof,
				Reason: "write HTTP method " + m + ": the loop never sends write methods unattended",
			}, true
		}

	case "web_replay":
		if b, ok := args["allow_write"]; ok {
			if v, isBool := b.(bool); isBool && v {
				return Decision{Action: action, Tier: TierProof, Reason: "replay with allow_write=true re-issues write methods"}, true
			}
		}
		return Decision{Action: action, Tier: TierReadOnly, Reason: "replay without allow_write"}, true

	case "web_session":
		switch strings.ToLower(str(args, "action")) {
		case "", "list", "show":
			return Decision{Action: action, Tier: TierReadOnly, Reason: "session " + str(args, "action") + " is a local read"}, true
		default:
			return Decision{Action: action, Tier: TierProof, Reason: "session " + str(args, "action") + " writes credential state"}, true
		}

	case "fairy_handoff":
		// Downloading a sample is a human decision: youkai never pulls binaries.
		if strings.TrimSpace(str(args, "url")) != "" && truthy(args["confirm"]) {
			return Decision{Action: action, Tier: TierProof, Reason: "handoff confirm=true downloads a sample; youkai does not pull"}, true
		}
		return Decision{Action: action, Tier: TierReadOnly, Reason: "handoff without confirm: registration only"}, true

	case "fairy_ledger_advance":
		switch strings.ToLower(str(args, "action")) {
		case "approve":
			return Decision{Action: action, Tier: TierDeep, Reason: "approving an intent is forbidden to youkai, in every tier"}, true
		case "finding-status":
			switch strings.ToLower(str(args, "status")) {
			case "verified":
				return Decision{
					Action: action, Tier: TierProof,
					Reason: "candidate->verified is an operator judgement, never automatic",
				}, true
			}
		}
		return Decision{Action: action, Tier: TierReadOnly, Reason: "ledger bookkeeping (claim/done/blocked/skipped)"}, true

	case "fairy_worker_run", "fairy_auto_run":
		inner := strings.TrimSpace(str(args, "action"))
		if inner == "" {
			return Decision{
				Action: action, Tier: TierDeep,
				Reason: "handing an unspecified action to the hand: failing closed",
			}, true
		}
		// The tier of the wrapper is the tier of what it runs.
		d := Explain(inner, args)
		return Decision{
			Action: action,
			Tier:   d.Tier,
			Reason: "wrapper for " + inner + ": " + d.Reason,
		}, true
	}
	return Decision{}, false
}

func str(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}
