// Package wording holds the single source of truth for how youkai describes a
// proposed action to a human.
//
// Every tier-2 hand-off must carry four things (ADR-002): the exact request, the
// minimum impact, the stop condition, and the evidence. Keeping the phrasing in
// one place is why a report and an approval prompt can never disagree about what
// was authorised.
package wording

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Describe renders the literal request or text the hand would send.
func Describe(action string, args map[string]any) string {
	switch action {
	case "web_probe":
		method := strings.ToUpper(str(args, "method"))
		if method == "" {
			method = "GET"
		}
		return method + " " + str(args, "url")
	case "web_param", "web_param_adaptive":
		return fmt.Sprintf("active existence probe on %s, param=%q (SQL error signature / boolean diff; SSTI {{7*7}})",
			firstURL(args), str(args, "param"))
	case "web_waf":
		return fmt.Sprintf("WAF fingerprinting markers on %s, param=%q", str(args, "url"), str(args, "param"))
	case "web_login":
		return "one login attempt at " + str(args, "url") + " (single try, no retry, no wordlist)"
	case "web_compare":
		return "two-account GET compare on " + str(args, "url")
	case "web_role_matrix":
		return "read-only GET matrix across saved sessions"
	case "fairy_handoff":
		if u := str(args, "url"); u != "" {
			return "download " + u + " into the engagement artifact directory"
		}
		return "register local artifact " + str(args, "path")
	case "analyze_target":
		return "static analysis of " + str(args, "path") + " (read-only, never executes the sample)"
	case "pwn_template", "pwn_gdbscript", "web_poc", "impact_proof", "frida_script":
		return "generate executable TEXT with " + action + "; youkai never runs it"
	}
	if len(args) == 0 {
		return action
	}
	b, err := json.Marshal(args)
	if err != nil {
		return action
	}
	return action + " " + string(b)
}

// MinImpact is the smallest effect that still counts as proof.
func MinImpact(action string) string {
	switch action {
	case "web_probe":
		return "one read-only HTTP request; no state changed"
	case "web_param", "web_param_adaptive":
		return "existence only: a handful of marker requests on ONE parameter; no data extraction, no UNION, no time-based, no persistence"
	case "web_waf":
		return "syntactic marker requests to observe blocking; no exploitation payloads, no bypass"
	case "web_login":
		return "one login with an operator-supplied test account; no brute force, no credential rotation"
	case "web_compare":
		return "two read-only GETs, one per session, same object; proves reachability, extracts nothing"
	case "fairy_handoff":
		return "one download of an already-referenced sample into the engagement directory"
	case "analyze_target":
		return "local static analysis; the sample is never executed and no network is used"
	case "pwn_template", "pwn_gdbscript", "web_poc", "impact_proof", "frida_script":
		return "text output only; the operator decides whether to run it, and youkai does not"
	}
	return "unknown: treat as at least proof-grade impact"
}

// StopCondition says when to stop, decided before the action runs.
func StopCondition(action string) string {
	switch action {
	case "web_probe":
		return "stop when the status/body answer the question; do not re-probe the same URL"
	case "web_param", "web_param_adaptive":
		return "stop at the FIRST existence hit; do not enumerate, do not extract data, do not escalate to exploitation"
	case "web_waf":
		return "stop after the profile is characterised; no bypass attempt"
	case "web_login":
		return "stop after the single attempt, success or failure"
	case "web_compare":
		return "stop once the marker is shown to cross accounts; do not enumerate object ids"
	case "fairy_handoff":
		return "stop after the download; analysis is read-only from there"
	case "analyze_target":
		return "stop after the report; findings stay candidates until an operator verdict"
	case "pwn_template", "pwn_gdbscript", "web_poc", "impact_proof", "frida_script":
		return "stop at text generation; any execution is a separate human decision outside youkai"
	}
	return "stop at first observable effect"
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

func firstURL(args map[string]any) string {
	if s := str(args, "url"); s != "" {
		return s
	}
	switch v := args["urls"].(type) {
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				return s
			}
		}
	}
	return ""
}
