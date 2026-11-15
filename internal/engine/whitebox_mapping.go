package engine

import (
	"strings"

	"youkai/internal/ledger"
)

// probeForHypothesis maps a lead to the capability that can settle it.
//
// Every sink the whitebox package can name now has a probe EXCEPT deserialisation:
// an unsafe deserialiser has no safe existence check, so that lead is handed to a
// human instead of being "tested" with a gadget.
func probeForHypothesis(h ledger.Hypothesis) (capability string, args map[string]any, ok bool) {
	if strings.TrimSpace(h.Entry) == "" {
		return "", nil, false
	}
	switch h.Sink {
	case "redirect":
		return "redirect_check", map[string]any{"hypothesis_id": h.ID}, true
	case "deserialize":
		// No safe existence probe. Sending a serialized gadget to observe the
		// reaction is exploitation, not detection.
		return "", nil, false
	case "html-output":
		// A reflected-output lead has no probe in this build; keep it as a note.
		return "", nil, false
	}
	probeClass, known := map[string]string{
		"sql-concat": "sqli",
		"ssti":       "ssti",
		"ssrf":       "ssrf",
		"path":       "path",
		"rce":        "cmdi",
		"xxe":        "xxe",
	}[h.Sink]
	if !known || h.Param == "" {
		return "", nil, false
	}
	args = map[string]any{"param": h.Param, "classes": []string{probeClass}, "hypothesis_id": h.ID}
	if probeClass == "path" {
		// The marker the application would have to serve from outside its root for a
		// traversal to be visible at all.
		args["marker"] = "youkai-path-marker"
	}
	return "param", args, true
}
