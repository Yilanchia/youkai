// Package result reads the envelope a hand returns.
//
// Hands answer with JSON-as-text, and the identifiers an evidence chain needs are
// nested differently per tool: a single request answers with a top-level
// request_id, a two-account comparison nests one under "a"/"b", and a parameter
// probe only names request ids inside each finding's evidence. Reading that shape
// in one place is what keeps "every conclusion carries a request_id" true rather
// than aspirational.
package result

import (
	"encoding/json"
	"strings"
)

// RequestID finds the most specific request identifier in a hand's text result.
//
// Order: top-level request_id, then the first finding's evidence request_id, then
// a/b comparison request ids, then a nested "result" object.
func RequestID(text string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return ""
	}
	if s := str(m["request_id"]); s != "" {
		return s
	}
	if root, ok := m["result"].(map[string]any); ok {
		if s := str(root["request_id"]); s != "" {
			return s
		}
		if s := requestIDFromFindings(root); s != "" {
			return s
		}
	}
	if s := requestIDFromFindings(m); s != "" {
		return s
	}
	for _, key := range []string{"a", "b"} {
		if sub, ok := m[key].(map[string]any); ok {
			if s := str(sub["request_id"]); s != "" {
				return s
			}
		}
	}
	if s := requestIDsFromRequests(m); s != "" {
		return s
	}
	return ""
}

// RequestIDs collects every request id visible in the result, in first-seen
// order, capped at max (0 means 32).
func RequestIDs(text string, max int) []string {
	if max <= 0 {
		max = 32
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[s] || len(out) >= max {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	if s := str(m["request_id"]); s != "" {
		add(s)
	}
	for _, f := range findings(m) {
		if ev, ok := f["evidence"].(map[string]any); ok {
			add(str(ev["request_id"]))
		}
	}
	for _, key := range []string{"a", "b"} {
		if sub, ok := m[key].(map[string]any); ok {
			add(str(sub["request_id"]))
		}
	}
	if reqs, ok := m["requests"].([]any); ok {
		for _, r := range reqs {
			if sub, ok := r.(map[string]any); ok {
				add(str(sub["request_id"]))
			}
		}
	}
	return out
}

// URL finds the target a result is about.
func URL(text string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return ""
	}
	for _, k := range []string{"url", "final_url", "seed", "target"} {
		if s := str(m[k]); s != "" {
			return s
		}
	}
	if root, ok := m["result"].(map[string]any); ok {
		for _, k := range []string{"url", "final_url", "seed"} {
			if s := str(root[k]); s != "" {
				return s
			}
		}
	}
	return ""
}

// AuditPath finds the on-disk audit trail a hand recorded for this call. When a
// tool answers without a per-request id (an active probe reports per-run ids
// only), the audit path is what makes the evidence checkable.
func AuditPath(text string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return ""
	}
	if s := str(m["audit_path"]); s != "" {
		return s
	}
	if root, ok := m["result"].(map[string]any); ok {
		if s := str(root["audit_path"]); s != "" {
			return s
		}
	}
	return ""
}

// RunID finds the hand's run identifier, which names the audit file.
func RunID(text string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return ""
	}
	if s := str(m["run_id"]); s != "" {
		return s
	}
	if root, ok := m["result"].(map[string]any); ok {
		return str(root["run_id"])
	}
	return ""
}

// Summary is a one-line, non-secret description of a result for traces.
func Summary(text string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return truncate(strings.TrimSpace(text), 160)
	}
	parts := make([]string, 0, 3)
	if u := str(m["url"]); u != "" {
		parts = append(parts, "url="+u)
	}
	if st, ok := m["status"]; ok {
		parts = append(parts, "status="+scalar(st))
	}
	if n := len(findings(m)); n > 0 {
		parts = append(parts, "findings="+itoa(n))
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, " ")
}

func requestIDFromFindings(m map[string]any) string {
	for _, f := range findings(m) {
		if ev, ok := f["evidence"].(map[string]any); ok {
			if s := str(ev["request_id"]); s != "" {
				return s
			}
		}
	}
	return ""
}

func requestIDsFromRequests(m map[string]any) string {
	if reqs, ok := m["requests"].([]any); ok {
		for _, r := range reqs {
			if sub, ok := r.(map[string]any); ok {
				if s := str(sub["request_id"]); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func findings(m map[string]any) []map[string]any {
	var out []map[string]any
	for _, key := range []string{"findings", "candidates", "hits"} {
		arr, ok := m[key].([]any)
		if !ok {
			continue
		}
		for _, e := range arr {
			if sub, ok := e.(map[string]any); ok {
				out = append(out, sub)
			}
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return itoa(int(t))
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
