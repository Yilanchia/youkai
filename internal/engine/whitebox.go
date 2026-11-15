package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"youkai/internal/ledger"
)

// Whitebox leads drive black-box probes.
//
// The rule is one-way and deliberately blunt: a code-only lead about a sink we can
// test from outside becomes a probe on this engagement's own target. The lead never
// becomes evidence by itself - if the probe does not hit, the lead is marked
// unconfirmed and reported as such (see ConfirmHypothesis).

// probeForHypothesis maps a lead to the capability that can settle it.
//
// Only sinks with a real existence check are mapped. A lead about command execution
// or deserialisation is worth remembering but there is no safe "is it there?" probe
// for it, so it stays a note for the human.
func probeForHypothesis(h ledger.Hypothesis) (capability string, args map[string]any, ok bool) {
	if strings.TrimSpace(h.Entry) == "" {
		return "", nil, false
	}
	switch h.Sink {
	case "sql-concat":
		if h.Param == "" {
			return "", nil, false
		}
		return "param", map[string]any{"param": h.Param, "classes": []string{"sqli"}, "hypothesis_id": h.ID}, true
	case "redirect":
		return "redirect_check", map[string]any{"hypothesis_id": h.ID}, true
	}
	return "", nil, false
}

// baseURL picks the engagement's first in-scope origin.
func baseURL(scopeRaw []byte) string {
	var sc map[string]any
	if len(scopeRaw) == 0 {
		return ""
	}
	if err := json.Unmarshal(scopeRaw, &sc); err != nil {
		return ""
	}
	inc, _ := sc["include"].([]any)
	for _, v := range inc {
		s, _ := v.(string)
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// A passport may name a bare host. Probe loopback/private hosts over http
		// and everything else over https - the same guess a human would make.
		if !strings.Contains(s, "://") {
			host := s
			if i := strings.IndexAny(host, "/?#"); i >= 0 {
				host = host[:i]
			}
			scheme := "https"
			if isLocalHost(host) {
				scheme = "http"
			}
			s = scheme + "://" + host
		}
		u, err := url.Parse(s)
		if err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

// isLocalHost reports whether a host is loopback or private.
func isLocalHost(host string) bool {
	h := strings.ToLower(host)
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	switch {
	case h == "localhost", h == "::1", strings.HasPrefix(h, "127."),
		strings.HasPrefix(h, "10."), strings.HasPrefix(h, "192.168."):
		return true
	}
	if strings.HasPrefix(h, "172.") {
		return true // 172.16/12 is the private range that matters in practice
	}
	return false
}

// entryPath turns "GET /search" into "/search".
func entryPath(entry string, _ string) string {
	if i := strings.Index(entry, " "); i >= 0 {
		return strings.TrimSpace(entry[i+1:])
	}
	return strings.TrimSpace(entry)
}

// ruleWhiteboxProbe derives one black-box probe per open lead.
func (e *Engine) ruleWhiteboxProbe(ctx context.Context, g ledger.GraphView) ([]derivation, error) {
	hypotheses, err := e.cfg.Store.ListHypotheses(ctx, e.cfg.EngagementID, ledger.HypothesisOpen)
	if err != nil {
		// A failure to read leads must not stop the run: it is an optimisation.
		return nil, nil
	}
	if len(hypotheses) == 0 {
		return nil, nil
	}
	base := baseURL(g.Engagement.Scope)
	if base == "" {
		return nil, nil
	}
	var out []derivation
	for _, h := range hypotheses {
		capability, args, ok := probeForHypothesis(h)
		if !ok {
			continue
		}
		p := entryPath(h.Entry, "")
		if p == "" {
			continue
		}
		target := withParam(base+p, h.Param, "1")
		args["url"] = target
		reason := fmt.Sprintf("源码线索:%s 的参数 %s 可能%s(%s);用一次存在性探测去证伪或证实",
			h.Entry, h.Param, sinkPhrase(h.Sink), h.Path)
		out = append(out, derivation{
			capability: capability,
			args:       args,
			rationale:  reason,
			expected:   "探测命中则线索升级为候选;不命中则记未确认",
		})
		if len(out) >= 6 {
			break
		}
	}
	return out, nil
}

// withParam appends a query parameter unless the URL already has a value for it.
func withParam(raw, param, value string) string {
	if param == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if q.Get(param) == "" {
		q.Set(param, value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// sinkPhrase is the user-facing sentence for a sink class.
func sinkPhrase(sink string) string {
	switch sink {
	case "sql-concat":
		return "拼接进 SQL"
	case "redirect":
		return "影响跳转目标"
	case "rce":
		return "进入命令执行"
	case "path":
		return "进入文件路径"
	case "ssti":
		return "进入模板渲染"
	case "ssrf":
		return "进入对外请求"
	case "deserialize":
		return "进入反序列化"
	case "html-output":
		return "直接进入 HTML"
	}
	return sink
}

// ConfirmHypothesis records the outcome of a probe against its lead.
//
// Nothing here can invent a finding: the probe's own evidence does that. This only
// moves the lead along, and only in the direction the evidence supports.
func (e *Engine) ConfirmHypothesis(ctx context.Context, hypothesisID int64, findings int, requestIDs []string) {
	s := e.cfg.Store
	ConfirmProbe(ctx, &s, e.cfg.EngagementID, hypothesisID, findings, requestIDs)
}

// ConfirmProbe settles a lead from the outcome of a probe.
//
// It is exported because tier-2 probes run through the API's execute route rather
// than through the engine's own loop, and both must report back the same way: a hit
// makes the lead a candidate, a miss records it as unconfirmed. Neither can turn a
// lead into a finding - that takes the probe's own evidence plus a human verdict.
func ConfirmProbe(ctx context.Context, store *Store, engagementID, hypothesisID int64, findings int, requestIDs []string) {
	if store == nil || hypothesisID <= 0 {
		return
	}
	if findings > 0 {
		note := fmt.Sprintf("黑盒探测命中:%d 条候选发现,请求 %s", findings, joinLimited(requestIDs, 3))
		_ = (*store).SetHypothesisState(ctx, engagementID, hypothesisID, ledger.HypothesisCandidate, note)
		return
	}
	_ = (*store).SetHypothesisState(ctx, engagementID, hypothesisID, ledger.HypothesisUnconfirmed,
		"代码看着可疑,但这次探测没有复现:不构成发现,仅记录")
}

// HypothesisIDOf reads the lead id a probe was derived for (0 when none).
func HypothesisIDOf(args map[string]any) int64 { return hypothesisIDOf(args) }
