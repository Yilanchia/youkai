package engine

import (
	"net/url"
	"strings"
	"time"
)

// StepEvent is what one step of a run looks like from the outside.
//
// The point is to let a human watch the agent work: "it scanned this, it found
// that, it wants to do something risky and is waiting for me". So the event is
// built to be shown, which makes its SHAPE the security boundary: everything here
// is a normalised summary, never a response body, a header value, a cookie, a
// credential or a token.
//
// It is deliberately a separate type from StepRecord: the record is the engine's
// internal bookkeeping, the event is the projection that leaves the process.
type StepEvent struct {
	RunID      int64    `json:"run_id"`
	Seq        int      `json:"seq"`
	Phase      string   `json:"phase"` // derive | exec | reflect | stop
	IntentID   int64    `json:"intent_id,omitempty"`
	Capability string   `json:"capability,omitempty"`
	Tier       int      `json:"tier,omitempty"`
	Target     string   `json:"target,omitempty"`
	Status     string   `json:"status,omitempty"` // ok | miss | failed | parked | skipped | info
	Summary    string   `json:"summary,omitempty"`
	Facts      int      `json:"facts,omitempty"`
	Findings   int      `json:"findings,omitempty"`
	RequestID  string   `json:"request_id,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Stop       string   `json:"stop,omitempty"`
	At         string   `json:"at"`
	Tags       []string `json:"tags,omitempty"`
}

// Step phases.
const (
	PhaseDerive  = "derive"
	PhaseExec    = "exec"
	PhaseReflect = "reflect"
	PhaseStop    = "stop"
)

// maxEventSummary bounds a summary so a chatty capability cannot flood the UI.
const maxEventSummary = 240

// newStepEvent stamps the common fields.
func newStepEvent(runID int64, seq int, phase string) StepEvent {
	return StepEvent{RunID: runID, Seq: seq, Phase: phase, At: time.Now().UTC().Format(time.RFC3339)}
}

// eventForRecord projects one finished step into an event.
//
// Status is a word the operator can act on: ok / miss / failed. "miss" means the
// step ran and found nothing, which is different from "failed" (it could not run) -
// and both are different from "parked" (waiting for a human).
func eventForRecord(runID int64, args map[string]any, rec StepRecord) StepEvent {
	ev := newStepEvent(runID, 0, PhaseExec)
	ev.IntentID = rec.IntentID
	ev.Capability = rec.Capability
	ev.Tier = rec.Tier
	ev.Facts = rec.Facts
	ev.Findings = rec.Findings
	if len(rec.RequestIDs) > 0 {
		ev.RequestID = rec.RequestIDs[0]
	}
	switch {
	case rec.Err != "":
		ev.Status = "failed"
		ev.Reason = clipEvent(cleanReason(rec.Err))
	case rec.Sensitive != nil:
		ev.Status = "parked"
		ev.Reason = "发现疑似敏感数据,主动停下交人复核"
	case rec.Findings > 0:
		ev.Status = "ok"
		ev.Summary = clipEvent(stepSummary(rec))
	case rec.Facts > 0:
		ev.Status = "ok"
		ev.Summary = clipEvent(stepSummary(rec))
	default:
		ev.Status = "miss"
		ev.Summary = "没有新证据"
	}
	ev.Target = targetOfArgsForEvent(args)
	return ev
}

// stepSummary is the one line the operator reads: what it did, what came back.
func stepSummary(rec StepRecord) string {
	parts := []string{}
	if rec.Facts > 0 {
		parts = append(parts, itoaSmall(rec.Facts)+" 条事实")
	}
	if rec.Findings > 0 {
		parts = append(parts, itoaSmall(rec.Findings)+" 条候选")
	}
	if len(parts) == 0 {
		return "完成"
	}
	return "得到 " + strings.Join(parts, "、")
}

// targetOfArgsForEvent renders the target without leaking what was sent to it.
//
// A URL keeps its scheme/host/path and its parameter NAMES; the values are
// replaced by "…". That is enough for a human to recognise "the ?id= probe" while
// never echoing a payload, a token or a session id.
func targetOfArgsForEvent(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"url", "target", "login_url", "authorize_url"} {
		raw, ok := args[key].(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		return sanitiseTargetURL(raw)
	}
	if s, ok := args["path"].(string); ok {
		return "文件:" + baseName(s)
	}
	return ""
}

// sanitiseTargetURL drops userinfo, the fragment and every query VALUE.
func sanitiseTargetURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return clipEvent(raw)
	}
	if u.Host == "" {
		// A relative path: keep it as-is, there is nothing secret in a path alone.
		return clipEvent(u.Path)
	}
	out := u.Scheme + "://" + u.Host + u.Path
	if u.RawQuery != "" {
		names := make([]string, 0, 4)
		for name := range u.Query() {
			names = append(names, name)
		}
		sortStrings(names)
		out += "?" + strings.Join(names, "&") + "=…"
	}
	return clipEvent(out)
}

// cleanReason keeps the first line of an error and drops anything that looks like
// a URL query string, in case a backend echoed a payload into the message.
func cleanReason(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i] + "?…"
	}
	return s
}

func clipEvent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxEventSummary {
		return s
	}
	return s[:maxEventSummary] + "…"
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// emitStep calls the optional hook. A nil hook is a no-op, so behaviour without a
// listener is bit-for-bit what it was before this file existed.
func (e *Engine) emitStep(ev StepEvent) {
	if e.cfg.OnStep == nil {
		return
	}
	e.stepSeq++
	ev.Seq = e.stepSeq
	e.cfg.OnStep(ev)
}

// TargetForArgs exposes the sanitised target for callers outside the engine (the
// approval route narrates its own steps and must use the same rule).
func TargetForArgs(args map[string]any) string { return targetOfArgsForEvent(args) }
