package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Trace retrieval: what has already been done, in a shape a planner can use.
//
// The engine writes a structured line into `intents.trace` after every step. Until
// now nothing read it back, so each planning round started from zero and could
// spend its budget re-checking an endpoint that was already checked. This file is
// the read side: a deterministic, redacted projection of completed work.
//
// Invariants:
//   - read-only: one SELECT, no target traffic, no guard, no gate;
//   - scoped to one engagement (memory must not leak between jobs);
//   - redacted: trace lines only ever contain capability/counters/request ids;
//     this projection adds nothing that was not already there;
//   - stable: results are ordered by intent id, so a planner call can be replayed.

// TraceHit is one reusable piece of process memory.
type TraceHit struct {
	IntentID   int64    `json:"intent_id"`
	Capability string   `json:"capability"`
	Tier       int      `json:"tier"`
	Status     string   `json:"status"`
	Target     string   `json:"target,omitempty"`
	Summary    string   `json:"summary"`
	RequestIDs []string `json:"request_ids,omitempty"`
	At         string   `json:"at"`
}

// TraceQuery filters the projection. Empty fields mean "no filter".
type TraceQuery struct {
	Capability string
	Host       string
	Keyword    string
	Limit      int
}

const (
	defaultTraceLimit = 50
	maxTraceLimit     = 200
)

// SearchTraces returns completed work for one engagement, newest last.
func (s *Store) SearchTraces(ctx context.Context, engagementID int64, q TraceQuery) ([]TraceHit, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = defaultTraceLimit
	}
	if limit > maxTraceLimit {
		limit = maxTraceLimit
	}

	// Only steps that actually ran (or were deliberately skipped) are memory worth
	// reading; a queued intent is a plan, not a result.
	rows, err := s.pool.Query(ctx, `
		SELECT id, capability, tier, status, args, trace, updated_at
		  FROM intents
		 WHERE engagement_id = $1
		   AND trace <> ''
		   AND status IN ('done','skipped','needs_approval','blocked','active')
		 ORDER BY id ASC`, engagementID)
	if err != nil {
		return nil, fmt.Errorf("ledger: search traces: %w", err)
	}
	defer rows.Close()

	capFilter := strings.TrimSpace(q.Capability)
	hostFilter := strings.ToLower(strings.TrimSpace(q.Host))
	kw := strings.ToLower(strings.TrimSpace(q.Keyword))

	var hits []TraceHit
	for rows.Next() {
		var (
			h     TraceHit
			args  []byte
			trace string
			at    time.Time
		)
		if err := rows.Scan(&h.IntentID, &h.Capability, &h.Tier, &h.Status, &args, &trace, &at); err != nil {
			return nil, err
		}
		rawArgs := decodeArgs(args)
		h.Target = targetOfArgs(rawArgs)
		h.Summary = summariseTrace(trace)
		h.RequestIDs = requestIDsOfTrace(trace)
		h.At = at.UTC().Format(time.RFC3339)

		if capFilter != "" && !strings.EqualFold(h.Capability, capFilter) {
			continue
		}
		if hostFilter != "" && !strings.EqualFold(hostOfTarget(h.Target), hostFilter) {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(h.Capability+" "+h.Target+" "+h.Summary), kw) {
			continue
		}
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Newest last is what a planner reads best; the cap keeps the oldest tail in
	// the same shape as the rest of the prompt (recent history matters most).
	if len(hits) > limit {
		hits = hits[len(hits)-limit:]
	}
	return hits, nil
}

// Covered reports whether a read-only check of this capability against this target
// has already completed.
//
// The engine uses it as a derivation guard so a chain does not re-run the same
// endpoint check every round. It deliberately ignores derivations that carry a
// selector (a parameter, a marker, a session): those are new questions about the
// same endpoint, not repetitions.
func Covered(hits []TraceHit, capability, target string) bool {
	if target == "" {
		return false
	}
	for _, h := range hits {
		if !strings.EqualFold(h.Capability, capability) {
			continue
		}
		if h.Status != StatusDone && h.Status != StatusSkipped {
			continue
		}
		if strings.EqualFold(h.Target, target) {
			return true
		}
	}
	return false
}

// ---- helpers ---------------------------------------------------------------

func decodeArgs(raw []byte) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// targetOfArgs picks the most specific target an intent carried and normalises it
// to "host/path" (no scheme, no query): the query is where markers and parameters
// live, and two probes of the same endpoint differ only there.
func targetOfArgs(args map[string]any) string {
	raw := ""
	for _, key := range []string{"url", "path"} {
		if s, ok := args[key].(string); ok && strings.TrimSpace(s) != "" {
			raw = s
			break
		}
	}
	if raw == "" {
		switch v := args["urls"].(type) {
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok && s != "" {
					raw = s
					break
				}
			}
		case []string:
			if len(v) > 0 {
				raw = v[0]
			}
		}
	}
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Host == "" {
		return u.Path
	}
	return strings.ToLower(u.Host) + u.EscapedPath()
}

func hostOfTarget(target string) string {
	if target == "" {
		return ""
	}
	if i := strings.IndexByte(target, '/'); i >= 0 {
		return target[:i]
	}
	return target
}

// summariseTrace keeps one line and bounds its length: the trace is already
// structured text, but a planner prompt is a budget, not a log dump.
func summariseTrace(trace string) string {
	line := strings.TrimSpace(strings.SplitN(strings.ReplaceAll(trace, "\r\n", "\n"), "\n", 2)[0])
	if len(line) > 240 {
		line = line[:240] + "…"
	}
	return line
}

// requestIDsOfTrace pulls the ids the engine recorded ("request_ids=a,b,c").
func requestIDsOfTrace(trace string) []string {
	const marker = "request_ids="
	i := strings.Index(trace, marker)
	if i < 0 {
		return nil
	}
	rest := trace[i+len(marker):]
	if j := strings.IndexAny(rest, " \n"); j >= 0 {
		rest = rest[:j]
	}
	var out []string
	for _, id := range strings.Split(rest, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// TargetKey is the normalised "host/path" identity of an intent target.
//
// It is exported because the engine's derivation guard and the trace projection must
// agree exactly: if they normalised differently, the guard would silently never
// match (or worse, match the wrong endpoint).
func TargetKey(args map[string]any) string { return targetOfArgs(args) }
