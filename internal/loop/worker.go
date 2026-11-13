package loop

import (
	"context"
	"fmt"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/graph"
	"youkai/internal/result"
)

// ledgerSink is optionally implemented by a hands implementation that can mirror
// findings into Fairy's ledger.
type ledgerSink interface {
	IngestIntoFairy(ctx context.Context, project, source string, payload any) (bool, string)
}

// execOne executes exactly one claimed intent.
//
// Discipline, in order:
//  1. re-classify (never trust the stored tier alone)
//  2. refuse anything above tier 1
//  3. call the hand, once
//  4. normalise the result into facts/findings/assets, never raw bodies
//  5. record the trace; on failure leave the intent active and do not retry
func (r *Runner) execOne(ctx context.Context, n *graph.Node) StepRecord {
	action := n.String("action")
	args := n.Map("args")
	rec := StepRecord{IntentID: n.ID, Action: action, Tier: int(r.effectiveTier(n))}

	dec := gate.Explain(action, args)
	rec.Decision = dec.Reason

	// Second gate check. choose() already filtered, but a worker that trusts its
	// caller is not a wall.
	if !dec.Allowed() {
		_, _ = r.owner.Apply(graph.CmdSetStatus(n.ID, graph.StatusNeedsApproval))
		msg := "gate refused at dispatch: " + dec.Reason
		_, _ = r.owner.Apply(graph.CmdAddTrace(n.ID, msg))
		rec.Err = msg
		rec.Trace = msg
		return rec
	}

	hand, err := r.hands.HandFor(action)
	if err != nil {
		return r.fail(n, rec, "no hand owns this tool: "+err.Error())
	}
	rec.Hand = hand

	callArgs := r.callArgs(hand, args)
	res, err := r.hands.Call(ctx, hand, action, callArgs)
	if err != nil {
		return r.fail(n, rec, "hand call failed: "+err.Error())
	}
	if res.IsError {
		return r.fail(n, rec, "hand reported an error: "+firstLine(res.Text()))
	}

	obs := normalize(action, callArgs, res)
	rec.RequestID = result.RequestID(res.Text())
	rec.AuditPath = result.AuditPath(res.Text())
	rec.RunID = result.RunID(res.Text())

	for _, f := range obs.Facts {
		written, err := r.owner.Apply(graph.CmdAddFact(graph.FactSeed{
			Statement: f.Statement,
			Evidence:  f.Evidence,
			Tags:      f.Tags,
			Anchors:   anchorsForFact(f),
		}))
		if err != nil {
			continue
		}
		if !written.Deduped {
			rec.Facts++
			if _, err := r.owner.Apply(graph.CmdAddEdge(written.NodeID, n.ID, graph.RelSupports)); err != nil {
				continue
			}
		}
	}

	findingAnchors := anchorsFromArgs(args)
	for _, f := range obs.Findings {
		props := map[string]any{
			"title":    f.Title,
			"severity": f.Severity,
			"where":    f.Where,
			"detail":   f.Detail,
			"tags":     f.Tags,
			"evidence": f.Evidence,
			// A finding starts as a candidate, always. Only a human moves it to
			// verified, and youkai has no code path that does.
			"status": "candidate",
		}
		res, err := r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
			Kind:    graph.KindFinding,
			Props:   props,
			Anchors: findingAnchors,
		}))
		if err != nil {
			continue
		}
		rec.Findings++
		_, _ = r.owner.Apply(graph.CmdAddEdge(res.NodeID, n.ID, graph.RelSupports))
	}

	for _, a := range obs.Assets {
		props := map[string]any{"value": a.Value, "kind": a.Kind}
		for k, v := range a.Props {
			props[k] = v
		}
		_, _ = r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{Kind: graph.KindAsset, Props: props}))
	}

	// Sensitive-data check happens after the facts are recorded (they contain no
	// secrets) and before the loop continues.
	hit, sensitive := ScanSensitive(res.Text())

	trace := fmt.Sprintf("worker hand=%s action=%s ok=true tier=%d facts=%d findings=%d",
		hand, action, rec.Tier, rec.Facts, rec.Findings)
	if rec.RequestID != "" {
		trace += " request_id=" + rec.RequestID
	}
	if rec.AuditPath != "" {
		trace += " audit=" + rec.AuditPath
	}
	// Mirror binary-hand findings into Fairy's ledger so the authoritative
	// evidence store stays in one place (ADR-002). Best effort, and always
	// recorded: a silent failure here would look like "no findings".
	if hand == HandVerdex && len(obs.Findings) > 0 {
		if sink, ok := r.hands.(ledgerSink); ok && r.cfg.Project != "" {
			var payload any
			_ = res.JSON(&payload)
			if ok, note := sink.IngestIntoFairy(ctx, r.cfg.Project, "verdex", payload); ok {
				trace += " fairy_ingest=ok"
			} else {
				trace += " fairy_ingest=failed(" + note + ")"
			}
		}
	}
	if sensitive {
		trace += " SENSITIVE=" + hit.Name
	}
	rec.Trace = trace

	if _, err := r.owner.Apply(graph.CmdSetStatus(n.ID, graph.StatusDone)); err != nil {
		return r.fail(n, rec, "could not mark intent done: "+err.Error())
	}
	if _, err := r.owner.Apply(graph.CmdAddTrace(n.ID, trace)); err != nil {
		return r.fail(n, rec, "could not record trace: "+err.Error())
	}

	rec.OK = true
	if sensitive {
		rec.Sensitive = &hit
	}
	return rec
}

// fail records a failed step. The intent stays active so it is never silently
// retried by this loop; a human can requeue it deliberately.
func (r *Runner) fail(n *graph.Node, rec StepRecord, msg string) StepRecord {
	rec.OK = false
	rec.Err = msg
	rec.Trace = msg
	_, _ = r.owner.Apply(graph.CmdAddTrace(n.ID, msg+" (no retry; intent left active)"))
	return rec
}

func anchorsForFact(f Fact) []string {
	var out []string
	if f.Evidence != nil {
		if u := stringOf(f.Evidence["url"]); u != "" {
			if h := hostOf(u); h != "" {
				out = append(out, "host:"+h)
			}
		}
	}
	return out
}

func anchorsFromArgs(args map[string]any) []string {
	var out []string
	if p := stringArg(args, "path"); p != "" {
		out = append(out, "artifact:"+p)
	}
	if u := stringArg(args, "url"); u != "" {
		if h := hostOf(u); h != "" {
			out = append(out, "host:"+h)
		}
	}
	for _, u := range asStringSlice(args["urls"]) {
		if h := hostOf(u); h != "" {
			out = append(out, "host:"+h)
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
