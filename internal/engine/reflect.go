package engine

import (
	"context"
	"fmt"
	"strings"

	"youkai/internal/ledger"
)

// Reflection (v0.19 §2): after a step, say what it changed.
//
// The rule that matters here is honesty. A probe that found nothing is a RESULT,
// not a failure to be spun: the reflection says "this lead was not confirmed" and
// stops arguing. There is no scoring that can turn a miss into a reason to keep
// digging - that is exactly the failure mode this project exists to avoid.
//
// The reflection is a fact: it lands in the graph, it can be replayed, and the
// planner sees it next round.

// reflection is what one finished step implies for the rest of the run.
type reflection struct {
	Line      string   // one sentence for the trace
	Statement string   // the fact
	Tags      []string // hypothesis-confirmed / hypothesis-refuted / chain-unlocked
	Evidence  map[string]any
}

// reflectOn turns a finished step into a reflection, or nil when there is nothing
// worth saying (a plain scan of a plain page changes no hypothesis).
func (e *Engine) reflectOn(it ledger.Intent, rec StepRecord) *reflection {
	hypID := hypothesisIDOf(it.Args)
	hit := rec.Findings > 0

	switch {
	case hypID > 0 && hit:
		return &reflection{
			Line: fmt.Sprintf("复盘:线索 #%d 被证实(%s 命中 %d 条发现)", hypID, it.Capability, rec.Findings),
			Statement: fmt.Sprintf("复盘:白盒线索 #%d 已被黑盒证实 —— %s 在本次探测中命中 %d 条候选发现;"+
				"代码线索与运行证据同时成立,可信度从 code-only 升为双证据", hypID, it.Capability, rec.Findings),
			Tags: []string{"reflection", "hypothesis-confirmed"},
			Evidence: map[string]any{
				"hypothesis_id": hypID, "capability": it.Capability,
				"findings": rec.Findings, "request_ids": rec.RequestIDs,
			},
		}
	case hypID > 0 && !hit:
		// The honest branch. No "but maybe with another payload" - that is how a
		// miss turns into an invented conclusion.
		return &reflection{
			Line: fmt.Sprintf("复盘:线索 #%d 未被这次探测证实", hypID),
			Statement: fmt.Sprintf("复盘:白盒线索 #%d 未被证实 —— %s 这一次没有命中任何发现。"+
				"代码看着可疑但运行没复现,如实记为未证实,不据此继续推断", hypID, it.Capability),
			Tags: []string{"reflection", "hypothesis-unconfirmed"},
			Evidence: map[string]any{
				"hypothesis_id": hypID, "capability": it.Capability, "findings": 0,
			},
		}
	case it.Capability == "code_ingest" && rec.Facts > 0:
		return &reflection{
			Line: "复盘:源码摄取完成,后续假设可以按代码线索排序",
			Statement: fmt.Sprintf("复盘:源码摄取产出 %d 条事实,白盒线索进入账本;"+
				"接下来的探测会按线索优先级排列", rec.Facts),
			Tags:     []string{"reflection", "chain-unlocked"},
			Evidence: map[string]any{"facts": rec.Facts},
		}
	}
	return nil
}

// recordReflection writes it to the trace and the graph.
func (e *Engine) recordReflection(ctx context.Context, it ledger.Intent, rec StepRecord) {
	r := e.reflectOn(it, rec)
	if r == nil {
		return
	}
	// Also narrate the thought: "what did this change" is the most useful line in
	// the stream, and the wording is already the honest one from v0.19.
	{
		ev := newStepEvent(0, 0, PhaseReflect)
		ev.IntentID = it.ID
		ev.Capability = it.Capability
		ev.Status = "info"
		ev.Summary = clipEvent(strings.TrimPrefix(r.Line, "复盘:"))
		ev.Tags = r.Tags
		e.emitStep(ev)
	}
	_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, it.ID, r.Line)
	// Facts go through the same ingest path as everything else, so they are
	// queryable and replayable.
	obs := ledger.Observation{
		RequestIDs: rec.RequestIDs,
		Facts: []ledger.FactSeed{{
			Statement: r.Statement,
			Evidence:  r.Evidence,
			Tags:      r.Tags,
		}},
	}
	if len(obs.RequestIDs) == 0 {
		// A reflection about a local step still needs an anchor to be traceable.
		obs.Facts[0].Tags = append(obs.Facts[0].Tags, "no-request")
	}
	_, _ = e.cfg.Store.Ingest(ctx, e.cfg.EngagementID, nil, nil, obs)
}

// reflectionSummary is the one-line status the UI shows: what the engine thinks it
// is doing, and what it is waiting for.
func (e *Engine) reflectionSummary() string {
	var parts []string
	if len(e.lastReflections) > 0 {
		parts = append(parts, e.lastReflections[len(e.lastReflections)-1])
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " · ")
}
