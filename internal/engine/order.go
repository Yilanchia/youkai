package engine

import (
	"sort"
	"strings"

	"youkai/internal/ledger"
)

// Evidence-weighted ordering (v0.17).
//
// The engine used to take ready intents in creation order. That is deterministic
// but arbitrary: a probe derived from a whitebox lead is worth more than a generic
// surface scan, and the operator's budget is finite.
//
// This file adds a small, explicit score. It is a RANKING, not a permission: a
// tier-2 step still parks for a human whether it scores first or last. Every score
// comes with its reasons so the trace says why this step went first.
type intentScore struct {
	Intent ledger.Intent
	Score  int
	Why    []string
}

// scoreIntent is deliberately legible: every point has a named reason, and the
// weights are small integers a human can argue with.
func (e *Engine) scoreIntent(it ledger.Intent) (int, []string) {
	score := 0
	var why []string

	// 1) A step derived from a code lead has evidence behind it already.
	if hypothesisIDOf(it.Args) > 0 {
		score += 5
		why = append(why, "白盒线索支撑(+5)")
	}
	// 2) A step that carries the engine's own rationale from a fact is more likely
	// to matter than a bare surface check.
	if it.Provenance != "" {
		score += 3
		why = append(why, "有来源("+it.Provenance+")(+3)")
	}
	// 3) Read-only work is cheap to run and produces evidence for the next choice.
	if e.effectiveTier(it).AutonomousOK() {
		score += 2
		why = append(why, "只读可自走(+2)")
	}
	// 4) Capabilities that widen the map come before ones that only confirm it.
	switch it.Capability {
	case "code_ingest":
		score += 4
		why = append(why, "白盒摄取,能扩大后续视野(+4)")
	case "scan", "crawl", "api_spec":
		score += 1
		why = append(why, "铺开面(+1)")
	}
	// 5) Chain criticality: a step that other steps depend on gates the whole chain,
	// so it goes first. The dependency graph is the source of truth, not a guess.
	if e.dependedOn(it.ID) {
		score += 4
		why = append(why, "链上关键步,别的步骤在等它(+4)")
	}
	// 6) Fresh evidence: after a confirmed lead, probing the same area is worth more
	// than opening a brand-new surface. This keeps the run coherent instead of
	// scattering.
	if e.hasRecentConfirmation() {
		score += 1
		why = append(why, "刚有线索被证实(+1)")
	}
	// 7) A step whose endpoint is already covered by the engagement's trace is worth
	// less: the derivation guard would drop it anyway, this just ranks it lower.
	if e.priorWork != nil && ledger.Covered(e.priorWork, it.Capability, ledger.TargetKey(it.Args)) {
		score -= 4
		why = append(why, "trace 已覆盖该端点(-4)")
	}
	if len(why) == 0 {
		why = append(why, "无加分项")
	}
	return score, why
}

// orderWork sorts ready work by score, deterministically.
//
// Ties break on intent ID so the same graph always produces the same order: a
// planner whose output changes between runs cannot be audited.
func (e *Engine) orderWork(work []ledger.Intent) []intentScore {
	scored := make([]intentScore, 0, len(work))
	for _, it := range work {
		s, why := e.scoreIntent(it)
		scored = append(scored, intentScore{Intent: it, Score: s, Why: why})
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		return scored[i].Intent.ID < scored[j].Intent.ID
	})
	return scored
}

// explainOrder puts the ranking into the trace, so "why did this run first?" has
// an answer that is not "the model felt like it".
func explainOrder(scored []intentScore) string {
	if len(scored) == 0 {
		return ""
	}
	out := "优先级:"
	for i, s := range scored {
		if i >= 3 {
			break
		}
		if i > 0 {
			out += ";"
		}
		out += "#" + itoa64(s.Intent.ID) + " " + s.Intent.Capability + "=" + itoa64(int64(s.Score))
	}
	return out
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// dependedOn reports whether any intent waits for this one.
func (e *Engine) dependedOn(id int64) bool {
	for _, it := range e.lastGraph.Intents {
		for _, d := range it.Deps {
			if d == id {
				return true
			}
		}
	}
	return false
}

// hasRecentConfirmation reports whether the last round produced a confirmed lead.
func (e *Engine) hasRecentConfirmation() bool {
	for _, line := range e.lastReflections {
		if strings.Contains(line, "被证实") {
			return true
		}
	}
	return false
}
