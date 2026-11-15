package engine

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Chain execution (v0.19 §1).
//
// The table in chainlib.go says which chains exist and what they need; this file
// builds them. Two invariants hold for every node, whatever the type:
//
//   - the tier comes from gate.Classify, exactly like a hand-made intent, and a
//     tier-2 node parks for its own approval;
//   - a node's dependencies are intents that must be DONE before it is even
//     claimable, which is what makes this a chain and not a list.
//
// Assembling a chain adds no authority. It only decides what comes after what.

// ensureChains walks the table and assembles whatever the evidence supports.
//
// Every declared pair is considered, not just the first one: a site with three
// owned objects deserves three chances to show the same defect.
func (e *Engine) ensureChains(ctx context.Context, g ledger.GraphView) (int, error) {
	// A chain needs either identities or a lead that needs none (SSRF). Bail out
	// early so an engagement with neither does not walk the table.
	if e.cfg.PairSource == nil && !hasSSRFLead(g) {
		return 0, nil
	}
	var pairs []AccessPair
	if e.cfg.PairSource != nil {
		got, err := e.cfg.PairSource.BolaPairs(ctx)
		if err == nil {
			pairs = got
		}
	}
	added := 0
	for _, ct := range e.chainTable() {
		// Every pair gets its own chain; types that only need one use pairs[0].
		seen := map[string]bool{}
		for _, pair := range pairsOrOne(pairs) {
			cand := append([]AccessPair{pair}, pairs...)
			cc, ready := ct.Ready(e, g, cand)
			if !ready {
				continue
			}
			// Same type + same resource + same identities = the same chain. Do not
			// build it twice because two pairs happen to share a URL.
			key := ct.Name + "|" + cc.URL + "|" + cc.Pair.Owner + "|" + cc.Pair.Viewer
			if seen[key] {
				continue
			}
			seen[key] = true
			n, err := e.buildChain(ctx, ct, cc)
			if err != nil {
				return added, err
			}
			added += n
		}
	}
	return added, nil
}

func pairsOrOne(pairs []AccessPair) []AccessPair {
	if len(pairs) == 0 {
		return []AccessPair{{}}
	}
	return pairs
}

func hasSSRFLead(g ledger.GraphView) bool {
	for _, a := range g.Assets {
		if a.Kind == "code-endpoint" {
			return true
		}
	}
	return false
}

// buildChain ensures the nodes exist, links the dependencies and records lineage.
func (e *Engine) buildChain(ctx context.Context, ct chainType, cc chainContext) (int, error) {
	added := 0
	ids := make([]int64, 0, len(ct.Steps))
	prov := "chain:" + ct.Name
	for i, step := range ct.Steps {
		args := step.args(cc)
		var deps []int64
		for _, di := range step.deps {
			if di < len(ids) {
				deps = append(deps, ids[di])
			}
		}
		tier := int(gate.Classify(step.capability, args))
		spec := ledger.IntentSpec{
			Capability:       step.capability,
			Args:             args,
			Tier:             tier,
			Rationale:        fmt.Sprintf("[%s 链 %d/%d] %s — 依据:%s", ct.Name, i+1, len(ct.Steps), step.rationale, cc.Lead),
			Provenance:       prov,
			RequiresApproval: gate.Tier(tier).NeedsHuman(),
			GateReason:       gate.Explain(step.capability, args).Reason,
			Deps:             deps,
		}
		it, created, err := e.cfg.Store.EnsureIntent(ctx, e.cfg.EngagementID, spec)
		if err != nil {
			return added, err
		}
		if created {
			added++
		}
		ids = append(ids, it.ID)
		// A node that already existed without its dependencies (a plain rule got
		// there first) gets them attached: the chain is about ordering, and a step
		// that ran out of order should not run again.
		// Only adopt a node that has not already run: attaching dependencies to a
		// finished step would claim an order that never happened.
		if !created && len(deps) > 0 && len(it.Deps) == 0 &&
			(it.Status == ledger.StatusTodo || it.Status == ledger.StatusNeedsApproval) {
			if derr := e.cfg.Store.SetIntentDeps(ctx, e.cfg.EngagementID, it.ID, deps); derr != nil {
				return added, derr
			}
		}
	}
	if added > 0 && len(ids) > 0 {
		_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, ids[0],
			fmt.Sprintf("chain assembled: type=%s lead=%q identities=%s/%s steps=%d url=%s",
				ct.Name, cc.Lead, cc.Pair.Owner, cc.Pair.Viewer, len(ct.Steps), cc.URL))
	}
	return added, nil
}

// absolute turns a resource path into a URL on the engagement's own origin.
func absolute(resource string, g ledger.GraphView) string {
	if strings.HasPrefix(resource, "http://") || strings.HasPrefix(resource, "https://") {
		return resource
	}
	base := baseURL(g.Engagement.Scope)
	if base == "" {
		return resource
	}
	if !strings.HasPrefix(resource, "/") {
		resource = "/" + resource
	}
	u, err := url.Parse(base + resource)
	if err != nil {
		return base + resource
	}
	return u.String()
}
