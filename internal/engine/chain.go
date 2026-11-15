package engine

import (
	"context"
	"fmt"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Chain assembly (v0.17 §2).
//
// A chain is a set of intents where each step depends on the previous one, so the
// engine walks them in order and stops at the first step a human has to approve.
// That is the whole difference from a list: the second step does not even become
// claimable until the first has succeeded.
//
// The rules here are narrow on purpose. A chain is only assembled when BOTH halves
// are present: a code-side lead that says "this resource is reachable by id", and
// at least two identities with declared ownership. Anything less and the existing
// single-step rules are a better answer.
//
// A chain is NOT an execution plan: every tier-2 node in it parks for its own
// approval, exactly like a standalone step. The chain only decides what comes
// after what.

// orderishLead reports whether the graph holds a lead about a resource reached by
// an identifier: a code-side missing-authz hypothesis, or an ordered endpoint the
// surface scan already recorded.
func (e *Engine) orderishLead(g ledger.GraphView) (string, bool) {
	for _, a := range g.Assets {
		if a.Kind == "code-endpoint" {
			return "代码侧入口 " + a.Value, true
		}
	}
	return "", false
}

// ensureChain assembles the "two identities, one resource" chain.
//
// It returns how many intents it created. Errors are returned, not swallowed: a
// chain that cannot be built is fine, a chain that half-built is not.
func (e *Engine) ensureChain(ctx context.Context, g ledger.GraphView) (int, error) {
	if e.cfg.PairSource == nil {
		return 0, nil
	}
	lead, ok := e.orderishLead(g)
	if !ok {
		return 0, nil
	}
	pairs, err := e.cfg.PairSource.BolaPairs(ctx)
	if err != nil || len(pairs) == 0 {
		return 0, nil
	}
	pair := pairs[0]
	if pair.Owner == "" || pair.Viewer == "" {
		return 0, nil
	}

	added := 0
	mk := func(spec ledger.IntentSpec) (ledger.Intent, bool, error) {
		spec.Tier = int(gate.Classify(spec.Capability, spec.Args))
		spec.RequiresApproval = gate.Tier(spec.Tier).NeedsHuman()
		spec.GateReason = gate.Explain(spec.Capability, spec.Args).Reason
		it, created, err := e.cfg.Store.EnsureIntent(ctx, e.cfg.EngagementID, spec)
		if created {
			added++
		}
		return it, created, err
	}

	// Step 1 and 2: the two identities sign in. Tier 2, one approval each.
	ownerIt, ownerNew, err := mk(ledger.IntentSpec{
		Capability: "accounts_provision",
		Args:       map[string]any{"session": pair.Owner},
		Rationale:  "链的第 1 步:" + lead + " 需要两个身份;" + pair.Owner + " 先登录一次并保存会话",
		Provenance: "chain:idor/" + pair.Marker,
	})
	if err != nil {
		return added, err
	}
	viewerIt, viewerNew, err := mk(ledger.IntentSpec{
		Capability: "accounts_provision",
		Args:       map[string]any{"session": pair.Viewer},
		Rationale:  "链的第 2 步:另一个身份 " + pair.Viewer + " 登录,用来验证同一资源是否被越权访问",
		Provenance: "chain:idor/" + pair.Marker,
	})
	if err != nil {
		return added, err
	}
	if !ownerNew && !viewerNew {
		return added, nil // the chain already exists
	}

	// Step 3: the comparison. Tier 1, so it runs as soon as both logins are done -
	// and only then, because that is what Deps means.
	if pair.URL != "" {
		cmpIt, cmpCreated, cerr := mk(ledger.IntentSpec{
			Capability: "compare",
			Args: map[string]any{
				"url": pair.URL, "session_a": pair.Owner, "session_b": pair.Viewer,
				"marker": pair.Marker,
			},
			Rationale: fmt.Sprintf("链的第 3 步:%s 用 %s 的会话读一次、%s 的会话再读一次,"+
				"同样的资源两个身份都能拿到才叫越权", pair.URL, pair.Owner, pair.Viewer),
			ExpectedFact: "双账号比对结果",
			Provenance:   "chain:idor/" + pair.Marker,
			Deps:         []int64{ownerIt.ID, viewerIt.ID},
		})
		if cerr != nil {
			return added, cerr
		}
		// A plain rule may have derived this comparison before the chain existed.
		// Adopt it rather than deriving a second one that would run twice: the chain
		// is about ordering, not about adding work.
		if !cmpCreated && len(cmpIt.Deps) == 0 {
			if derr := e.cfg.Store.SetIntentDeps(ctx, e.cfg.EngagementID, cmpIt.ID,
				[]int64{ownerIt.ID, viewerIt.ID}); derr != nil {
				return added, derr
			}
		}
	}

	// The lineage goes into the graph as a fact, so the chain is visible to a human
	// (and to the next derive pass) without reading intent metadata.
	if added > 0 {
		_ = e.cfg.Store.AppendTrace(ctx, e.cfg.EngagementID, ownerIt.ID,
			"chain assembled: "+lead+" + identities "+pair.Owner+"/"+pair.Viewer+
				" → provision → provision → compare (deps on the two logins)")
	}
	return added, nil
}
