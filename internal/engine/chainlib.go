package engine

import (
	"context"
	"strings"

	"youkai/internal/ledger"
)

// The chain library (v0.19 §1).
//
// A chain is a small dependency graph of ordinary intents. Every node goes through
// the same gate as a hand-created step, and every tier-2 node parks for its own
// approval. Assembling a chain therefore adds NO authority: it only decides what
// comes after what, and what evidence is worth gathering next.
//
// The types live in a table rather than in if-statements so that adding one is a
// data change, and so a reviewer can see at a glance which leads each type needs.

// chainContext is what a chain type gets to work with.
type chainContext struct {
	Lead  string       // human-readable evidence that justified the chain
	Pair  AccessPair   // the identity pair (owner/viewer) and the resource
	Pairs []AccessPair // all declared pairs, for types that need more than one
	URL   string       // the resource to verify, absolute when possible
}

// chainType declares one kind of chain.
type chainType struct {
	Name string
	// Ready reports whether the evidence this chain needs is present.
	Ready func(e *Engine, g ledger.GraphView, pairs []AccessPair) (chainContext, bool)
	// Steps describes the nodes, in order. deps index into this slice.
	Steps []chainStep
}

// chainStep is one node template.
type chainStep struct {
	capability string
	args       func(c chainContext) map[string]any
	rationale  string
	// deps lists the indices of earlier steps this one waits for.
	deps []int
}

// chains is the table itself.
func (e *Engine) chainTable() []chainType {
	return []chainType{
		{
			Name:  "idor",
			Ready: readyResourceLead,
			Steps: []chainStep{
				{capability: "accounts_provision", args: func(c chainContext) map[string]any {
					return map[string]any{"session": c.Pair.Owner}
				}, rationale: "链的第 1 步:让所有者身份登录并保存会话"},
				{capability: "accounts_provision", args: func(c chainContext) map[string]any {
					return map[string]any{"session": c.Pair.Viewer}
				}, rationale: "链的第 2 步:让另一个身份登录,用来验证同一资源是否被越权访问"},
				{capability: "compare", deps: []int{0, 1}, args: func(c chainContext) map[string]any {
					// Same argument shape as ruleBolaCompare on purpose: the chain
					// adopts that intent (and gives it its dependencies) instead of
					// creating a second comparison that would run on its own.
					return map[string]any{
						"url": c.Pair.URL, "session_a": c.Pair.Owner, "session_b": c.Pair.Viewer,
						"marker": c.Pair.Marker,
					}
				}, rationale: "链的第 3 步:两个会话各读一次,同样的资源和标记都可见才算越权"},
			},
		},
		{
			// BFLA: a role matrix over the documented surface, once two identities
			// exist. It answers "does the low-privilege identity see the same data?"
			// without touching a single mutating endpoint.
			Name:  "bfla",
			Ready: readyMatrixSurface,
			Steps: []chainStep{
				{capability: "accounts_provision", args: func(c chainContext) map[string]any {
					return map[string]any{"session": c.Pair.Owner}
				}, rationale: "链的第 1 步:高权限身份登录"},
				{capability: "accounts_provision", args: func(c chainContext) map[string]any {
					return map[string]any{"session": c.Pair.Viewer}
				}, rationale: "链的第 2 步:低权限身份登录"},
				{capability: "role_matrix", deps: []int{0, 1}, args: func(c chainContext) map[string]any {
					return map[string]any{
						"urls": []string{c.URL},
						"sessions": []map[string]any{
							{"name": c.Pair.Owner},
							{"name": c.Pair.Viewer},
						},
					}
				}, rationale: "链的第 3 步:同一 URL 用两个身份各读一次,比对状态与内容"},
			},
		},
		{
			// SSRF: the whitebox lead already names the parameter, so this is a
			// single tier-2 node. It is a chain type anyway, so "which lead produced
			// this step" is answered the same way for every type.
			Name:  "ssrf",
			Ready: readySSRFLead,
			Steps: []chainStep{
				{capability: "param", args: func(c chainContext) map[string]any {
					return map[string]any{
						"url":     c.URL,
						"param":   c.Pair.Marker, // the hypothesis carries the parameter name in Marker
						"classes": []string{"ssrf"},
					}
				}, rationale: "链的第 1 步:把参数换成 canary URL,看目标会不会反向请求"},
			},
		},
		{
			// Auth weakness: weak JWT/OAuth configuration plus two identities means
			// an authorisation matrix is worth running - the token weakness may be
			// what lets a low-privilege identity in.
			Name:  "authz-after-weak-auth",
			Ready: readyWeakAuth,
			Steps: []chainStep{
				{capability: "accounts_provision", args: func(c chainContext) map[string]any {
					return map[string]any{"session": c.Pair.Owner}
				}, rationale: "链的第 1 步:高权限身份登录(用于取得合法会话做对照)"},
				{capability: "accounts_provision", args: func(c chainContext) map[string]any {
					return map[string]any{"session": c.Pair.Viewer}
				}, rationale: "链的第 2 步:低权限身份登录"},
				{capability: "role_matrix", deps: []int{0, 1}, args: func(c chainContext) map[string]any {
					return map[string]any{
						"urls": []string{c.URL},
						"sessions": []map[string]any{
							{"name": c.Pair.Owner},
							{"name": c.Pair.Viewer},
						},
					}
				}, rationale: "链的第 3 步:认证配置弱点已在报告里,这里验证它是否真的换来了越权"},
			},
		},
	}
}

// readyResourceLead: a code-side entry plus a declared pair with a resource.
func readyResourceLead(e *Engine, g ledger.GraphView, pairs []AccessPair) (chainContext, bool) {
	lead := codeLead(g)
	if lead == "" || !twoIdentities(pairs) || pairs[0].URL == "" {
		return chainContext{}, false
	}
	return chainContext{Lead: lead, Pair: pairs[0], Pairs: pairs, URL: absolute(pairs[0].URL, g)}, true
}

// readyMatrixSurface: a code lead plus a pair, using the pair's URL or the origin.
func readyMatrixSurface(e *Engine, g ledger.GraphView, pairs []AccessPair) (chainContext, bool) {
	lead := codeLead(g)
	if lead == "" || !twoIdentities(pairs) {
		return chainContext{}, false
	}
	url := pairs[0].URL
	if url == "" {
		url = "/"
	}
	return chainContext{Lead: lead, Pair: pairs[0], Pairs: pairs, URL: absolute(url, g)}, true
}

// readySSRFLead: a whitebox hypothesis naming an SSRF sink.
func readySSRFLead(e *Engine, g ledger.GraphView, pairs []AccessPair) (chainContext, bool) {
	h, ok := e.hypothesisFor(context.Background(), g, "ssrf")
	if !ok {
		return chainContext{}, false
	}
	pair := AccessPair{Marker: h.Param}
	if len(pairs) > 0 {
		pair = pairs[0]
	}
	return chainContext{
		Lead: "白盒线索:" + h.Entry + " 的参数 " + h.Param + " 可能触发服务端请求",
		Pair: pair, Pairs: pairs,
		URL: absolute(entryPath(h.Entry, ""), g),
	}, true
}

// readyWeakAuth: a JWT/OAuth finding plus two identities.
func readyWeakAuth(e *Engine, g ledger.GraphView, pairs []AccessPair) (chainContext, bool) {
	var weak string
	for _, f := range g.Findings {
		if f.Kind == "jwt" || f.Kind == "oauth" {
			weak = f.Title
			break
		}
	}
	if weak == "" || !twoIdentities(pairs) {
		return chainContext{}, false
	}
	url := pairs[0].URL
	if url == "" {
		url = "/"
	}
	return chainContext{Lead: "认证配置弱点:" + weak, Pair: pairs[0], Pairs: pairs, URL: absolute(url, g)}, true
}

// codeLead returns a short description of the strongest code-side lead, if any.
func codeLead(g ledger.GraphView) string {
	for _, a := range g.Assets {
		if a.Kind == "code-endpoint" {
			return "代码侧入口 " + a.Value
		}
	}
	return ""
}

// hypothesisFor finds a whitebox lead for a sink class.
func (e *Engine) hypothesisFor(ctx context.Context, g ledger.GraphView, sink string) (ledger.Hypothesis, bool) {
	hs, err := e.cfg.Store.ListHypotheses(ctx, e.cfg.EngagementID, ledger.HypothesisOpen)
	if err != nil {
		return ledger.Hypothesis{}, false
	}
	for _, h := range hs {
		if h.Sink == sink {
			return h, true
		}
	}
	return ledger.Hypothesis{}, false
}

// twoIdentities reports whether a pair actually names two different identities.
// An empty marker means "no declared ownership", and a chain must never be built
// on that: a login step with an empty session name is not a step.
func twoIdentities(pairs []AccessPair) bool {
	if len(pairs) == 0 {
		return false
	}
	p := pairs[0]
	return strings.TrimSpace(p.Owner) != "" && strings.TrimSpace(p.Viewer) != ""
}
