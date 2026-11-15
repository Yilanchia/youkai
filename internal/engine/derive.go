package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// derivation is one rule's output: a typed intent ready for the ledger.
type derivation struct {
	capability string
	args       map[string]any
	rationale  string
	expected   string
	anchors    []string
	deps       []int64
}

// derive runs every rule once and ensures the resulting intents exist.
//
// Rules are pure functions of the graph plus the engagement scope; they are
// idempotent (the ledger dedupes on the intent fingerprint), so "derive then
// execute then derive again" converges instead of exploding.
func (e *Engine) derive(ctx context.Context) (int, error) {
	g, err := e.cfg.Store.Graph(ctx, e.cfg.EngagementID)
	if err != nil {
		return 0, err
	}

	// What this chain has already done. It is used as a derivation guard below: a
	// check that already completed against the same endpoint is not re-derived, so
	// the planning budget goes to what is still unknown. Retrieval is read-only and
	// scoped to this engagement (see ledger.SearchTraces).
	prior, err := e.cfg.Store.SearchTraces(ctx, e.cfg.EngagementID, ledger.TraceQuery{Limit: 100})
	if err != nil {
		// Memory is an optimisation, never a prerequisite: without it the chain
		// simply re-derives, which the fingerprint dedupe already bounds.
		prior = nil
	}
	e.priorWork = prior

	added := 0
	rules := []func(context.Context, ledger.GraphView) ([]derivation, error){
		e.ruleBootstrapAssets,
		e.ruleGitConfigProbe,
		e.ruleSurfaceScan,
		e.ruleAPISpec,
		e.ruleWhiteboxProbe,
		e.ruleArtifactChain,
		e.ruleBolaCompare,
		e.ruleDocSurfaceMatrix,
		e.ruleProofFollowUp,
	}
	for _, rule := range rules {
		ds, err := rule(ctx, g)
		if err != nil {
			return added, err
		}
		for _, d := range ds {
			if e.alreadyCovered(prior, d) {
				continue
			}
			spec := ledger.IntentSpec{
				Capability:   d.capability,
				Args:         d.args,
				Tier:         int(gate.Classify(d.capability, d.args)),
				Rationale:    d.rationale,
				ExpectedFact: d.expected,
				Anchors:      d.anchors,
				Deps:         d.deps,
				GateReason:   gate.Explain(d.capability, d.args).Reason,
			}
			spec.RequiresApproval = gate.Tier(spec.Tier).NeedsHuman()
			_, created, err := e.cfg.Store.EnsureIntent(ctx, e.cfg.EngagementID, spec)
			if err != nil {
				return added, fmt.Errorf("ensure intent %s: %w", d.capability, err)
			}
			if created {
				added++
			}
		}
		// Refresh after EVERY rule: a rule may have created assets (bootstrap)
		// rather than intents, and the next rule must see them.
		g, err = e.cfg.Store.Graph(ctx, e.cfg.EngagementID)
		if err != nil {
			return added, err
		}
	}
	return added, nil
}

// ruleBootstrapAssets turns authorised surfaces into host/surface vertices.
//
// Source of truth is the engagement's own scope passport: the included targets
// ARE the surfaces to look at. SeedURLs exist for a scope-less dry run (a lab).
func (e *Engine) ruleBootstrapAssets(ctx context.Context, g ledger.GraphView) ([]derivation, error) {
	if len(g.Assets) > 0 {
		return nil, nil
	}
	surfaces := scopeSurfaces(g.Engagement.Scope)
	for _, s := range e.cfg.SeedURLs {
		surfaces = appendUnique(surfaces, strings.TrimSpace(s))
	}
	if len(surfaces) == 0 {
		return nil, nil
	}
	// Assets are created directly: they are vertices, not work.
	for _, surface := range surfaces {
		base := baseOf(surface)
		if base == "" {
			continue
		}
		host := hostOf(base)
		if host == "" {
			continue
		}
		if _, err := e.cfg.Store.UpsertAsset(ctx, e.cfg.EngagementID, ledger.AssetSeed{
			Kind: "host", Value: "host:" + host,
			Props: map[string]any{"host": host, "base": base},
		}); err != nil {
			return nil, err
		}
		if surface != base {
			if _, err := e.cfg.Store.UpsertAsset(ctx, e.cfg.EngagementID, ledger.AssetSeed{
				Kind: "surface", Value: "surface:" + surface,
				Props: map[string]any{"host": host, "base": base, "url": surface},
			}); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

// ruleGitConfigProbe is the classic first read-only step: is .git exposed?
func (e *Engine) ruleGitConfigProbe(_ context.Context, g ledger.GraphView) ([]derivation, error) {
	var out []derivation
	for _, a := range g.Assets {
		if a.Kind != "host" {
			continue
		}
		base, _ := a.Props["base"].(string)
		if base == "" {
			continue
		}
		out = append(out, derivation{
			capability: "probe",
			args:       map[string]any{"url": strings.TrimRight(base, "/") + "/.git/config", "method": "GET"},
			rationale:  "暴露的 .git 目录会泄露源码与历史;先做一次只读 GET 确认可读性。",
			expected:   "HTTP 200 且包含 [core] 段",
			anchors:    []string{a.Value},
		})
	}
	return out, nil
}

// ruleSurfaceScan runs one read-only evidence sweep per surface.
func (e *Engine) ruleSurfaceScan(_ context.Context, g ledger.GraphView) ([]derivation, error) {
	var out []derivation
	for _, a := range g.Assets {
		var surface string
		switch a.Kind {
		case "host":
			surface, _ = a.Props["base"].(string)
		case "surface":
			surface, _ = a.Props["url"].(string)
		default:
			continue
		}
		if surface == "" {
			continue
		}
		out = append(out, derivation{
			capability: "scan",
			args:       map[string]any{"url": surface},
			rationale:  "安全头/Cookie/CORS/暴露面属于只读面,一次扫描即可给出候选。",
			expected:   "候选清单(每条带 request_id)",
			anchors:    []string{a.Value},
		})
	}
	return out, nil
}

// ruleArtifactChain derives the read-only binary analysis chain for a registered
// artifact: identify first, then the analyses that depend on it.
func (e *Engine) ruleArtifactChain(_ context.Context, g ledger.GraphView) ([]derivation, error) {
	var out []derivation
	identifyIDs := map[string]int64{}
	for _, it := range g.Intents {
		if it.Capability == "artifact_identify" {
			if p, ok := it.Args["path"].(string); ok {
				identifyIDs[p] = it.ID
			}
		}
	}
	for _, a := range g.Assets {
		if a.Kind != "artifact" {
			continue
		}
		path, _ := a.Props["path"].(string)
		if path == "" {
			continue // a URL artifact needs a human to fetch it first
		}
		anchor := []string{a.Value}
		dep := identifyIDs[path]
		out = append(out, derivation{
			capability: "artifact_identify",
			args:       map[string]any{"path": path},
			rationale:  "先确认样本格式与架构,后续分析才有的放矢。",
			expected:   "格式/架构/sha256",
			anchors:    anchor,
		})
		// Follow-ups depend on identify; if its id is unknown yet, the chain
		// appears on the next tick (deps fail closed until then).
		followUps := []struct {
			capability, rationale, expected string
		}{
			{"checksec", "缓解措施决定后续分析价值(是否存在可利用面)。", "PIE/NX/RELRO/Canary"},
			{"strings", "字符串常泄露路径、密钥线索与第三方库版本。", "关键字符串与计数"},
			{"secrets", "样本里硬编码的凭据是最高价值的只读发现。", "掩码后的凭据线索"},
		}
		for _, f := range followUps {
			d := derivation{
				capability: f.capability,
				args:       map[string]any{"path": path},
				rationale:  f.rationale,
				expected:   f.expected,
				anchors:    anchor,
			}
			if dep != 0 {
				d.deps = []int64{dep}
			}
			out = append(out, d)
		}
	}
	return out, nil
}

// ruleProofFollowUp is the tier-2 boundary.
//
// Seeing a reflecting parameter is a read-only observation. Actually probing it
// sends active payload-shaped requests, which is proof-grade: the engine derives
// the intent and then stops in front of it.
func (e *Engine) ruleProofFollowUp(_ context.Context, g ledger.GraphView) ([]derivation, error) {
	var out []derivation
	for _, f := range g.Facts {
		if !hasTag(f.Tags, "param-candidate") {
			continue
		}
		target, param, ok := paramFollowUp(f)
		if !ok {
			continue
		}
		anchors := []string{}
		if h := hostOf(target); h != "" {
			anchors = append(anchors, "host:"+h)
		}
		out = append(out, derivation{
			capability: "param",
			args:       map[string]any{"url": target, "param": param},
			rationale:  "反射已由只读检测观察到;存在性探针会发主动载荷形状请求,属档 2,必须人过闸。",
			expected:   "SQLi/SSTI 存在性命中(仅判存在)",
			anchors:    anchors,
		})
	}
	return out, nil
}

// ---- scope helpers ---------------------------------------------------------

// scopeSurfaces extracts usable base URLs from the engagement's scope JSON.
func scopeSurfaces(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var sc discipline.Scope
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil
	}
	var out []string
	for _, inc := range sc.Include {
		if strings.Contains(inc, "/") && !strings.Contains(inc, "://") {
			continue // CIDR: needs an explicit target, not a crawl seed
		}
		if strings.HasPrefix(inc, "*.") {
			continue // a wildcard is a permission, not a surface
		}
		if u := normaliseSurface(inc); u != "" {
			out = appendUnique(out, u)
		}
	}
	sort.Strings(out)
	return out
}

// normaliseSurface turns a scope entry into a full base URL.
func normaliseSurface(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	if !strings.Contains(in, "://") {
		in = "https://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func baseOf(rawURL string) string { return discipline.BaseOf(rawURL) }
func hostOf(rawURL string) string { return discipline.HostOf(rawURL) }

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

// ---- fact helpers ----------------------------------------------------------

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

var whereParamRe = regexp.MustCompile(`(?:^|\s)(https?://\S+)\s+\(param:\s*([^)]+)\)`)

// paramFollowUp pulls (url, param) out of a reflection fact.
func paramFollowUp(f ledger.Fact) (target, param string, ok bool) {
	if where, _ := f.Evidence["where"].(string); where != "" {
		if u, p, found := parseWhereParam(where); found {
			return u, p, true
		}
	}
	if u, p, found := parseWhereParam(f.Statement); found {
		return u, p, true
	}
	// Last resort: the evidence names the url and the statement names the param.
	if u, _ := f.Evidence["url"].(string); u != "" {
		if p := paramNameInText(f.Statement); p != "" {
			return u, p, true
		}
	}
	return "", "", false
}

// parseWhereParam reads Fairy-style locations: "GET https://h/p?q=1 (param: q)".
func parseWhereParam(s string) (string, string, bool) {
	m := whereParamRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	p := strings.TrimSpace(m[2])
	if p == "" {
		return "", "", false
	}
	return m[1], p, true
}

var paramNameRe = regexp.MustCompile(`param[^A-Za-z0-9]{1,3}([A-Za-z_][A-Za-z0-9_\-]{0,40})`)

func paramNameInText(s string) string {
	if m := paramNameRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// ruleBolaCompare derives the read-only half of a BOLA test: two GETs of the
// owner's object, one per identity.
//
// The intent records session NAMES, never headers - the dispatcher resolves them
// from the encrypted store at dispatch time. Without declared ownership there is
// no pair and no intent: youkai does not guess who owns what.
func (e *Engine) ruleBolaCompare(ctx context.Context, _ ledger.GraphView) ([]derivation, error) {
	if e.cfg.PairSource == nil {
		return nil, nil
	}
	pairs, err := e.cfg.PairSource.BolaPairs(ctx)
	if err != nil {
		// A broken manifest is a configuration problem, not a reason to stop the
		// read-only chain: record it as no pairs and let the operator see it in the
		// accounts panel.
		return nil, nil
	}
	var out []derivation
	for _, p := range pairs {
		host := hostOf(p.URL)
		anchors := []string{}
		if host != "" {
			anchors = append(anchors, "host:"+host)
		}
		out = append(out, derivation{
			capability: "compare",
			args: map[string]any{
				"url":       p.URL,
				"session_a": p.Owner,
				"session_b": p.Viewer,
				"marker":    p.Marker,
			},
			rationale: "归属关系已声明:同一对象换一个身份读一次,看标记是否两边都可见(BOLA)。",
			expected:  "两侧标记可见性对比",
			anchors:   anchors,
		})
	}
	return out, nil
}

// coveredByTrace lists the capabilities whose meaning is "check THIS endpoint".
//
// The guard is deliberately narrow: it only suppresses a repeat of the same check
// against the same endpoint. A derivation that carries a selector (a parameter, a
// marker, a session) is a different question about the same place, and those are
// never suppressed - that is where new evidence comes from.
var coveredByTrace = map[string]bool{
	"probe": true, "fingerprint": true, "scan": true, "headers": true,
	"cors": true, "exposures": true, "redirect_check": true, "browser": true,
	"api_spec": true,
}

// alreadyCovered reports whether this derivation repeats completed work.
func (e *Engine) alreadyCovered(prior []ledger.TraceHit, d derivation) bool {
	if !coveredByTrace[d.capability] {
		return false
	}
	// Any selector makes it a new question. "method" only counts when it is not a
	// read: every probe carries method=GET, and a POST probe is a different, tier-2
	// question that must still be proposed.
	for _, key := range []string{"param", "marker", "session", "session_a", "session_b", "headers"} {
		if v, ok := d.args[key]; ok && v != nil && v != "" {
			return false
		}
	}
	if m, ok := d.args["method"].(string); ok {
		switch strings.ToUpper(strings.TrimSpace(m)) {
		case "", "GET", "HEAD", "OPTIONS":
		default:
			return false
		}
	}
	target := ledger.TargetKey(d.args)
	if target == "" {
		return false
	}
	return ledger.Covered(prior, d.capability, target)
}

// targetKey normalises an intent's target the same way SearchTraces does, so the
// guard compares like with like.
func targetKey(args map[string]any) string {
	raw := ""
	if s, ok := args["url"].(string); ok {
		raw = s
	}
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host) + u.EscapedPath()
}

// SessionLister is implemented by a dispatcher that knows which identities have a
// ready session. Optional: without it the engine simply never derives a matrix.
type SessionLister interface {
	ReadySessions(ctx context.Context) ([]string, error)
}

// ruleDocSurfaceMatrix turns a documented API into a matrix.
//
// When an API document has been ingested (facts tagged source=openapi) and at least
// two identities are ready, the whole documented GET surface can be compared
// read-only: role_matrix costs one GET per (endpoint, identity) and proves
// reachability differences without touching state. This is the point of ingesting
// the document at all.
func (e *Engine) ruleDocSurfaceMatrix(ctx context.Context, g ledger.GraphView) ([]derivation, error) {
	lister, ok := e.cfg.Store.(SessionLister)
	if !ok || lister == nil {
		return nil, nil
	}
	sessions, err := lister.ReadySessions(ctx)
	if err != nil || len(sessions) < 2 {
		return nil, nil
	}
	var urls []string
	seen := map[string]bool{}
	for _, f := range g.Facts {
		if !hasTag(f.Tags, "source=openapi") {
			continue
		}
		u, _ := f.Evidence["url"].(string)
		if u == "" || seen[u] || len(urls) >= 10 {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
	}
	if len(urls) == 0 {
		return nil, nil
	}
	sort.Strings(sessions)
	return []derivation{{
		capability: "role_matrix",
		args:       map[string]any{"urls": urls, "sessions": sessions},
		rationale:  "API 文档已登记端点;用已就绪身份做一次只读权限矩阵,看谁能到哪。",
		expected:   "端点 × 身份的状态/长度差异",
	}}, nil
}

// ruleAPISpec looks for a machine-readable API document on each surface.
//
// One GET per host. If nothing is there, the capability says so in a fact and the
// trace guard stops us asking again - the cost of being wrong is a single 404, and
// the payoff is that the whole documented surface becomes testable instead of only
// what a crawl stumbled onto.
func (e *Engine) ruleAPISpec(_ context.Context, g ledger.GraphView) ([]derivation, error) {
	var out []derivation
	for _, a := range g.Assets {
		if a.Kind != "host" {
			continue
		}
		base, _ := a.Props["base"].(string)
		if base == "" {
			continue
		}
		out = append(out, derivation{
			capability: "api_spec",
			args:       map[string]any{"url": strings.TrimRight(base, "/") + "/openapi.json"},
			rationale:  "如果站点提供了机器可读的 API 文档,接入它能把整份文档化端点变成可测面(只读一次 GET)。",
			expected:   "OpenAPI/Swagger 文档及其端点清单",
			anchors:    []string{a.Value},
		})
	}
	return out, nil
}
