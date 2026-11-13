package loop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/graph"
)

// IntentSpec is a typed intent. Every intent - deterministic rule or LLM
// proposal - goes through the same construction path, so a proposal can never
// carry powers a rule does not have.
type IntentSpec struct {
	Goal         string         `json:"goal"`
	Action       string         `json:"action"`
	Args         map[string]any `json:"args"`
	Rationale    string         `json:"rationale,omitempty"`
	ExpectedFact string         `json:"expected_fact,omitempty"`
	// Anchors are ledger anchor values ("host:x", "artifact:/p").
	Anchors []string `json:"-"`
	// Deps are intent node ids that must finish first.
	Deps []int64 `json:"-"`
	// Inferred marks an LLM-proposed intent.
	Inferred bool `json:"inferred,omitempty"`
	// Provenance names the replayable archive that justifies an inferred intent.
	Provenance string `json:"provenance,omitempty"`
}

// TierOf returns the gate's tier for a spec's action+args. Rules and LLM output
// are both classified here; neither can declare its own tier.
func TierOf(spec IntentSpec) gate.Tier { return gate.Classify(spec.Action, spec.Args) }

// addIntent writes a typed intent into the graph.
//
// Deduplication is by (action, canonical args): a rule that fires twice must not
// produce two probes. The gate's tier is recorded so a human reading the graph
// sees the same classification the worker will re-check.
func (r *Runner) addIntent(spec IntentSpec) (int64, bool, error) {
	g := r.owner.Snapshot()
	if existing, ok := findIntent(g, spec.Action, spec.Args); ok {
		return existing, false, nil
	}

	tier := TierOf(spec)
	props := map[string]any{
		"action":            spec.Action,
		"args":              spec.Args,
		"tier":              int(tier),
		"tier_reason":       gate.Explain(spec.Action, spec.Args).Reason,
		"requires_approval": tier.NeedsHuman(),
		"status":            graph.StatusTodo,
		"goal":              spec.Goal,
	}
	if spec.Rationale != "" {
		props["rationale"] = spec.Rationale
	}
	if spec.ExpectedFact != "" {
		props["expected_fact"] = spec.ExpectedFact
	}
	if spec.Inferred {
		props["inferred"] = true
		props["provenance"] = spec.Provenance
	}

	res, err := r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
		Kind:    graph.KindIntent,
		Props:   props,
		Deps:    spec.Deps,
		Anchors: spec.Anchors,
	}))
	if err != nil {
		return 0, false, err
	}
	// Link the intent to the goal/fact that justified it.
	if goal := r.goalID(g); goal != 0 {
		if _, err := r.owner.Apply(graph.CmdAddEdge(res.NodeID, goal, graph.RelDerives)); err != nil {
			return res.NodeID, true, err
		}
	}
	return res.NodeID, true, nil
}

func (r *Runner) goalID(g *graph.Graph) int64 {
	goals := g.OfKind(graph.KindGoal)
	if len(goals) == 0 {
		return 0
	}
	return goals[0].ID
}

// findIntent looks for an intent with the same action and canonically equal args.
func findIntent(g *graph.Graph, action string, args map[string]any) (int64, bool) {
	want := argsKey(args)
	for _, n := range g.OfKind(graph.KindIntent) {
		if n.String("action") != action {
			continue
		}
		if argsKey(n.Map("args")) == want {
			return n.ID, true
		}
	}
	return 0, false
}

func argsKey(args map[string]any) string {
	if len(args) == 0 {
		return "{}"
	}
	b, err := json.Marshal(args)
	if err != nil {
		return fmt.Sprint(args)
	}
	return string(b)
}

// ---- deterministic rules ---------------------------------------------------
//
// These are the brain's priors: what a careful operator would try first given the
// ledger. They are pure functions of the graph plus (for bootstrap only) a
// read-only ledger query, so they are replayable and testable without a model.

type ruleFunc func(ctx context.Context, r *Runner, g *graph.Graph) (int, error)

var rules = []struct {
	name string
	fn   ruleFunc
}{
	{"bootstrap", ruleBootstrap},
	{"git-config-probe", ruleGitConfigProbe},
	{"surface-scan", ruleSurfaceScan},
	{"artifact-register", ruleArtifactRegister},
	{"artifact-analysis", ruleArtifactAnalysis},
	{"proof-follow-up", ruleProofFollowUp},
}

// tick runs every rule once, in order. It never sends a target request: the only
// hand call it may make is a read-only ledger query.
func (r *Runner) tick(ctx context.Context) (int, error) {
	total := 0
	for _, rule := range rules {
		g := r.owner.Snapshot()
		n, err := rule.fn(ctx, r, g)
		total += n
		if err != nil {
			return total, fmt.Errorf("rule %s: %w", rule.name, err)
		}
	}
	return total, nil
}

// ruleBootstrap derives the goal and the scope surfaces.
//
// Preferred source is Fairy's ledger ("账本驱动推断"); the configured seed URLs
// exist so youkai can be pointed at an engagement whose ledger is still empty.
//
// The rule is idempotent and incremental: the goal and the ledger query happen
// once, while seed URLs may be added on later runs (a new surface on a known host
// is a new thing to scan, so the asset keeps both the host and the full URL).
func ruleBootstrap(ctx context.Context, r *Runner, g *graph.Graph) (int, error) {
	added := 0

	var goalID int64
	if goals := g.OfKind(graph.KindGoal); len(goals) > 0 {
		goalID = goals[0].ID
	} else {
		res, err := r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
			Kind: graph.KindGoal,
			Props: map[string]any{
				"statement": "只读取证:" + r.cfg.Project,
				"project":   r.cfg.Project,
			},
		}))
		if err != nil {
			return added, err
		}
		goalID = res.NodeID
		added++
	}

	// Ask the ledger once per graph, not once per tick.
	ledgerAsked := false
	for _, h := range g.OfKind(graph.KindHint) {
		if h.String("source") == "fairy ledger summary" {
			ledgerAsked = true
			break
		}
	}

	var surfaces []string
	var source string
	ledgerN := 0
	if !ledgerAsked && r.cfg.Project != "" {
		res, err := r.callHand(ctx, "fairy", "fairy_ledger_show", map[string]any{
			"project": r.cfg.Project,
			"view":    "summary",
		})
		if err == nil && !res.IsError {
			hosts := hostsFromLedger(res.Text())
			ledgerN = len(hosts)
			surfaces = append(surfaces, hosts...)
			source = "fairy ledger summary"
		}
	}
	for _, h := range r.cfg.SeedHosts {
		surfaces = appendUniqueURL(surfaces, h)
	}
	if source == "" && len(surfaces) > 0 && len(r.cfg.SeedHosts) > 0 {
		source = "seed urls"
	} else if source == "" {
		source = "seed urls (ledger unavailable or empty)"
	}

	for _, surface := range surfaces {
		base := normalizeBase(surface)
		host := hostOf(base)
		if host == "" {
			continue
		}
		value := "host:" + host
		asset, err := r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
			Kind: graph.KindAsset,
			Props: map[string]any{
				"value": value,
				"kind":  "host",
				"host":  host,
				"base":  base,
			},
		}))
		if err != nil {
			return added, err
		}
		if !asset.Deduped {
			added++
			if _, err := r.owner.Apply(graph.CmdAddEdge(asset.NodeID, goalID, graph.RelSupports)); err != nil {
				return added, err
			}
		}

		// A surface deeper than the host root gets its own vertex. The graph is
		// append-only, so a later run cannot "update" an asset's URL - it adds a
		// sibling surface instead, and the history stays honest.
		if surface != base {
			surf, err := r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
				Kind: graph.KindAsset,
				Props: map[string]any{
					"value": "surface:" + surface,
					"kind":  "surface",
					"host":  host,
					"base":  base,
					"url":   surface,
				},
			}))
			if err != nil {
				return added, err
			}
			if !surf.Deduped {
				added++
				if _, err := r.owner.Apply(graph.CmdAddEdge(surf.NodeID, goalID, graph.RelSupports)); err != nil {
					return added, err
				}
			}
		}
	}

	if source != "" && (len(surfaces) > 0 || ledgerN > 0) {
		if _, err := r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
			Kind: graph.KindHint,
			Props: map[string]any{
				"source":       source,
				"hosts":        surfaces,
				"ledger_hosts": ledgerN,
				"note":         "bootstrap: context derived without human-provided intents",
			},
		})); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

// appendUniqueURL keeps the first spelling of each URL.
func appendUniqueURL(list []string, v string) []string {
	v = strings.TrimSpace(v)
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

// ruleGitConfigProbe probes /.git/config on every host asset. This is the
// chain step the design doc uses as its example, and it is tier 1.
func ruleGitConfigProbe(_ context.Context, r *Runner, g *graph.Graph) (int, error) {
	added := 0
	for _, a := range g.OfKind(graph.KindAsset) {
		if a.String("kind") != "host" {
			continue
		}
		base := a.String("base")
		if base == "" {
			continue
		}
		url := strings.TrimRight(base, "/") + "/.git/config"
		spec := IntentSpec{
			Goal:         "确认 .git/config 是否可读",
			Action:       "web_probe",
			Args:         map[string]any{"url": url, "method": "GET"},
			Rationale:    "暴露的 .git 目录会泄露源码与历史;先做一次只读 GET 确认可读性。",
			ExpectedFact: "HTTP 200 且包含 [core] 段",
			Anchors:      []string{a.String("value")},
		}
		if _, created, err := r.addIntent(spec); err != nil {
			return added, err
		} else if created {
			added++
		}
	}
	return added, nil
}

// ruleSurfaceScan runs one read-only evidence scan per host asset.
func ruleSurfaceScan(_ context.Context, r *Runner, g *graph.Graph) (int, error) {
	added := 0
	for _, a := range g.OfKind(graph.KindAsset) {
		// Host assets are scanned at their root; surface assets at their exact URL.
		var surface string
		switch a.String("kind") {
		case "host":
			surface = a.String("base")
		case "surface":
			surface = a.String("url")
		default:
			continue
		}
		if surface == "" {
			continue
		}
		spec := IntentSpec{
			Goal:         "一轮证据优先的只读检测",
			Action:       "web_scan",
			Args:         map[string]any{"urls": []string{surface}},
			Rationale:    "安全头/Cookie/CORS/反射/开放重定向属于只读面,一次扫描即可给出候选。",
			ExpectedFact: "候选清单(每条带 request_id)",
			Anchors:      []string{a.String("value")},
		}
		if _, created, err := r.addIntent(spec); err != nil {
			return added, err
		} else if created {
			added++
		}
	}
	return added, nil
}

// ruleArtifactRegister registers a URL artifact with Fairy's ledger WITHOUT
// downloading it.
//
// This is the web->binary handoff, step 1: Fairy's own scan tells us a sample
// exists; youkai records the metadata and stops. Pulling attacker-controlled
// bytes onto disk is a human decision (hands.PlanDownload), so the rule never
// passes confirm=true and never derives an analysis intent for a URL.
func ruleArtifactRegister(ctx context.Context, r *Runner, g *graph.Graph) (int, error) {
	if r.cfg.Project == "" {
		return 0, nil
	}
	registered := map[string]bool{}
	for _, h := range g.OfKind(graph.KindHint) {
		if h.String("source") == "fairy handoff" {
			registered[h.String("artifact")] = true
		}
	}
	added := 0
	for _, a := range g.OfKind(graph.KindAsset) {
		if a.String("kind") != "artifact" {
			continue
		}
		value := a.String("value")
		u := a.String("url")
		if u == "" || a.String("path") != "" || registered[value] {
			continue // local artifacts are analysed, URL artifacts are registered
		}
		res, err := r.callHand(ctx, HandFairy, "fairy_handoff", map[string]any{
			"project": r.cfg.Project,
			"url":     u,
			"note":    "registered by youkai; NOT downloaded (a human decides that)",
		})
		if err != nil || res.IsError {
			// Record the attempt so a reviewer sees the handoff was tried.
			note := "handoff registration failed"
			if err != nil {
				note += ": " + err.Error()
			} else {
				note += ": " + firstLine(res.Text())
			}
			_, _ = r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
				Kind:    graph.KindHint,
				Props:   map[string]any{"source": "fairy handoff", "artifact": value, "note": note, "ok": false},
				Anchors: []string{value},
			}))
			registered[value] = true
			added++
			continue
		}
		_, err = r.owner.Apply(graph.CmdAddNode(graph.NodeSeed{
			Kind: graph.KindHint,
			Props: map[string]any{
				"source":   "fairy handoff",
				"artifact": value,
				"note":     "registered with Fairy (metadata only, no download)",
				"ok":       true,
			},
			Anchors: []string{value},
		}))
		if err != nil {
			return added, err
		}
		registered[value] = true
		added++
	}
	return added, nil
}

// ruleArtifactAnalysis hands every local artifact to the binary hand, read-only.
func ruleArtifactAnalysis(_ context.Context, r *Runner, g *graph.Graph) (int, error) {
	added := 0
	for _, a := range g.OfKind(graph.KindAsset) {
		if a.String("kind") != "artifact" {
			continue
		}
		path := a.String("path")
		if path == "" {
			continue // a URL artifact needs a human to fetch it (see hands.Handoff)
		}
		spec := IntentSpec{
			Goal:         "对样本做只读静态分析",
			Action:       "analyze_target",
			Args:         map[string]any{"path": path},
			Rationale:    "样本已在本地;静态分析只读、不执行、不联网。",
			ExpectedFact: "kind/chain 与 file:line 发现",
			Anchors:      []string{a.String("value")},
		}
		if _, created, err := r.addIntent(spec); err != nil {
			return added, err
		} else if created {
			added++
		}
	}
	return added, nil
}

// ruleProofFollowUp is the tier-2 boundary.
//
// A reflection candidate is a parameter that echoes our marker. The read-only
// part is done (web_dom_context); actually probing that parameter is an ACTIVE
// request, which the loop must never send on its own. So it derives the intent
// and then stops in front of it - which is exactly the designed behaviour.
func ruleProofFollowUp(_ context.Context, r *Runner, g *graph.Graph) (int, error) {
	added := 0
	for _, f := range g.OfKind(graph.KindFact) {
		if !hasTag(f, "param-candidate") {
			continue
		}
		target, param, ok := paramFollowUpTarget(Fact{
			Statement: f.String("statement"),
			Evidence:  factEvidence(f),
		})
		if !ok || target == "" || param == "" {
			continue
		}
		anchors := []string{}
		if h := hostOf(target); h != "" {
			anchors = append(anchors, "host:"+h)
		}
		spec := IntentSpec{
			Goal:         "确认参数是否可注入",
			Action:       "web_param",
			Args:         map[string]any{"urls": []string{target}, "param": param},
			Rationale:    "反射已由只读检测观察到;存在性探针会发主动载荷形状请求,属档 2,必须人过闸。",
			ExpectedFact: "SQLi/SSTI 存在性命中(仅判存在)",
			Anchors:      anchors,
		}
		if _, created, err := r.addIntent(spec); err != nil {
			return added, err
		} else if created {
			added++
		}
	}
	return added, nil
}

func hasTag(n *graph.Node, tag string) bool {
	for _, t := range n.Strings("tags") {
		if t == tag {
			return true
		}
	}
	return false
}

func factEvidence(n *graph.Node) map[string]any {
	if m, ok := n.Prop("evidence").(map[string]any); ok {
		return m
	}
	return nil
}

// ---- ledger bootstrap helpers ---------------------------------------------

var (
	urlRe  = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
	hostRe = regexp.MustCompile(`(?i)"(?:host|target|value)"\s*:\s*"((?:[a-z0-9-]+\.)+[a-z]{2,}|localhost|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?`)
)

// hostsFromLedger pulls candidate base URLs out of whatever shape the ledger
// summary happens to have. Tolerant on purpose: the ledger is Fairy's authority
// and its summary shape is not youkai's to pin.
func hostsFromLedger(text string) []string {
	var out []string
	for _, raw := range urlRe.FindAllString(text, -1) {
		raw = strings.TrimRight(raw, `\/,`)
		if _, err := url.Parse(raw); err != nil {
			continue
		}
		out = appendUnique(out, normalizeBase(raw))
	}
	for _, m := range hostRe.FindAllStringSubmatch(text, -1) {
		if len(m) < 2 {
			continue
		}
		out = appendUnique(out, "http://"+m[1])
	}
	return out
}

// normalizeBase reduces a URL to scheme://host[:port], dropping any path.
func normalizeBase(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme + "://" + u.Host
}

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
