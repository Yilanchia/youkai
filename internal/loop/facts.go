package loop

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"youkai/internal/mcp"
)

// Fact is one normalised observation. This is the ONLY thing a worker is allowed
// to put into the graph: a short, reviewable statement plus an evidence pointer
// (request_id and/or audit location). Raw response bodies never enter the graph.
type Fact struct {
	Statement string
	Evidence  map[string]any
	Tags      []string
}

// Finding is a static-analysis result with a file:line location, produced by the
// binary hand. It is a candidate, never a verified vulnerability.
type Finding struct {
	Title    string
	Severity string
	Where    string
	Detail   string
	Tags     []string
	Evidence map[string]any
}

// Asset is a ledger-anchored vertex the loop may derive work from: a host to
// probe, or an artifact to hand to the binary hand.
type Asset struct {
	Value string // stable anchor id, e.g. "host:lab.invalid" or "artifact:/x/y.exe"
	Kind  string // "host" | "artifact"
	Props map[string]any
}

// Observation is one worker result reduced to graph-ready pieces.
type Observation struct {
	Facts    []Fact
	Findings []Finding
	Assets   []Asset
}

// normalize turns a hand result into observations, deterministically.
//
// This mirrors Fairy's worker.js factsFromResult: same triggers, same wording
// philosophy - record what was observed, never invent a vulnerability. It is
// tolerant about envelope shape (some tools nest under "result") because a
// normaliser that throws on an unexpected key would lose evidence.
func normalize(action string, args map[string]any, res mcp.ToolResult) Observation {
	var obs Observation
	if res.IsError || strings.TrimSpace(res.Text()) == "" {
		return obs
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(res.Text()), &root); err != nil {
		return obs // not JSON: nothing to decide, the trace keeps the raw text out
	}
	// Some tools wrap their payload in {"result": {...}}.
	if inner, ok := root["result"].(map[string]any); ok {
		merged := inner
		if id, has := root["request_id"]; has {
			if _, taken := merged["request_id"]; !taken {
				merged["request_id"] = id
			}
		}
		root = merged
	}

	switch action {
	case "web_probe":
		obs.Facts = append(obs.Facts, probeFacts(root, args)...)
	case "web_scan":
		obs.Facts = append(obs.Facts, scanFacts(root)...)
		obs.Findings = append(obs.Findings, scanFindings(root)...)
		obs.Assets = append(obs.Assets, scanAssets(root)...)
	case "web_compare":
		obs.Facts = append(obs.Facts, compareFacts(root, args)...)
	case "web_param", "web_param_adaptive":
		obs.Facts = append(obs.Facts, paramFacts(root, args)...)
	case "web_role_matrix":
		obs.Facts = append(obs.Facts, matrixFacts(root, args)...)
	case "analyze_target", "bin_info", "bin_dossier", "scan", "secrets":
		obs.Findings = append(obs.Findings, staticFindings(action, root)...)
		obs.Facts = append(obs.Facts, staticFacts(action, root)...)
	}
	return obs
}

func probeFacts(root map[string]any, args map[string]any) []Fact {
	target := firstString(root, "url", "final_url")
	if target == "" {
		target = stringArg(args, "url")
	}
	status := intOf(root["status"])
	method := strings.ToUpper(stringArg(args, "method"))
	if method == "" {
		method = "GET"
	}
	reqID := stringOf(root["request_id"])
	audit := stringOf(root["audit_path"])

	ev := map[string]any{"request_id": reqID, "url": target, "status": status}
	if audit != "" {
		ev["audit_path"] = audit
	}

	facts := []Fact{{
		Statement: fmt.Sprintf("%s %s -> %d", method, target, status),
		Evidence:  ev,
		Tags:      []string{"probe", "http"},
	}}

	// Fairy worker.js: probe 200 on /.git/config means the config is readable.
	if status == 200 && gitConfigRe.MatchString(target) {
		facts = append(facts, Fact{
			Statement: "git 配置可读:" + target,
			Evidence:  ev,
			Tags:      []string{"git", "exposed"},
		})
	}
	return facts
}

func scanFacts(root map[string]any) []Fact {
	var facts []Fact
	audit := stringOf(root["audit_path"])
	runID := stringOf(root["run_id"])

	for _, f := range asMapSlice(root["findings"]) {
		title := stringOf(f["title"])
		kind := stringOf(f["kind"])
		sev := stringOf(f["severity"])
		where := stringOf(f["where"])
		ev := map[string]any{}
		if e := asMap(f["evidence"]); e != nil {
			if id := stringOf(e["request_id"]); id != "" {
				ev["request_id"] = id
			}
			if st := intOf(e["status"]); st != 0 {
				ev["status"] = st
			}
		}
		if audit != "" {
			ev["audit_path"] = audit
		}
		if runID != "" {
			ev["run_id"] = runID
		}

		statement := fmt.Sprintf("scan 候选(%s): %s @ %s", sev, title, where)
		tags := []string{"scan", "candidate"}
		if kind != "" {
			tags = append(tags, kind)
		}
		facts = append(facts, Fact{Statement: statement, Evidence: ev, Tags: tags})

		if kind == "reflection" {
			// Keep the raw location too: the follow-up rule needs the exact
			// (url, param) pair, and reconstructing it from prose is lossy.
			evReflection := map[string]any{"where": where}
			for k, v := range ev {
				evReflection[k] = v
			}
			facts = append(facts, Fact{
				Statement: "参数反射待浏览器复核:" + where,
				Evidence:  evReflection,
				Tags:      []string{"reflects", "param-candidate"},
			})
		}
	}
	return facts
}

func scanFindings(root map[string]any) []Finding {
	var out []Finding
	for _, f := range asMapSlice(root["findings"]) {
		where := stringOf(f["where"])
		if where == "" {
			continue
		}
		ev := map[string]any{}
		if e := asMap(f["evidence"]); e != nil {
			if id := stringOf(e["request_id"]); id != "" {
				ev["request_id"] = id
			}
		}
		out = append(out, Finding{
			Title:    stringOf(f["title"]),
			Severity: stringOf(f["severity"]),
			Where:    where,
			Detail:   stringOf(f["detail"]),
			Tags:     append([]string{"scan"}, tagsOf(f)...),
			Evidence: ev,
		})
	}
	return out
}

func scanAssets(root map[string]any) []Asset {
	var out []Asset
	surface := asMap(root["attack_surface"])
	if surface == nil {
		return out
	}
	for _, a := range asMapSlice(surface["artifacts"]) {
		value := ""
		if s, ok := a["url"].(string); ok && s != "" {
			value = s
		} else if s, ok := a["href"].(string); ok && s != "" {
			value = s
		} else if s, ok := a["value"].(string); ok && s != "" {
			value = s
		}
		if value == "" {
			continue
		}
		out = append(out, Asset{
			Value: "artifact:" + value,
			Kind:  "artifact",
			Props: map[string]any{"kind": "artifact", "url": value},
		})
	}
	return out
}

func compareFacts(root map[string]any, args map[string]any) []Fact {
	target := firstString(root, "url")
	if target == "" {
		target = stringArg(args, "url")
	}
	verdict := firstString(root, "verdict")
	a := asMap(root["a"])
	b := asMap(root["b"])

	ev := map[string]any{"url": target, "verdict": verdict}
	if a != nil && stringOf(a["request_id"]) != "" {
		ev["request_id_a"] = stringOf(a["request_id"])
	}
	if b != nil && stringOf(b["request_id"]) != "" {
		ev["request_id_b"] = stringOf(b["request_id"])
	}

	facts := []Fact{{
		Statement: fmt.Sprintf("双账号比对 %s -> %s", target, verdict),
		Evidence:  ev,
		Tags:      []string{"compare"},
	}}
	if verdict == "marker-in-both" {
		facts = append(facts, Fact{
			Statement: "越权候选:" + target + " 标记在两账号均可见",
			Evidence:  ev,
			Tags:      []string{"bola", "idor"},
		})
	}
	return facts
}

func paramFacts(root map[string]any, args map[string]any) []Fact {
	var facts []Fact
	targets := asStringSlice(root["targets"])
	if len(targets) == 0 {
		targets = asStringSlice(args["urls"])
	}
	for _, f := range asMapSlice(root["findings"]) {
		kind := stringOf(f["kind"])
		where := stringOf(f["where"])
		if where == "" && len(targets) > 0 {
			where = targets[0]
		}
		ev := map[string]any{"url": where}
		if e := asMap(f["evidence"]); e != nil {
			if id := stringOf(e["request_id"]); id != "" {
				ev["request_id"] = id
			}
		}
		// An active probe reports per-run identifiers, not per-request ones; the
		// audit path is the evidence pointer in that case.
		if p := stringOf(root["audit_path"]); p != "" {
			ev["audit_path"] = p
		}
		if id := stringOf(root["run_id"]); id != "" {
			ev["run_id"] = id
		}
		facts = append(facts, Fact{
			Statement: fmt.Sprintf("参数探针命中 %s:%s", kind, where),
			Evidence:  ev,
			Tags:      []string{"param", kind},
		})
	}
	return facts
}

func matrixFacts(root map[string]any, args map[string]any) []Fact {
	var facts []Fact
	for _, r := range asMapSlice(root["rows"]) {
		target := stringOf(r["url"])
		if target == "" {
			continue
		}
		ev := map[string]any{"url": target}
		if stringOf(r["difference"]) != "" {
			ev["difference"] = stringOf(r["difference"])
		}
		facts = append(facts, Fact{
			Statement: fmt.Sprintf("权限矩阵 %s -> %s", target, firstString(r, "verdict", "status_summary")),
			Evidence:  ev,
			Tags:      []string{"role-matrix"},
		})
	}
	return facts
}

func staticFindings(action string, root map[string]any) []Finding {
	var out []Finding
	for _, f := range asMapSlice(root["findings"]) {
		where := firstString(f, "where", "file", "location")
		if where == "" {
			continue
		}
		if f["line"] != nil {
			where = fmt.Sprintf("%s:%d", where, intOf(f["line"]))
		}
		ev := map[string]any{}
		if stringOf(f["id"]) != "" {
			ev["finding_id"] = stringOf(f["id"])
		}
		out = append(out, Finding{
			Title:    firstString(f, "title", "name", "kind"),
			Severity: firstString(f, "severity", "confidence"),
			Where:    where,
			Detail:   firstString(f, "detail", "description"),
			Tags:     append([]string{"verdex", action}, tagsOf(f)...),
			Evidence: ev,
		})
	}
	return out
}

func staticFacts(action string, root map[string]any) []Fact {
	var facts []Fact
	kind := firstString(root, "kind", "target_kind", "format")
	if kind == "" {
		kind = action
	}
	ev := map[string]any{"tool": action}
	if p := firstString(root, "path", "target"); p != "" {
		ev["path"] = p
	}
	facts = append(facts, Fact{
		Statement: fmt.Sprintf("%s 完成:%s", action, kind),
		Evidence:  ev,
		Tags:      []string{"verdex", action},
	})
	return facts
}

// gitConfigRe matches the classic git-source-leak probe target.
var gitConfigRe = regexp.MustCompile(`/\.git/config$`)

// ---- tolerant JSON helpers -------------------------------------------------

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func asMapSlice(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func asStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		if s, ok := v.([]string); ok {
			return s
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func tagsOf(m map[string]any) []string {
	return asStringSlice(m["tags"])
}

func stringArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	s, _ := args[key].(string)
	return s
}

// paramFollowUpTarget pulls (url, param) out of a reflection finding's "where"
// field, which Fairy writes as: "GET https://host/path (param: q)".
var whereParamRe = regexp.MustCompile(`^(?:[A-Z]+ )?(\S+)\s+\(param:\s*([^)]+)\)$`)

func paramFollowUpTarget(fact Fact) (urlStr, param string, ok bool) {
	for _, raw := range []string{stringOf(fact.Evidence["url"]), stringOf(fact.Evidence["where"]), statementURL(fact.Statement)} {
		if raw == "" {
			continue
		}
		if m := whereParamRe.FindStringSubmatch(raw); m != nil {
			return m[1], strings.TrimSpace(m[2]), true
		}
	}
	// The statement embeds "GET <url> (param: q)" after the colon.
	if idx := strings.Index(fact.Statement, "GET "); idx >= 0 {
		if m := whereParamRe.FindStringSubmatch(fact.Statement[idx:]); m != nil {
			return m[1], strings.TrimSpace(m[2]), true
		}
	}
	return "", "", false
}

func statementURL(statement string) string {
	for _, field := range strings.Fields(statement) {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			return field
		}
	}
	return ""
}

// hostOf reduces a URL to its host, for asset anchoring.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}
