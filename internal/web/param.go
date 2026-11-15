package web

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Parameter-level existence probing (tier 2, proof-grade).
//
// The rule is existence only. The probes answer "does this parameter reach a SQL
// engine / a template engine?" and stop there: no UNION, no stacked queries, no
// time-based inference, no data extraction, no payload tuning. Every call is
// hard-capped at six target requests, and the budget is spent through one helper
// so the cap cannot be exceeded by adding a class.

const (
	// maxParamRequests is a hard cap, not a default: a call never sends more.
	maxParamRequests = 6
	// defaultMaxVariants bounds param_adaptive's encoding attempts.
	defaultMaxVariants = 3
	maxVariants        = 3
)

var (
	sqli49Rx = regexp.MustCompile(`\b49\b`)
	sqli42Rx = regexp.MustCompile(`\b42\b`)
)

type encodingVariant struct {
	name  string
	apply func(string) string
}

// encodingVariants mirror Fairy's vocabulary: "single" is the normal request
// encoding, "double" pre-encodes so the URL layer encodes a second time, and
// "html" sends entity forms. None of them is a bypass: they test whether the
// backend decodes differently from the WAF, and nothing more.
var encodingVariants = []encodingVariant{
	{name: "single", apply: func(s string) string { return s }},
	{name: "double", apply: doubleURLEncode},
	{name: "html", apply: htmlEntityEncode},
}

type sqlSignature struct {
	label string
	rx    *regexp.Regexp
}

var sqlSignatures = []sqlSignature{
	{"MySQL 语法错误", regexp.MustCompile(`(?i)You have an error in your SQL syntax`)},
	{"MySQL 语法提示", regexp.MustCompile(`(?i)SQL syntax.{0,80}MySQL`)},
	{"PHP MySQL 警告", regexp.MustCompile(`(?i)Warning:\s*mysql_[a-z_]+\(\)`)},
	{"MSSQL 未闭合引号", regexp.MustCompile(`(?i)unclosed quotation mark`)},
	{"Oracle 错误码", regexp.MustCompile(`ORA-\d{4,5}`)},
	{"PostgreSQL 错误", regexp.MustCompile(`(?i)PostgreSQL.{0,40}ERROR`)},
	{"SQLite 驱动错误", regexp.MustCompile(`(?i)SQLite/JDBCDriver`)},
	{"OLE DB SQL Server", regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`)},
	{"ODBC SQL Server", regexp.MustCompile(`(?i)ODBC SQL Server Driver`)},
	{"SQL 语法位置错误", regexp.MustCompile(`(?i)syntax error at or near`)},
}

type paramProbe struct {
	ctx     context.Context
	env     *Env
	rawURL  string
	name    string
	headers map[string]string
	budget  int
	b       *obsBuilder
	hits    map[string]bool
	probes  int
}

func runParam(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	return runParamProbe(ctx, env, args, false)
}

func runParamAdaptive(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	return runParamProbe(ctx, env, args, true)
}

func runParamProbe(ctx context.Context, env *Env, args map[string]any, adaptive bool) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	name, err := requiredString(args, "param")
	if err != nil {
		return ledger.Observation{}, err
	}
	classes, err := normaliseClasses(argStringSlice(args, "classes"))
	if err != nil {
		return ledger.Observation{}, err
	}

	g, err := guardOf(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	scope := g.Scope()
	if scope == nil || !scope.AllowActiveProbes {
		return ledger.Observation{}, fmt.Errorf(
			"web: 参数级主动探测未授权:在 scope 里设置 allow_active_probes=true 后重试(该能力会向目标发少量探测请求)")
	}
	variants := encodingVariants[:1]
	if adaptive {
		if !scope.AllowWAFProbe {
			return ledger.Observation{}, fmt.Errorf(
				"web: 编码变体探测需要 scope.allow_waf_probe=true;先对目标做 WAF 画像并显式授权")
		}
		n := clamp(argInt(args, "max_variants", defaultMaxVariants), 1, maxVariants)
		variants = encodingVariants[:n]
	}

	u, err := normaliseProbeURL(rawURL)
	if err != nil {
		return ledger.Observation{}, err
	}
	original := u.Query().Get(name)

	p := &paramProbe{
		ctx:     ctx,
		env:     env,
		rawURL:  rawURL,
		name:    name,
		headers: argStringMap(args, "headers"),
		budget:  maxParamRequests,
		b:       newObs(),
		hits:    map[string]bool{},
	}

	baseline, err := p.request(rawURL, "param:baseline")
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: param: 基线请求失败: %w", err)
	}

	for _, variant := range variants {
		if p.budget <= 0 {
			break
		}
		if classes["sqli"] && !p.hits["sqli"] {
			p.probeSQLi(variant, original, baseline)
		}
		if p.budget <= 0 {
			break
		}
		if classes["ssti"] && !p.hits["ssti"] {
			p.probeSSTI(variant, original, baseline)
		}
		if p.budget <= 0 {
			break
		}
		// The wider classes are single-shot existence checks, not variants: they
		// place one payload, observe one signal, and stop.
		if classes["ssrf"] && !p.hits["ssrf"] {
			p.probeSSRF(original)
		}
		if p.budget <= 0 {
			break
		}
		if classes["path"] && !p.hits["path"] {
			p.probePathTraversal(original, argString(args, "marker"))
		}
		if p.budget <= 0 {
			break
		}
		if classes["cmdi"] && !p.hits["cmdi"] {
			p.probeCMDI(original)
		}
		if p.budget <= 0 {
			break
		}
		if classes["xxe"] && !p.hits["xxe"] {
			p.probeXXE(original)
		}
		if p.budget <= 0 {
			break
		}
		if classes["upload"] && !p.hits["upload"] {
			p.probeUpload(original)
		}
		if p.budget <= 0 {
			break
		}
		if classes["nosql"] && !p.hits["nosql"] {
			p.probeNoSQL(original)
		}
		if p.budget <= 0 {
			break
		}
		if classes["crlf"] && !p.hits["crlf"] {
			p.probeCRLF(original)
		}
		if p.budget <= 0 {
			break
		}
		if classes["header"] && !p.hits["header"] {
			p.probeHeaderReflection(original)
		}
	}

	label := "param"
	if adaptive {
		label = "param_adaptive"
	}
	switch {
	case p.probes == 0:
		// Nothing beyond the baseline succeeded: say the probe did not run rather
		// than concluding "no hit" from evidence we do not have.
		p.b.fact(fmt.Sprintf("参数探测未执行:%s(param: %s,classes: %s;没有成功的探测请求:请求预算耗尽或被 guard 拒绝)",
			rawURL, name, strings.Join(sortedClassNames(classes), "/")),
			respEvidence(baseline), label, "incomplete")
	case len(p.b.obs.Findings) == 0:
		p.b.fact(fmt.Sprintf("参数探测无命中:%s(param: %s,classes: %s)",
			rawURL, name, strings.Join(sortedClassNames(classes), "/")),
			respEvidence(baseline), label, "no-hit", "param")
	}
	p.b.setSummary(fmt.Sprintf("%s %s param=%s: %d 发现, %d 探测", label, rawURL, name,
		len(p.b.obs.Findings), p.probes))
	return p.b.obs, nil
}

// request spends one unit of the six-request budget and sends through the guard.
func (p *paramProbe) request(rawURL, purpose string) (*discipline.Response, error) {
	if p.budget <= 0 {
		return nil, fmt.Errorf("web: param: 请求预算已用尽")
	}
	p.budget--
	res, err := do(p.ctx, p.env, discipline.Request{
		Method:          "GET",
		URL:             rawURL,
		Headers:         p.headers,
		Purpose:         purpose,
		FollowRedirects: false,
	})
	if err != nil {
		return nil, err
	}
	p.b.requestID(res.RequestID)
	if purpose != "param:baseline" {
		p.probes++
	}
	return res, nil
}

func (p *paramProbe) probeSQLi(variant encodingVariant, original string, baseline *discipline.Response) {
	baselineBody := baseline.Text()
	baselineHasError := matchSQLSignature(baselineBody) != ""

	quoteURL, err := withQueryParam(p.rawURL, p.name, variant.apply(original+"'"))
	if err != nil {
		return
	}
	quote, err := p.request(quoteURL, "param:sqli:quote")
	if err != nil {
		return
	}
	if label := matchSQLSignature(quote.Text()); label != "" && !baselineHasError {
		p.hits["sqli"] = true
		where := whereParam(p.rawURL, p.name, variant.name)
		evidence := findingEvidence(quote)
		evidence["signature"] = label
		evidence["transform"] = variant.name
		p.b.fact(fmt.Sprintf("SQL 错误签名:%s param=%s", p.rawURL, p.name), evidence,
			"param", "sqli")
		p.b.finding(ledger.FindingSeed{
			Title:    fmt.Sprintf("参数 %s 触发 SQL 错误", p.name),
			Severity: "medium",
			Kind:     "sqli",
			Where:    where,
			Detail: fmt.Sprintf("注入单引号后响应命中数据库错误签名(%s);仅确认存在,未做数据提取。"+
				"需人工确认错误由该参数引起且没有统一错误页。", label),
			Evidence: evidence,
			Tags:     []string{"sqli", "param", transformTag(variant.name)},
		})
		return
	}

	// Boolean differential: one true condition, one false condition.
	if p.budget < 2 {
		return
	}
	trueURL, err := withQueryParam(p.rawURL, p.name, variant.apply(original+"' AND '1'='1"))
	if err != nil {
		return
	}
	falseURL, err := withQueryParam(p.rawURL, p.name, variant.apply(original+"' AND '1'='2"))
	if err != nil {
		return
	}
	trueRes, err := p.request(trueURL, "param:sqli:true")
	if err != nil {
		return
	}
	falseRes, err := p.request(falseURL, "param:sqli:false")
	if err != nil {
		return
	}
	simTrue := jaccardText(baselineBody, trueRes.Text())
	simFalse := jaccardText(baselineBody, falseRes.Text())
	simPair := jaccardText(trueRes.Text(), falseRes.Text())
	if !(simTrue > 0.85 && simFalse < 0.7 && simPair < 0.7 && simTrue-simFalse > 0.2) {
		return
	}
	p.hits["sqli"] = true
	where := whereParam(p.rawURL, p.name, variant.name)
	evidence := findingEvidence(trueRes)
	evidence["false_request_id"] = falseRes.RequestID
	evidence["transform"] = variant.name
	evidence["similarity"] = map[string]any{
		"true":  round4(simTrue),
		"false": round4(simFalse),
		"pair":  round4(simPair),
	}
	p.b.fact(fmt.Sprintf("布尔差分:%s param=%s", p.rawURL, p.name), evidence, "param", "sqli")
	p.b.finding(ledger.FindingSeed{
		Title:    fmt.Sprintf("参数 %s 存在布尔差分", p.name),
		Severity: "medium",
		Kind:     "sqli",
		Where:    where,
		Detail: fmt.Sprintf("真/假条件响应显著不同(与基线相似度 true=%.2f, false=%.2f, 两者=%.2f)。"+
			"动态页面与缓存可能造成假阳性,需人工复核;未提取任何数据。", simTrue, simFalse, simPair),
		Evidence: evidence,
		Tags:     []string{"sqli", "param", transformTag(variant.name)},
	})
}

func (p *paramProbe) probeSSTI(variant encodingVariant, original string, baseline *discipline.Response) {
	const expression = "{{7*7}}"
	if strings.Contains(original, expression) {
		return
	}
	payloadURL, err := withQueryParam(p.rawURL, p.name, variant.apply(original+expression))
	if err != nil {
		return
	}
	payload, err := p.request(payloadURL, "param:ssti:payload")
	if err != nil {
		return
	}
	payloadBody := payload.Text()
	baselineBody := baseline.Text()
	if !sqli49Rx.MatchString(payloadBody) || strings.Contains(payloadBody, expression) || sqli49Rx.MatchString(baselineBody) {
		return
	}

	// 49 appeared and the expression did not echo. A control expression guards
	// against "49 was already on the page" and proves evaluation, not reflection.
	controlURL, err := withQueryParam(p.rawURL, p.name, variant.apply(original+"{{7*6}}"))
	if err != nil {
		return
	}
	if p.budget < 1 {
		p.b.fact(fmt.Sprintf("参数探测未完成:%s(param: %s,ssti 控制请求受请求预算限制未执行)",
			p.rawURL, p.name), respEvidence(payload), "param", "ssti", "incomplete")
		return
	}
	control, err := p.request(controlURL, "param:ssti:control")
	if err != nil {
		return
	}
	controlBody := control.Text()
	if !sqli42Rx.MatchString(controlBody) || strings.Contains(controlBody, "{{7*6}}") || sqli42Rx.MatchString(baselineBody) {
		return
	}

	p.hits["ssti"] = true
	where := whereParam(p.rawURL, p.name, variant.name)
	evidence := findingEvidence(payload)
	evidence["control_request_id"] = control.RequestID
	evidence["transform"] = variant.name
	p.b.fact(fmt.Sprintf("模板求值:%s param=%s", p.rawURL, p.name), evidence, "param", "ssti")
	p.b.finding(ledger.FindingSeed{
		Title:    fmt.Sprintf("参数 %s 疑似模板注入", p.name),
		Severity: "high",
		Kind:     "ssti",
		Where:    where,
		Detail: "提交 {{7*7}} 后响应出现 49 且原式未回显;控制请求 {{7*6}} 返回 42,基线中没有 49/42。" +
			"这是模板求值证据,但未执行任何命令;执行证明需人工在授权范围内完成。",
		Evidence: evidence,
		Tags:     []string{"ssti", "param", transformTag(variant.name)},
	})
}

// ---- helpers ----------------------------------------------------------------

func normaliseProbeURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("web: parse url %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("web: url %q has no host", rawURL)
	}
	return u, nil
}

func normaliseClasses(in []string) (map[string]bool, error) {
	if len(in) == 0 {
		in = []string{"sqli", "ssti"}
	}
	out := map[string]bool{}
	for _, c := range in {
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "sqli", "ssti", "ssrf", "path", "cmdi", "xxe", "upload", "nosql", "crlf", "header":
			out[strings.ToLower(strings.TrimSpace(c))] = true
		case "deserialize":
			// Deliberate refusal: there is no safe existence probe for an unsafe
			// deserializer. "Send a gadget and see" is exploitation, not detection,
			// so this class is handed to a human instead.
			return nil, fmt.Errorf("web: 反序列化没有安全的存在性探针:youkai 不主动探测,请人工在授权下验证")
		default:
			return nil, fmt.Errorf("web: classes 支持 sqli/ssti/ssrf/path/cmdi/xxe/upload/nosql/crlf/header,收到 %q", c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("web: classes 不能为空")
	}
	return out, nil
}

func sortedClassNames(classes map[string]bool) []string {
	out := make([]string, 0, len(classes))
	for name := range classes {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

func matchSQLSignature(body string) string {
	for _, sig := range sqlSignatures {
		if sig.rx.MatchString(body) {
			return sig.label
		}
	}
	return ""
}

func whereParam(rawURL, name, transform string) string {
	suffix := ""
	if transform != "" && transform != "single" {
		suffix = ", transform: " + transform
	}
	return fmt.Sprintf("GET %s (param: %s%s)", rawURL, name, suffix)
}

func transformTag(name string) string {
	if name == "" || name == "single" {
		return "single-encoding"
	}
	return name + "-encoding"
}

func doubleURLEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func htmlEntityEncode(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func round4(v float64) float64 {
	return float64(int(v*10000+0.5)) / 10000
}
