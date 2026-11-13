package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// The scan sweep: one page, a bounded set of checks, every claim tied to the
// audit row that produced it. The thin capabilities (headers, cors, exposures,
// redirect_check) are the same helpers with a one-check budget, so the UI can
// run exactly what it needs without paying for the whole sweep.

const (
	// canaryOrigin can never belong to the target, so an echoed ACAO is proof
	// the server allows arbitrary origins.
	canaryOrigin = "https://youkai-canary.invalid"
	// maxExposurePaths bounds the extra requests a scan may spend on exposures.
	maxExposurePaths = 8
	// maxReflectionParams bounds the extra requests a scan may spend on
	// reflection probes: at most one GET per parameter, three parameters total.
	maxReflectionParams = 3
)

var envLineRx = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{1,}=`)

type exposureCheck struct {
	path     string
	severity string
	title    string
	detail   string
	match    func([]byte) bool
}

// exposureChecks is deliberately short: each item is cheap, read-only, and has a
// content signature so a generic 200 (soft 404) cannot become a finding.
var exposureChecks = []exposureCheck{
	{
		path:     "/.git/config",
		severity: "high",
		title:    "Git 配置可读",
		detail:   "路径返回 200 且正文命中 Git 配置格式([core]/[remote]);仓库结构可能因此泄露。",
		match: func(b []byte) bool {
			return bytes.Contains(b, []byte("[core]")) || bytes.Contains(b, []byte("[remote"))
		},
	},
	{
		path:     "/.env",
		severity: "high",
		title:    "环境变量文件暴露",
		detail:   "路径返回 200 且正文命中环境变量行格式;可能包含凭据,已停止,不再拉取。",
		match: func(b []byte) bool {
			return envLineRx.Match(b)
		},
	},
	{
		path:     "/backup.zip",
		severity: "high",
		title:    "备份压缩包可下载",
		detail:   "路径返回 200 且正文带 ZIP 头(PK);可能包含源码或数据库备份,只确认存在,不下载。",
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("PK"))
		},
	},
	{
		path:     "/server-status",
		severity: "medium",
		title:    "Apache server-status 暴露",
		detail:   "路径返回 200 且正文为 Apache 状态页;会泄露请求路径与客户端地址。",
		match: func(b []byte) bool {
			return bytes.Contains(bytes.ToLower(b), []byte("apache server status"))
		},
	},
	{
		path:     "/.DS_Store",
		severity: "medium",
		title:    "macOS .DS_Store 暴露",
		detail:   "路径返回 200 且正文含 Bud1 签名;会泄露目录内文件名。",
		match: func(b []byte) bool {
			return bytes.Contains(b, []byte("Bud1"))
		},
	},
	{
		path:     "/WEB-INF/web.xml",
		severity: "high",
		title:    "WEB-INF/web.xml 暴露",
		detail:   "路径返回 200 且正文为 web.xml;Java 应用配置(含安全约束)可读。",
		match: func(b []byte) bool {
			return bytes.Contains(b, []byte("<web-app"))
		},
	},
}

type securityHeaderRule struct {
	name   string
	label  string
	detail string
	hsts   bool
}

var securityHeaderRules = []securityHeaderRule{
	{name: "Content-Security-Policy", label: "CSP", detail: "缺少内容安全策略,削弱 XSS 纵深防御。"},
	{name: "X-Frame-Options", label: "X-Frame-Options", detail: "缺少点击劫持防护。"},
	{name: "X-Content-Type-Options", label: "X-Content-Type-Options", detail: "缺少 MIME 嗅探防护(应为 nosniff)。"},
	{name: "Referrer-Policy", label: "Referrer-Policy", detail: "缺少引用来源策略,令牌可能随 Referer 外泄。"},
	{name: "Strict-Transport-Security", label: "HSTS", detail: "缺少 HSTS,HTTPS 可被降级。", hsts: true},
}

// scanCtx carries the URL being swept and the builder findings land in.
type scanCtx struct {
	url   string
	label string // "scan", "headers", ...; used in fact statements and purposes
	b     *obsBuilder
}

func newScanCtx(rawURL, label string) *scanCtx {
	return &scanCtx{url: rawURL, label: label, b: newObs()}
}

// add records a candidate finding and the fact that mirrors it. The two always
// share the evidence, so they can never drift onto different requests.
func (s *scanCtx) add(title, severity, kind, where, detail string, evidence map[string]any, tags ...string) {
	allTags := dedupeTags(append([]string{s.label, kind}, tags...))
	s.b.finding(ledger.FindingSeed{
		Title:    title,
		Severity: severity,
		Kind:     kind,
		Where:    where,
		Detail:   detail,
		Evidence: evidence,
		Tags:     allTags,
	})
	s.b.fact(fmt.Sprintf("%s 候选(%s): %s @ %s", s.label, severity, title, where), evidence, allTags...)
}

// securityHeaders reports whether it could run (HTML + non-error status).
func (s *scanCtx) securityHeaders(res *discipline.Response) bool {
	if res.Status >= 400 || !isHTMLResponse(res) {
		return false
	}
	final := res.FinalURL
	if final == "" {
		final = res.URL
	}
	https := strings.HasPrefix(strings.ToLower(final), "https://")

	for _, rule := range securityHeaderRules {
		if rule.hsts && !https {
			continue
		}
		if headerGet(res.Header, rule.name) != "" {
			continue
		}
		s.add("缺失安全响应头:"+rule.label, "low", "header-missing", s.url, rule.detail,
			findingEvidence(res), rule.name)
	}
	// A header that exists but says the wrong thing is its own finding.
	if v := headerGet(res.Header, "X-Content-Type-Options"); v != "" && !strings.Contains(strings.ToLower(v), "nosniff") {
		s.add("X-Content-Type-Options 非 nosniff", "low", "header-missing", s.url,
			"当前值为 "+v+";应为 nosniff。", findingEvidence(res))
	}
	return true
}

// cookies evaluates Set-Cookie security attributes.
//
// The guard redacts only the cookie VALUE and keeps the attributes
// ("sid=<redacted>; Path=/; HttpOnly; Secure"), so the flags are observable and
// the value can never reach evidence. Each missing flag is its own candidate
// finding; the evidence cites the cookie NAME and its attributes, never a value.
func (s *scanCtx) cookies(res *discipline.Response) {
	raw := headerGet(res.Header, "Set-Cookie")
	if raw == "" {
		return
	}
	flags, ok := parseCookieFlags(raw)
	if !ok {
		// There is a Set-Cookie header but no name could be parsed: say the
		// judgement did not run instead of inventing flags.
		s.b.fact(fmt.Sprintf("cookie 安全属性未判定:%s", s.url), map[string]any{
			"request_id": res.RequestID,
			"url":        res.URL,
			"status":     res.Status,
			"reason":     "Set-Cookie 存在但无法解析出 Cookie 名",
		}, s.label, "cookie", "incomplete")
		return
	}

	https := responseIsHTTPS(res)
	for _, cf := range flags {
		cookieEvidence := func(attribute string) map[string]any {
			ev := findingEvidence(res)
			ev["cookie"] = cf.name
			ev["attribute"] = attribute
			return ev
		}

		if !cf.httpOnly {
			s.add(fmt.Sprintf("Cookie %s 缺少 HttpOnly", cf.name), "medium", "cookie", s.url,
				"会话 Cookie 可被脚本读取(document.cookie),发生 XSS 时可直接窃取。",
				cookieEvidence("HttpOnly"), "cookie", "httponly")
		}
		if !cf.secure {
			if https {
				s.add(fmt.Sprintf("Cookie %s 缺少 Secure", cf.name), "medium", "cookie", s.url,
					"HTTPS 页面设置的 Cookie 未带 Secure,可能随明文请求发送。",
					cookieEvidence("Secure"), "cookie", "secure")
			} else {
				s.add(fmt.Sprintf("Cookie %s 通过明文 HTTP 设置", cf.name), "info", "cookie", s.url,
					"目标以 http 提供服务且 Cookie 未带 Secure;凭证可能随明文请求发送。",
					cookieEvidence("Secure"), "cookie", "secure")
			}
		}
		switch {
		case cf.sameSite == "":
			s.add(fmt.Sprintf("Cookie %s 缺少 SameSite", cf.name), "low", "cookie", s.url,
				"缺少 SameSite 限制,跨站请求可能自动携带该 Cookie(CSRF 纵深防御缺失)。",
				cookieEvidence("SameSite"), "cookie", "samesite")
		case strings.EqualFold(cf.sameSite, "none") && !cf.secure:
			s.add(fmt.Sprintf("Cookie %s SameSite=None 但未设置 Secure", cf.name), "medium", "cookie", s.url,
				"SameSite=None 且缺少 Secure:现代浏览器会拒绝该 Cookie,跨站发送也不受 SameSite 限制。",
				cookieEvidence("SameSite"), "cookie", "samesite")
		}
	}
}

// responseIsHTTPS judges transport from the final URL the guard actually talked
// to, so an http->https redirect is not misread as plaintext.
func responseIsHTTPS(res *discipline.Response) bool {
	final := res.FinalURL
	if final == "" {
		final = res.URL
	}
	return strings.HasPrefix(strings.ToLower(final), "https://")
}

// redirects records the hop chain and flags plaintext HTTP in the clear.
func (s *scanCtx) redirects(res *discipline.Response) {
	final := res.FinalURL
	if final == "" {
		final = res.URL
	}
	ev := respEvidence(res)
	ev["final_url"] = final
	ev["hops"] = len(res.Redirects)
	if len(res.Redirects) > 0 {
		chain := make([]map[string]any, 0, len(res.Redirects))
		for _, hop := range res.Redirects {
			s.b.requestID(hop.RequestID)
			chain = append(chain, map[string]any{
				"url":        hop.URL,
				"status":     hop.Status,
				"request_id": hop.RequestID,
			})
		}
		ev["chain"] = chain
	}
	s.b.fact(fmt.Sprintf("重定向链:%s -> %s (%d 跳)", res.URL, final, len(res.Redirects)), ev,
		s.label, "redirect")

	// Plaintext transport is only interesting when the network is real.
	host := discipline.HostOf(res.URL)
	if strings.HasPrefix(strings.ToLower(res.URL), "http://") &&
		!strings.HasPrefix(strings.ToLower(final), "https://") &&
		!isLoopbackHost(host) {
		s.add("明文 HTTP 传输", "medium", "transport", s.url,
			"页面通过 http 提供且未见 https 跳转;凭证与数据可被中间人读取。",
			findingEvidence(res), "transport")
	}
}

// versionDisclosure reports banner versions, which are information, not a vuln.
func (s *scanCtx) versionDisclosure(res *discipline.Response) {
	if server := headerGet(res.Header, "Server"); server != "" && versionRx.MatchString(server) {
		s.add("服务端版本号暴露", "info", "version-disclosure", s.url,
			"Server: "+server+" —— 可辅助匹配已知 CVE,建议隐藏版本。", findingEvidence(res))
	}
	if powered := headerGet(res.Header, "X-Powered-By"); powered != "" {
		s.add("X-Powered-By 暴露技术栈", "info", "version-disclosure", s.url,
			"X-Powered-By: "+powered, findingEvidence(res))
	}
}

// corsProbe asks the target about one impossible origin and judges the answer.
func (s *scanCtx) corsProbe(ctx context.Context, env *Env, headers map[string]string) (*discipline.Response, error) {
	h := cloneHeaders(headers)
	h["Origin"] = canaryOrigin
	res, err := do(ctx, env, discipline.Request{
		Method:          "GET",
		URL:             s.url,
		Headers:         h,
		Purpose:         s.label + ":cors",
		FollowRedirects: false,
	})
	if err != nil {
		return nil, err
	}
	acao := headerGet(res.Header, "Access-Control-Allow-Origin")
	acac := headerGet(res.Header, "Access-Control-Allow-Credentials")
	if acao == "*" || strings.EqualFold(strings.TrimSpace(acao), canaryOrigin) {
		severity := "medium"
		title := "CORS 允许任意源"
		acacText := acac
		if acacText == "" {
			acacText = "未设置"
		}
		detail := fmt.Sprintf("ACAO=%s, ACAC=%s —— 任意源可读取响应", acao, acacText)
		if strings.EqualFold(strings.TrimSpace(acac), "true") {
			severity = "high"
			title = "CORS 允许任意源且携带凭证"
			detail += ",且允许携带凭证(高危)"
		}
		s.add(title, severity, "cors", s.url, detail, findingEvidence(res))
	}
	return res, nil
}

// reflections tests up to three query parameters for direct reflection and stops
// at the first hit.
//
// The marker is a plain `youkai<hex8>` string with no metacharacters: it can show
// that a value reaches the response, but it is not a payload. A reflection alone
// is not a vulnerability, so the finding is a candidate that points the tier-2
// hand-off (fact tag `param-candidate`) at a parameter worth a browser context
// check. Returns the number of guarded probes spent.
func (s *scanCtx) reflections(ctx context.Context, env *Env, headers map[string]string) int {
	u, err := url.Parse(s.url)
	if err != nil || u.RawQuery == "" {
		return 0
	}
	names := sortedKeys(u.Query())
	if len(names) > maxReflectionParams {
		names = names[:maxReflectionParams]
	}

	probes := 0
	for _, name := range names {
		marker := reflectionMarker()
		probeURL, err := withQueryParam(s.url, name, marker)
		if err != nil {
			continue
		}
		res, err := do(ctx, env, discipline.Request{
			Method:          "GET",
			URL:             probeURL,
			Headers:         headers,
			Purpose:         s.label + ":reflection",
			FollowRedirects: true,
		})
		if err != nil {
			continue
		}
		probes++
		s.b.requestID(res.RequestID)
		if res.Status >= 400 || !strings.Contains(res.Text(), marker) {
			continue
		}

		where := fmt.Sprintf("GET %s (param: %s)", probeURL, name)
		s.add(fmt.Sprintf("参数 %s 的值反射进响应", name), "medium", "reflection", where,
			"标记原样出现在响应中。反射本身不是漏洞;需在浏览器中确认标记落点能否逃逸当前上下文后才能定级。",
			findingEvidence(res), "reflection")

		factEvidence := findingEvidence(res)
		factEvidence["where"] = where
		factEvidence["url"] = probeURL
		s.b.fact("参数反射待浏览器复核:"+where, factEvidence, "reflects", "param-candidate")
		return probes // stop after the first hit
	}
	return probes
}

// reflectionMarker is `youkai` + 8 hex characters: unique per probe, and safe to
// put in a query string without escaping.
func reflectionMarker() string {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "youkai00000000"
	}
	return "youkai" + hex.EncodeToString(raw[:])
}

// exposures probes the bounded sensitive-path list against the URL's origin.
// Extra requests are GET only and each hit names its own request_id.
func (s *scanCtx) exposures(ctx context.Context, env *Env, headers map[string]string, only []string) (*discipline.Response, int) {
	base := originOf(s.url)
	if base == "" {
		return nil, 0
	}
	checks := selectExposures(only)
	var first *discipline.Response
	probes := 0
	for _, check := range checks {
		probeURL := base + check.path
		res, err := do(ctx, env, discipline.Request{
			Method:          "GET",
			URL:             probeURL,
			Headers:         headers,
			Purpose:         s.label + ":exposure",
			FollowRedirects: false,
		})
		if err != nil {
			// A single failed probe is not a claim; it stays out of evidence and
			// is counted in the summary instead.
			continue
		}
		probes++
		s.b.requestID(res.RequestID)
		if first == nil {
			first = res
		}
		if res.Status != 200 || !check.match(res.Body) {
			continue
		}
		s.add(check.title, check.severity, "exposure", probeURL, check.detail,
			findingEvidence(res), "exposure")
	}
	return first, probes
}

func selectExposures(only []string) []exposureCheck {
	if len(only) == 0 {
		out := make([]exposureCheck, len(exposureChecks))
		copy(out, exposureChecks)
		if len(out) > maxExposurePaths {
			out = out[:maxExposurePaths]
		}
		return out
	}
	want := map[string]bool{}
	for _, p := range only {
		want[strings.TrimSpace(p)] = true
	}
	var out []exposureCheck
	for _, check := range exposureChecks {
		if want[check.path] {
			out = append(out, check)
		}
		if len(out) >= maxExposurePaths {
			break
		}
	}
	return out
}

// ---- capability entry points ------------------------------------------------

func runScan(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	headers := argStringMap(args, "headers")
	res, err := do(ctx, env, discipline.Request{
		Method:          "GET",
		URL:             rawURL,
		Headers:         headers,
		Purpose:         "scan",
		FollowRedirects: argBool(args, "follow_redirects", true),
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: scan: %w", err)
	}

	s := newScanCtx(rawURL, "scan")
	s.b.requestID(res.RequestID)
	s.b.asset("surface", "surface:"+rawURL)

	if !s.securityHeaders(res) {
		s.b.fact(fmt.Sprintf("安全响应头检查跳过:%s(响应非 HTML 或状态 >= 400)", rawURL),
			respEvidence(res), "scan", "incomplete")
	}
	s.cookies(res)
	s.redirects(res)
	s.versionDisclosure(res)

	corsRes, corsErr := s.corsProbe(ctx, env, headers)
	if corsErr == nil && corsRes != nil {
		s.b.requestID(corsRes.RequestID)
	}

	reflectionProbes := s.reflections(ctx, env, headers)

	_, probes := s.exposures(ctx, env, headers, nil)
	if probes == 0 {
		// The sweep could not spend its exposure probes; record that instead of
		// letting "no exposure finding" imply "no exposure".
		s.b.fact(fmt.Sprintf("暴露面探测未执行:%s(所有探测请求都失败)", rawURL),
			respEvidence(res), "scan", "incomplete")
	}

	summary := fmt.Sprintf("scan %s: %d 发现, %d 请求, %d 暴露面探测, %d 反射探测",
		rawURL, len(s.b.obs.Findings), len(s.b.obs.RequestIDs), probes, reflectionProbes)
	if corsErr != nil {
		summary += "; CORS 检查未执行"
	}
	s.b.setSummary(summary)
	return s.b.obs, nil
}

func runHeaders(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	res, err := do(ctx, env, discipline.Request{
		Method:          "GET",
		URL:             rawURL,
		Headers:         argStringMap(args, "headers"),
		Purpose:         "headers",
		FollowRedirects: argBool(args, "follow_redirects", true),
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: headers: %w", err)
	}

	s := newScanCtx(rawURL, "headers")
	s.b.requestID(res.RequestID)
	if !s.securityHeaders(res) {
		// Say it did not run: a non-HTML or error response has no meaningful
		// security-header judgement.
		s.b.fact(fmt.Sprintf("安全响应头检查未执行:%s(响应非 HTML 或状态 >= 400)", rawURL),
			respEvidence(res), "headers")
	}
	s.versionDisclosure(res)
	s.b.setSummary(fmt.Sprintf("headers %s -> HTTP %d", rawURL, res.Status))
	return s.b.obs, nil
}

func runCORS(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	s := newScanCtx(rawURL, "cors")
	res, err := s.corsProbe(ctx, env, argStringMap(args, "headers"))
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: cors: %w", err)
	}
	s.b.requestID(res.RequestID)
	acao := headerGet(res.Header, "Access-Control-Allow-Origin")
	if acao == "" {
		acao = "未设置"
	}
	s.b.fact(fmt.Sprintf("CORS 检查:%s ACAO=%s", rawURL, acao), respEvidence(res), "cors")
	s.b.setSummary(fmt.Sprintf("cors %s -> ACAO=%s", rawURL, acao))
	return s.b.obs, nil
}

func runExposures(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	s := newScanCtx(rawURL, "exposures")
	first, probes := s.exposures(ctx, env, argStringMap(args, "headers"), argStringSlice(args, "paths"))
	if probes == 0 {
		return ledger.Observation{}, fmt.Errorf("web: exposures: 没有一次探测请求成功(检查 scope、方法授权与目标可达性)")
	}
	if len(s.b.obs.Findings) == 0 {
		s.b.fact(fmt.Sprintf("暴露面探测未命中:%s(已探测 %d 条路径)", rawURL, probes),
			respEvidence(first), "exposures")
	}
	s.b.setSummary(fmt.Sprintf("exposures %s: %d 路径, %d 命中", rawURL, probes, len(s.b.obs.Findings)))
	return s.b.obs, nil
}

func runRedirectCheck(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	res, err := do(ctx, env, discipline.Request{
		Method:          "GET",
		URL:             rawURL,
		Headers:         argStringMap(args, "headers"),
		Purpose:         "redirect_check",
		FollowRedirects: true,
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: redirect_check: %w", err)
	}
	s := newScanCtx(rawURL, "redirect_check")
	s.b.requestID(res.RequestID)
	s.redirects(res)
	s.b.setSummary(fmt.Sprintf("redirect_check %s: %d 跳 -> %s", rawURL, len(res.Redirects), res.FinalURL))
	return s.b.obs, nil
}

// ---- cookie parsing ---------------------------------------------------------

type cookieFlags struct {
	name     string
	httpOnly bool
	secure   bool
	sameSite string
}

// parseCookieFlags reads the guard's sanitised Set-Cookie header.
//
// The header is already `name=<redacted>; Path=/; HttpOnly; Secure; SameSite=...`,
// with multiple cookies joined by "; ". A new cookie starts at any `key=value`
// segment whose key is not a known attribute; the value is ignored entirely (it
// is the redaction placeholder), so no credential can be reconstructed.
//
// ok=false means the header existed but no cookie name could be parsed; the
// caller must then report that the judgement did not run.
func parseCookieFlags(raw string) (flags []cookieFlags, ok bool) {
	var cur *cookieFlags
	flush := func() {
		if cur != nil && cur.name != "" {
			flags = append(flags, *cur)
		}
		cur = nil
	}
	for _, segment := range strings.Split(raw, ";") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		key, value, hasEq := strings.Cut(segment, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if hasEq {
			switch strings.ToLower(key) {
			case "samesite":
				if cur != nil {
					cur.sameSite = value
				}
				continue
			case "path", "domain", "expires", "max-age", "priority", "partitioned",
				"comment", "version":
				continue
			}
			flush()
			cur = &cookieFlags{name: key}
			continue
		}
		switch strings.ToLower(key) {
		case "secure":
			if cur != nil {
				cur.secure = true
			}
		case "httponly":
			if cur != nil {
				cur.httpOnly = true
			}
		}
	}
	flush()
	return flags, len(flags) > 0
}
