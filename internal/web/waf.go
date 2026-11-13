package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// WAF behaviour analysis (tier 2).
//
// This is deliberately not a bypass tool. It sends a handful of benign marker
// shapes (a tag, a quote, a traversal-shaped string, a template expression) under
// standard encoding variants and records which ones the edge refuses and which
// reach the application. A difference means the WAF and the backend normalise
// differently - a hypothesis for a human to verify, not a payload to use.

const (
	defaultWAFProbes = 12
	maxWAFProbes     = 24
)

var wafBlockStatuses = map[int]bool{403: true, 406: true, 429: true, 501: true}

var wafGenericBlockRx = regexp.MustCompile(
	`(?i)web application firewall|request blocked|access denied|not acceptable|非法请求|请求被拦截|拦截`)

type wafShape struct {
	id    string
	label string
	make  func(marker string) string
}

var wafShapes = []wafShape{
	{"tag", "HTML 标签", func(m string) string { return "<" + m + ">" }},
	{"quote", "单引号", func(m string) string { return "'" + m }},
	{"traversal", "路径穿越", func(m string) string { return "../" + m }},
	{"template", "模板表达式", func(m string) string { return "{{7*7}}" + m }},
}

type wafSignature struct {
	vendor  string
	headers []string
	bodyRx  *regexp.Regexp
	cookie  *regexp.Regexp
}

// wafSignatures is a small, explicit fingerprint set: every entry is a header
// name, cookie name or literal block-page string, so a hit is inspectable.
var wafSignatures = []wafSignature{
	{"Cloudflare", []string{"cf-ray"}, regexp.MustCompile(`(?i)Attention Required!?\s*\|\s*Cloudflare`), regexp.MustCompile(`(?i)^__cf_bm$`)},
	{"Akamai", []string{"akamai-grn", "x-akamai-request-id"}, regexp.MustCompile(`(?i)Access Denied[\s\S]{0,80}akamai`), nil},
	{"Imperva", []string{"x-iinfo"}, regexp.MustCompile(`Incapsula`), regexp.MustCompile(`(?i)^(visid_incap_|incap_ses_)`)},
	{"F5 BIG-IP", []string{"x-wa-info"}, regexp.MustCompile(`(?i)The requested URL was rejected`), nil},
	{"Sucuri", []string{"x-sucuri-id"}, regexp.MustCompile(`(?i)Sucuri WebSite Firewall`), nil},
	{"FortiWeb", nil, regexp.MustCompile(`FortiWeb`), regexp.MustCompile(`(?i)^FORTIWAFSID$`)},
	{"Azure Front Door", []string{"x-azure-ref"}, regexp.MustCompile(`(?i)Azure Front Door`), nil},
	{"ModSecurity", nil, regexp.MustCompile(`(?i)ModSecurity|Not Acceptable!?[\s\S]{0,80}Apache`), nil},
	{"Barracuda", nil, regexp.MustCompile(`Barracuda`), regexp.MustCompile(`(?i)^barra_counter_session$`)},
	{"Aliyun WAF", nil, regexp.MustCompile(`(?i)errors\.aliyun\.com|aliyun[\s\S]{0,40}(block|拦截)`), nil},
	{"Tencent Cloud WAF", nil, regexp.MustCompile(`腾讯云|waf\.tencent`), nil},
	{"SafeLine", nil, regexp.MustCompile(`SafeLine|雷池`), nil},
	{"Safedog", nil, regexp.MustCompile(`安全狗|safedog`), nil},
}

func runWAF(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	param, err := requiredString(args, "param")
	if err != nil {
		return ledger.Observation{}, err
	}
	g, err := guardOf(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	scope := g.Scope()
	if scope == nil || !scope.AllowWAFProbe {
		return ledger.Observation{}, fmt.Errorf(
			"web: WAF 行为分析未授权:在 scope 里设置 allow_waf_probe=true 后重试(该能力会向目标发少量带标记的请求)")
	}
	maxProbes := clamp(argInt(args, "max_probes", defaultWAFProbes), 1, maxWAFProbes)
	headers := argStringMap(args, "headers")
	marker := newMarker("youkaiwaf")

	b := newObs()
	baselineURL, err := withQueryParam(rawURL, param, marker)
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: waf: %w", err)
	}
	baseline, err := do(ctx, env, discipline.Request{
		Method: "GET", URL: baselineURL, Headers: headers,
		Purpose: "waf:baseline", FollowRedirects: false,
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: waf: 基线请求失败: %w", err)
	}
	b.requestID(baseline.RequestID)
	baselineVendor, baselineConfidence, baselineEvidence := fingerprintWAF(baseline)

	type wafRow struct {
		shape     string
		transform string
		blocked   bool
		passed    bool
		vendor    string
	}

	rows := make([]wafRow, 0, maxProbes)
	blockedCount := 0
	firstBlockedID := ""
	firstBlockedStatus := 0

outer:
	for _, shape := range wafShapes {
		for _, variant := range encodingVariants {
			if len(rows) >= maxProbes {
				break outer
			}
			probeURL, err := withQueryParam(rawURL, param, variant.apply(shape.make(marker)))
			if err != nil {
				continue
			}
			res, err := do(ctx, env, discipline.Request{
				Method: "GET", URL: probeURL, Headers: headers,
				Purpose: "waf:probe", FollowRedirects: false,
			})
			if err != nil {
				continue
			}
			b.requestID(res.RequestID)
			vendor, _, _ := fingerprintWAF(res)
			blocked := wafLooksBlocked(res, baseline, vendor)
			row := wafRow{
				shape:     shape.id,
				transform: variant.name,
				blocked:   blocked,
				passed:    !blocked && res.Status < 400,
				vendor:    vendor,
			}
			if blocked {
				blockedCount++
				if firstBlockedID == "" {
					firstBlockedID = res.RequestID
					firstBlockedStatus = res.Status
				}
			}
			rows = append(rows, row)
		}
	}

	vendor := baselineVendor
	confidence := baselineConfidence
	evidence := append([]string(nil), baselineEvidence...)
	for _, row := range rows {
		if !row.blocked {
			continue
		}
		if vendor == "" && row.vendor != "" {
			vendor = row.vendor
			confidence = "medium"
		}
		if row.vendor != "" {
			evidence = append(evidence, "block page: "+row.vendor)
		}
	}
	evidence = dedupeTags(evidence)

	// Per-shape observation, kept as strings because it is a human-readable
	// profile, not a data structure the ledger has to understand.
	var observations []string
	normalizationGap := false
	for _, shape := range wafShapes {
		rawBlocked := false
		var passed []string
		var blocked []string
		for _, row := range rows {
			if row.shape != shape.id {
				continue
			}
			if row.blocked {
				blocked = append(blocked, row.transform)
				if row.transform == "single" {
					rawBlocked = true
				}
			}
			if row.passed && row.transform != "single" {
				passed = append(passed, row.transform)
			}
		}
		switch {
		case rawBlocked && len(passed) > 0:
			normalizationGap = true
			observations = append(observations, fmt.Sprintf("%s:单次编码被拦截;%s 通过(规范化差异)",
				shape.label, strings.Join(passed, "/")))
		case rawBlocked:
			observations = append(observations, shape.label+":所有变体均被拦截")
		case len(blocked) > 0:
			observations = append(observations, shape.label+":部分编码被拦截")
		default:
			observations = append(observations, shape.label+":未见拦截")
		}
	}

	verdict := "no-waf-signal"
	switch {
	case normalizationGap:
		verdict = "normalization-gap"
	case blockedCount > 0:
		verdict = "waf-present"
	case vendor != "":
		verdict = "waf-fingerprint-only"
	}

	if len(rows) == 0 {
		b.fact(fmt.Sprintf("WAF 分析未执行:%s param=%s(所有探针请求都失败)", rawURL, param),
			respEvidence(baseline), "waf", "incomplete")
		b.setSummary(fmt.Sprintf("waf %s param=%s: 未执行", rawURL, param))
		return b.obs, nil
	}

	profileEvidence := respEvidence(baseline)
	profileEvidence["param"] = param
	profileEvidence["verdict"] = verdict
	profileEvidence["vendor"] = vendor
	profileEvidence["confidence"] = confidence
	profileEvidence["probes"] = len(rows)
	profileEvidence["blocked"] = blockedCount
	profileEvidence["normalization_gap"] = normalizationGap
	profileEvidence["observations"] = observations
	if len(evidence) > 0 {
		profileEvidence["waf_evidence"] = evidence
	}
	b.fact(fmt.Sprintf("WAF 画像:%s param=%s -> %s", rawURL, param, verdict), profileEvidence,
		"waf", verdict)

	if vendor != "" && blockedCount > 0 {
		severity := "low"
		if normalizationGap {
			severity = "medium"
		}
		findingEv := map[string]any{
			"request_id": firstBlockedID,
			"status":     firstBlockedStatus,
			"url":        rawURL,
			"param":      param,
			"vendor":     vendor,
			"blocked":    blockedCount,
			"probes":     len(rows),
		}
		b.finding(ledger.FindingSeed{
			Title:    "WAF 拦截页可指纹:" + vendor,
			Severity: severity,
			Kind:     "waf",
			Where:    rawURL,
			Detail: fmt.Sprintf("%d/%d 个探针被拦截页拦截,可指纹为 %s(置信度 %s)。"+
				"规范化差异=%t;这只说明边界与后端解码可能不一致,不等于可绕过,验证必须由人工在授权范围内完成。",
				blockedCount, len(rows), vendor, confidence, normalizationGap),
			Evidence: findingEv,
			Tags:     []string{"waf", "fingerprint"},
		})
	}

	b.setSummary(fmt.Sprintf("waf %s param=%s -> %s (%d/%d 拦截)",
		rawURL, param, verdict, blockedCount, len(rows)))
	return b.obs, nil
}

func wafLooksBlocked(res, baseline *discipline.Response, vendor string) bool {
	if res == nil || !wafBlockStatuses[res.Status] {
		return false
	}
	if vendor != "" {
		return true
	}
	if wafGenericBlockRx.MatchString(res.Text()) {
		return true
	}
	return baseline != nil && baseline.Status < 400 && res.Status != baseline.Status
}

// fingerprintWAF returns the first matching vendor, its confidence, and every
// piece of evidence that matched. The first match is the best one by ordering.
func fingerprintWAF(res *discipline.Response) (string, string, []string) {
	if res == nil {
		return "", "", nil
	}
	vendor := ""
	confidence := ""
	var evidence []string
	for _, sig := range wafSignatures {
		matched := false
		for _, name := range sig.headers {
			if v := headerGet(res.Header, name); v != "" {
				matched = true
				evidence = append(evidence, "header "+name)
			}
		}
		if sig.cookie != nil {
			for _, name := range cookieNames(headerGet(res.Header, "Set-Cookie")) {
				if sig.cookie.MatchString(name) {
					matched = true
					evidence = append(evidence, "cookie "+name)
				}
			}
		}
		if sig.bodyRx != nil && sig.bodyRx.MatchString(res.Text()) {
			matched = true
			evidence = append(evidence, "body: "+sig.vendor)
		}
		if matched && vendor == "" {
			vendor = sig.vendor
			confidence = "medium"
		}
	}
	if vendor != "" {
		confidence = "high"
	}
	return vendor, confidence, evidence
}
