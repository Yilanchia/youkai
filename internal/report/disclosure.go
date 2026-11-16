package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// Disclosure is the document you send to a vendor or a bug bounty programme.
//
// It is deliberately narrower than the report:
//
//   - only `verified` findings - youkai does not tell a vendor that a guess is a
//     vulnerability;
//   - no response bodies, no credentials, no markers: the evidence section points
//     at request ids that the authorised party can pull from the audit trail;
//   - a fixed authorisation statement with the passport summary, because a
//     disclosure that does not say "you authorised this" is just an accusation.
//
// With no verified findings, or with no passport basis, it refuses to produce a
// hollow document and says why.

// ErrNoVerified is returned when there is nothing verified to disclose.
type ErrNoVerified struct{}

func (ErrNoVerified) Error() string {
	return "尚无已验证发现:披露包只收 verified,候选发现不进披露包"
}

// ErrNoAuthorisation is returned when the passport cannot back the disclosure.
type ErrNoAuthorisation struct{ Reason string }

func (e ErrNoAuthorisation) Error() string {
	return "无法生成披露包:授权依据缺失或不完整(" + e.Reason + ")"
}

// Disclosable returns the verified findings with all four evidence pieces present.
func Disclosable(b Bundle) []FindingReport {
	var out []FindingReport
	for _, f := range b.Findings {
		if f.Disclosable {
			out = append(out, f)
		}
	}
	return out
}

// DisclosureMarkdown renders the disclosure document.
func DisclosureMarkdown(b Bundle, scope ScopeSummary) (string, error) {
	items, err := disclosureItems(b, scope)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# 安全披露 — %s\n\n", b.Engagement)
	sb.WriteString("## 授权声明\n\n")
	writeAuthStatementMD(&sb, scope)
	sb.WriteString("\n## 发现\n\n")
	for i, f := range items {
		writeDisclosureFindingMD(&sb, i+1, f)
	}
	sb.WriteString("\n## 证据调取\n\n")
	sb.WriteString("每条发现都标注了 `request_id`。这些请求的完整审计记录(时间、方法、URL、状态、判定)保存在测试方的账本中,\n")
	sb.WriteString("授权方可以按 `request_id` 索取。本文件不含响应正文、不含任何凭据。\n\n")
	sb.WriteString("---\n本文件由 youkai 从只读证据台账生成;定级为**估计值**,正式定级需双方确认。\n")
	return sb.String(), nil
}

// DisclosureHTML renders the same document, self-contained.
func DisclosureHTML(b Bundle, scope ScopeSummary) (string, error) {
	items, err := disclosureItems(b, scope)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	fmt.Fprintf(&sb, "<title>安全披露 — %s</title>", html.EscapeString(b.Engagement))
	sb.WriteString("<style>body{font-family:-apple-system,\"Segoe UI\",Roboto,\"Noto Sans SC\",sans-serif;max-width:860px;margin:0 auto;padding:32px 20px;color:#1a1a1a;line-height:1.6}")
	sb.WriteString("h1{font-size:24px}h2{font-size:18px;margin-top:28px;border-bottom:1px solid #e5e5e5;padding-bottom:6px}h3{font-size:16px;margin-top:20px}")
	sb.WriteString("table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}th,td{border-bottom:1px solid #eee;padding:5px 8px;text-align:left}")
	sb.WriteString(".card{border:1px solid #e5e5e5;border-radius:8px;padding:14px 16px;margin:14px 0}.muted{color:#666}")
	sb.WriteString(".cvss{font-family:ui-monospace,Menlo,Consolas,monospace;background:#f3f3f3;padding:1px 6px;border-radius:4px}")
	sb.WriteString("footer{margin-top:30px;color:#888;font-size:12px;border-top:1px solid #eee;padding-top:10px}</style></head><body>")
	fmt.Fprintf(&sb, "<h1>安全披露 — %s</h1>", html.EscapeString(b.Engagement))

	sb.WriteString("<h2>授权声明</h2>")
	writeAuthStatementHTML(&sb, scope)

	fmt.Fprintf(&sb, "<h2>发现(%d)</h2>", len(items))
	for i, f := range items {
		fmt.Fprintf(&sb, "<div class=\"card\"><h3>%d. %s</h3>", i+1, html.EscapeString(f.Title))
		fmt.Fprintf(&sb, "<p><span class=\"cvss\">CVSS %s(估计)</span> · 严重度:%s · 类型:%s</p>",
			html.EscapeString(estimateCVSS(f.Severity)), html.EscapeString(f.Severity), html.EscapeString(dash(f.Kind)))
		fmt.Fprintf(&sb, "<p><strong>影响</strong>:%s</p>", html.EscapeString(firstNonEmpty(f.Detail, f.MinImpact)))
		fmt.Fprintf(&sb, "<p><strong>复现</strong>:</p><ol>")
		for _, step := range reproSteps(f) {
			fmt.Fprintf(&sb, "<li>%s</li>", html.EscapeString(step))
		}
		sb.WriteString("</ol>")
		fmt.Fprintf(&sb, "<p><strong>修复建议</strong>:%s</p>", html.EscapeString(remediationFor(f)))
		fmt.Fprintf(&sb, "<p class=\"muted\">证据锚点:%s(可按 request_id 调取)</p>", html.EscapeString(strings.Join(f.Evidence.RequestIDs, ", ")))
		sb.WriteString("</div>")
	}

	sb.WriteString("<h2>证据调取</h2><p>每条发现标注了 <code>request_id</code>;完整审计记录保存在测试方账本中,授权方可按 id 索取。本文件不含响应正文与凭据。</p>")
	sb.WriteString("<footer>本文件由 youkai 从只读证据台账生成;定级为估计值,正式定级需双方确认。</footer></body></html>")
	return sb.String(), nil
}

// ---- scope summary ---------------------------------------------------------

// ScopeSummary is the passport facts a disclosure must state.
type ScopeSummary struct {
	Basis     string   `json:"basis"`
	Operator  string   `json:"operator"`
	Include   []string `json:"include"`
	Exclude   []string `json:"exclude"`
	ExpiresAt string   `json:"expires_at"`
	Methods   []string `json:"methods"`
}

// ParseScope extracts the disclosure-relevant passport fields.
func ParseScope(raw json.RawMessage) ScopeSummary {
	var s struct {
		Basis     string   `json:"basis"`
		Operator  string   `json:"operator"`
		Include   []string `json:"include"`
		Exclude   []string `json:"exclude"`
		ExpiresAt string   `json:"expires_at"`
		Methods   []string `json:"methods"`
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &s)
	}
	return ScopeSummary{
		Basis: s.Basis, Operator: s.Operator, Include: s.Include,
		Exclude: s.Exclude, ExpiresAt: s.ExpiresAt, Methods: s.Methods,
	}
}

func disclosureItems(b Bundle, scope ScopeSummary) ([]FindingReport, error) {
	if strings.TrimSpace(scope.Basis) == "" || len(scope.Include) == 0 {
		return nil, ErrNoAuthorisation{Reason: "缺少 basis 或 include"}
	}
	items := Disclosable(b)
	if len(items) == 0 {
		return nil, ErrNoVerified{}
	}
	return items, nil
}

// estimateCVSS maps a severity band to a CVSS v3.1 base-score ESTIMATE. It is
// labelled as an estimate everywhere it appears: the real score depends on the
// concrete exploit, which is a human decision.
func estimateCVSS(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "9.0"
	case "high":
		return "7.5"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "0.0"
	}
}

func reproSteps(f FindingReport) []string {
	var steps []string
	steps = append(steps, "在授权范围内访问:"+dash(f.Where))
	for _, a := range f.Evidence.Audit {
		steps = append(steps, fmt.Sprintf("对应的一次只读请求:%s %s(审计 request_id=%s,判定 %s)",
			a.Method, a.URL, a.RequestID, a.Verdict))
	}
	if f.MinImpact != "" {
		steps = append(steps, "该操作的最小影响:"+f.MinImpact)
	}
	steps = append(steps, "观察到的差异:"+dash(f.Detail))
	return steps
}

func remediationFor(f FindingReport) string {
	if f.Remediation != "" {
		return f.Remediation
	}
	if r := RemediationFor(f.Kind); r != "" {
		return r
	}
	return "按该类型的一般修复原则处理;复核同一判定逻辑是否在其他接口重复。"
}

func writeAuthStatementMD(sb *strings.Builder, scope ScopeSummary) {
	sb.WriteString("本次测试在下列授权范围内进行,未经授权不得对范围外系统使用本文件内容:\n\n")
	fmt.Fprintf(sb, "- 授权依据:%s\n", dash(scope.Basis))
	if scope.Operator != "" {
		fmt.Fprintf(sb, "- 授权人/操作员:%s\n", scope.Operator)
	}
	fmt.Fprintf(sb, "- 授权目标:%s\n", dash(strings.Join(scope.Include, ", ")))
	if len(scope.Exclude) > 0 {
		fmt.Fprintf(sb, "- 排除范围:%s\n", strings.Join(scope.Exclude, ", "))
	}
	if !isZeroTime(scope.ExpiresAt) {
		fmt.Fprintf(sb, "- 授权到期:%s\n", scope.ExpiresAt)
	}
	if len(scope.Methods) > 0 {
		fmt.Fprintf(sb, "- 授权方法:%s\n", strings.Join(scope.Methods, ", "))
	}
	sb.WriteString("- 测试性质:只读探测与证据收集;未执行破坏性操作。\n")
}

func writeAuthStatementHTML(sb *strings.Builder, scope ScopeSummary) {
	sb.WriteString("<p>本次测试在下列授权范围内进行,未经授权不得对范围外系统使用本文件内容:</p><ul>")
	fmt.Fprintf(sb, "<li>授权依据:%s</li>", html.EscapeString(dash(scope.Basis)))
	if scope.Operator != "" {
		fmt.Fprintf(sb, "<li>授权人/操作员:%s</li>", html.EscapeString(scope.Operator))
	}
	fmt.Fprintf(sb, "<li>授权目标:%s</li>", html.EscapeString(dash(strings.Join(scope.Include, ", "))))
	if len(scope.Exclude) > 0 {
		fmt.Fprintf(sb, "<li>排除范围:%s</li>", html.EscapeString(strings.Join(scope.Exclude, ", ")))
	}
	if !isZeroTime(scope.ExpiresAt) {
		fmt.Fprintf(sb, "<li>授权到期:%s</li>", html.EscapeString(scope.ExpiresAt))
	}
	if len(scope.Methods) > 0 {
		fmt.Fprintf(sb, "<li>授权方法:%s</li>", html.EscapeString(strings.Join(scope.Methods, ", ")))
	}
	sb.WriteString("<li>测试性质:只读探测与证据收集;未执行破坏性操作。</li></ul>")
}

func writeDisclosureFindingMD(sb *strings.Builder, n int, f FindingReport) {
	fmt.Fprintf(sb, "### %d. %s\n\n", n, f.Title)
	fmt.Fprintf(sb, "- 定级:**CVSS %s(估计)** · 严重度 %s · 类型 %s\n", estimateCVSS(f.Severity), f.Severity, dash(f.Kind))
	fmt.Fprintf(sb, "- 影响:%s\n", dash(firstNonEmpty(f.Detail, f.MinImpact)))
	sb.WriteString("- 复现:\n")
	for _, step := range reproSteps(f) {
		fmt.Fprintf(sb, "  1. %s\n", step)
	}
	fmt.Fprintf(sb, "- 修复建议:%s\n", remediationFor(f))
	fmt.Fprintf(sb, "- 证据锚点:`%s`(可按 request_id 调取)\n\n", strings.Join(f.Evidence.RequestIDs, "`, `"))
}

// isZeroTime reports the Go zero timestamp, which JSON renders as
// "0001-01-01T00:00:00Z" - a value that means "no expiry", not "expired in year 1".
func isZeroTime(v string) bool {
	return v == "" || strings.HasPrefix(v, "0001-01-01")
}
