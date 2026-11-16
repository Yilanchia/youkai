package report

import (
	"fmt"
	"html"
	"strings"
)

// HTML renders a self-contained page: no external stylesheet, no script, no remote
// font. A report that needs the network to display is not a deliverable you can
// hand to a client behind an air gap.
func HTML(b Bundle) string {
	var sb strings.Builder
	sb.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	fmt.Fprintf(&sb, "<title>youkai 证据报告 — %s</title>", esc(b.Engagement))
	sb.WriteString("<style>")
	sb.WriteString(`body{font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans SC",sans-serif;
max-width:960px;margin:0 auto;padding:32px 20px;color:#1a1a1a;background:#fff;line-height:1.55}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:28px 0 10px;border-bottom:1px solid #e5e5e5;padding-bottom:6px}
h3{font-size:16px;margin:18px 0 6px}
.muted{color:#666}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;background:#eef;color:#224}
.tag.verified{background:#e6f7e9;color:#1c6b2e}.tag.candidate{background:#fff4e0;color:#8a5a00}
table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:13px}
th,td{border-bottom:1px solid #e8e8e8;padding:5px 8px;text-align:left;vertical-align:top}
.card{border:1px solid #e5e5e5;border-radius:8px;padding:14px 16px;margin:12px 0}
.four{margin:8px 0 0;padding-left:18px}.four li{margin:4px 0}
.warn{border-left:4px solid #d9a300;background:#fffbea;padding:8px 12px;margin:8px 0}
pre{background:#f7f7f7;padding:8px;border-radius:6px;overflow:auto}
footer{margin-top:32px;color:#888;font-size:12px;border-top:1px solid #eee;padding-top:12px}`)
	sb.WriteString("</style></head><body>")

	fmt.Fprintf(&sb, "<h1>youkai 证据报告 — %s</h1>", esc(b.Engagement))
	if b.GeneratedAt != "" {
		fmt.Fprintf(&sb, "<p class=\"muted\">生成于(账本最新审计时刻):%s · 格式 %s</p>", esc(b.GeneratedAt), esc(b.Schema))
	}
	fmt.Fprintf(&sb, "<p class=\"mono\">资产 %d · 事实 %d · 发现 %d(已确认 %d) · 利用提供者:%s</p>",
		b.Stats.Assets, b.Stats.Facts, b.Stats.Findings, b.Stats.Verified, esc(b.Provider))

	fmt.Fprintf(&sb, "<h2>覆盖</h2><p>%s</p>", esc(b.Coverage.Statement))
	if len(b.Coverage.EndpointList) > 0 {
		sb.WriteString("<table><thead><tr><th>方法 + 端点</th></tr></thead><tbody>")
		for _, e := range b.Coverage.EndpointList {
			fmt.Fprintf(&sb, "<tr><td class=\"mono\">%s</td></tr>", esc(e))
		}
		sb.WriteString("</tbody></table>")
	}

	if len(b.Incomplete) > 0 {
		fmt.Fprintf(&sb, "<div class=\"warn\"><strong>证据不完整</strong>:以下发现缺四样证据中至少一样,已排除在披露包之外。<ul>")
		for _, s := range b.Incomplete {
			fmt.Fprintf(&sb, "<li>%s</li>", esc(s))
		}
		sb.WriteString("</ul></div>")
	}

	sb.WriteString("<h2>发现</h2>")
	if len(b.Findings) == 0 {
		sb.WriteString("<p class=\"muted\">(无)</p>")
	}
	for _, f := range b.Findings {
		fmt.Fprintf(&sb, "<div class=\"card\"><h3>%s</h3>", esc(f.Title))
		fmt.Fprintf(&sb, "<p><span class=\"tag %s\">%s</span> <span class=\"tag\">%s</span>",
			esc(f.State), esc(f.State), esc(f.Severity))
		if f.Kind != "" {
			fmt.Fprintf(&sb, " <span class=\"mono\">%s</span>", esc(f.Kind))
		}
		sb.WriteString("</p>")
		fmt.Fprintf(&sb, "<p class=\"mono\">位置:%s</p>", esc(dash(f.Where)))

		sb.WriteString("<ul class=\"four\"><li><strong>① 证据</strong><ul>")
		if len(f.Evidence.RequestIDs) == 0 {
			sb.WriteString("<li>缺失:没有任何 request_id</li>")
		}
		for _, id := range f.Evidence.RequestIDs {
			if row, ok := f.evidenceRow(id); ok {
				fmt.Fprintf(&sb, "<li><code>%s</code> — %s %s → %d [%s]</li>",
					esc(id), esc(row.Method), esc(row.URL), row.Status, esc(row.Verdict))
			} else {
				fmt.Fprintf(&sb, "<li><code>%s</code> — 审计表里找不到</li>", esc(id))
			}
		}
		sb.WriteString("</ul></li>")
		fmt.Fprintf(&sb, "<li><strong>② 最小影响</strong>:%s</li>", esc(dash(f.MinImpact)))
		fmt.Fprintf(&sb, "<li><strong>③ 停止点</strong>:%s</li>", esc(dash(f.StopCondition)))
		fmt.Fprintf(&sb, "<li><strong>④ 反证说明</strong>:%s</li>", esc(dash(f.Counter)))
		if r := remediationFor(f); r != "" {
			fmt.Fprintf(&sb, "<li><strong>⑤ 修复建议</strong>:%s</li>", esc(r))
		}
		sb.WriteString("</ul>")
		if f.Detail != "" {
			fmt.Fprintf(&sb, "<p>%s</p>", esc(f.Detail))
		}
		if len(f.Incomplete) > 0 {
			fmt.Fprintf(&sb, "<p class=\"warn\">证据不完整:缺 %s</p>", esc(strings.Join(f.Incomplete, "、")))
		}
		sb.WriteString("</div>")
	}

	sb.WriteString("<h2>事实</h2><ul>")
	if len(b.Facts) == 0 {
		sb.WriteString("<li class=\"muted\">(无)</li>")
	}
	for _, f := range b.Facts {
		fmt.Fprintf(&sb, "<li>[%s] %s</li>", esc(strings.Join(f.Tags, ",")), esc(f.Statement))
	}
	sb.WriteString("</ul>")

	sb.WriteString("<h2>意图与审批</h2><table><thead><tr><th>#</th><th>能力</th><th>档</th><th>状态</th><th>最小影响</th><th>停止点</th></tr></thead><tbody>")
	for _, it := range b.Intents {
		fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"mono\">%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			it.ID, esc(it.Capability), it.Tier, esc(it.Status), esc(it.MinImpact), esc(it.StopCondition))
	}
	sb.WriteString("</tbody></table>")

	sb.WriteString("<h2>审计(最近)</h2><table><thead><tr><th>request_id</th><th>方法</th><th>URL</th><th>状态</th><th>判定</th></tr></thead><tbody>")
	for _, a := range b.Audit {
		fmt.Fprintf(&sb, "<tr><td class=\"mono\">%s</td><td class=\"mono\">%s</td><td class=\"mono\">%s</td><td>%d</td><td>%s</td></tr>",
			esc(a.RequestID), esc(a.Method), esc(a.URL), a.Status, esc(a.Verdict))
	}
	sb.WriteString("</tbody></table>")

	sb.WriteString("<footer>本报告由账本投影生成,不含响应正文与凭据。每条发现都可用 request_id 在审计表复核。</footer>")
	sb.WriteString("</body></html>")
	return sb.String()
}

func esc(s string) string { return html.EscapeString(s) }
