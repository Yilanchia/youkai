package report

import (
	"fmt"
	"strings"
)

// Markdown renders the bundle.
//
// It is a pure function of the bundle, so the same ledger always renders the same
// bytes - that is what makes a snapshot checkable. Nothing here may call Now() or
// read the environment.
func Markdown(b Bundle) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# youkai 证据报告 — %s\n\n", b.Engagement)
	if b.GeneratedAt != "" {
		fmt.Fprintf(&sb, "生成于(账本最新审计时刻):%s\n\n", b.GeneratedAt)
	}
	fmt.Fprintf(&sb, "- 资产 %d / 事实 %d / 发现 %d(已确认 %d)\n",
		b.Stats.Assets, b.Stats.Facts, b.Stats.Findings, b.Stats.Verified)
	fmt.Fprintf(&sb, "- 利用提供者:%s\n", b.Provider)
	fmt.Fprintf(&sb, "- 覆盖:%s\n\n", b.Coverage.Statement)

	if len(b.Incomplete) > 0 {
		sb.WriteString("## ⚠ 证据不完整\n\n")
		sb.WriteString("以下发现缺少四样证据中至少一样,已排除在披露包之外:\n\n")
		for _, s := range b.Incomplete {
			fmt.Fprintf(&sb, "- %s\n", s)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## 发现\n\n")
	if len(b.Findings) == 0 {
		sb.WriteString("(无)\n\n")
	}
	for _, f := range b.Findings {
		writeFindingMD(&sb, f)
	}

	sb.WriteString("## 覆盖\n\n")
	fmt.Fprintf(&sb, "%s\n\n", b.Coverage.Statement)
	if len(b.Coverage.Hosts) > 0 {
		fmt.Fprintf(&sb, "- 主机:%s\n", strings.Join(b.Coverage.Hosts, ", "))
	}
	if len(b.Coverage.EndpointList) > 0 {
		fmt.Fprintf(&sb, "- 端点(%d):\n", b.Coverage.Endpoints)
		for _, e := range b.Coverage.EndpointList {
			fmt.Fprintf(&sb, "  - `%s`\n", e)
		}
	}
	sb.WriteString("\n")

	sb.WriteString("## 事实\n\n")
	if len(b.Facts) == 0 {
		sb.WriteString("(无)\n")
	}
	for _, f := range b.Facts {
		fmt.Fprintf(&sb, "- [%s] %s\n", strings.Join(f.Tags, ","), f.Statement)
	}
	sb.WriteString("\n## 意图与审批\n\n")
	if len(b.Intents) == 0 {
		sb.WriteString("(无)\n")
	}
	for _, it := range b.Intents {
		fmt.Fprintf(&sb, "- #%d `%s` tier=%d status=%s approved=%v\n", it.ID, it.Capability, it.Tier, it.Status, it.Approved)
		fmt.Fprintf(&sb, "  - 最小影响:%s\n", it.MinImpact)
		fmt.Fprintf(&sb, "  - 停止点:%s\n", it.StopCondition)
	}
	sb.WriteString("\n## 审计(最近)\n\n")
	if len(b.Audit) == 0 {
		sb.WriteString("(无)\n")
	}
	for _, a := range b.Audit {
		fmt.Fprintf(&sb, "- `%s` %s %s → %d [%s] %s\n", a.RequestID, a.Method, a.URL, a.Status, a.Verdict, a.Reason)
	}
	sb.WriteString("\n---\n本报告由账本投影生成,不含响应正文与凭据;每条发现都可用 request_id 在审计表复核。\n")
	return sb.String()
}

func writeFindingMD(sb *strings.Builder, f FindingReport) {
	fmt.Fprintf(sb, "### [%s] %s\n\n", f.Severity, f.Title)
	fmt.Fprintf(sb, "- 状态:**%s**%s\n", f.State, disclosableTag(f))
	if f.Kind != "" {
		fmt.Fprintf(sb, "- 类型:`%s`\n", f.Kind)
	}
	fmt.Fprintf(sb, "- 位置:`%s`\n", dash(f.Where))

	sb.WriteString("\n**① 证据**\n\n")
	if len(f.Evidence.RequestIDs) == 0 {
		sb.WriteString("- 缺失:没有任何 request_id,这条发现无法复核。\n")
	} else {
		for _, id := range f.Evidence.RequestIDs {
			if row, ok := f.evidenceRow(id); ok {
				fmt.Fprintf(sb, "- `%s` — %s %s → %d [%s](审计表可查)\n", id, row.Method, row.URL, row.Status, row.Verdict)
			} else {
				fmt.Fprintf(sb, "- `%s` — **审计表里找不到这条请求**\n", id)
			}
		}
	}

	fmt.Fprintf(sb, "\n**② 最小影响**:%s\n", dash(f.MinImpact))
	fmt.Fprintf(sb, "\n**③ 停止点**:%s\n", dash(f.StopCondition))
	fmt.Fprintf(sb, "\n**④ 反证说明**:%s\n", dash(f.Counter))
	if f.Detail != "" {
		fmt.Fprintf(sb, "\n观察记录:%s\n", f.Detail)
	}
	if f.Operator != "" {
		fmt.Fprintf(sb, "\n操作员判定:%s(%s)\n", f.Operator, f.VerdictNote)
	}
	if len(f.Incomplete) > 0 {
		fmt.Fprintf(sb, "\n> ⚠ 证据不完整:缺 %s。\n", strings.Join(f.Incomplete, "、"))
	}
	sb.WriteString("\n")
}

// evidenceRow looks up a resolved audit row for one id.
func (f FindingReport) evidenceRow(id string) (struct {
	Method  string
	URL     string
	Status  int
	Verdict string
}, bool) {
	for _, a := range f.Evidence.Audit {
		if a.RequestID == id {
			return struct {
				Method  string
				URL     string
				Status  int
				Verdict string
			}{a.Method, a.URL, a.Status, a.Verdict}, true
		}
	}
	return struct {
		Method  string
		URL     string
		Status  int
		Verdict string
	}{}, false
}

func disclosableTag(f FindingReport) string {
	if f.Disclosable {
		return " · 可披露"
	}
	return ""
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
