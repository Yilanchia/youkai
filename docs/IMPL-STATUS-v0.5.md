# IMPL-STATUS v0.5 — 证据闭环与可披露报告

> 日期:2026-11-14 · 承接 DEVPLAN-v0.5 · `go test ./...` 全绿 · `scripts/acceptance-v02.ps1` 全通过
> 新增:`internal/report/{bundle,markdown,html,sarif,disclosure,counter}.go`、
> `internal/ledger/snapshots.go`、`report_snapshots` 表、`findings.counter`、
> API 的 `/reports` `/sarif` `/disclosure`、SPA 证据面板重做。

## 一句话

把"账本投影式报告"补成**能复核、能定级、能披露**的成品:四样证据强制齐备、快照不可改且带哈希、
SARIF 能进 CI、披露包只收已证 —— 而且报告全程**不发一个请求**。

## 一 · 四样证据成品化

`internal/report` 是纯函数包:账本数据进、文本出。`internal/discipline` 里新增静态检查
`TestReportPackageCannotReachTheNetwork`,禁止 report 包 import
`gate/discipline/web/binary/accounts/runtime/net/http/net` —— "读账本"不会悄悄变成"再问目标一次",
否则快照就不可复现了。

四样的落点(校验已有数据,不新造事实):

| # | 四样 | 落点 | 缺失时 |
|---|---|---|---|
| ① | 证据 | `evidence.request_id[]`,逐个反查 `audit_log` | `incomplete:evidence` |
| ② | 最小影响 | 从审计 `purpose` 反推能力 → `wording.MinImpact` | 能力未知 → `incomplete:min_impact` |
| ③ | 停止点 | 同上 → `wording.StopCondition` | 空 → `incomplete:stop_condition` |
| ④ | 反证说明 | `findings.counter`(新列)或按 kind 的模板 | 未知 kind → `incomplete:counter` |

`counter` 是这次新加的列(`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`,幂等),能力可以自己写,
不写就用模板。**模板只覆盖 youkai 真实会产出的 kind**,未知 kind 保持缺失 ——
"没有反证"和"编一句听起来合理的反证"是两件事。

`wording` 同步补齐了 v0.2+ 的能力名(`probe/param/waf/login/compare/scan/crawl/browser/...`),
这样审批台的措辞和报告里的措辞是同一句。

## 二 · 不可变快照

```sql
CREATE TABLE report_snapshots (
  id BIGSERIAL PRIMARY KEY, engagement_id BIGINT REFERENCES engagements(id),
  created_at TIMESTAMPTZ DEFAULT now(),
  content_sha256 TEXT,        -- 快照 JSON 的哈希,复核锚点
  scope_snapshot JSONB,       -- 出报告那一刻的护照
  bundle JSONB                -- 完整 ReportBundle
);
-- 触发器:UPDATE / DELETE 直接 RAISE EXCEPTION
```

`POST /reports` 落一行快照 + 一份自包含 HTML(`<artifacts>/<eng>/reports/report-<sha8>.html`)。

**可复现**:`GeneratedAt` 不取 `time.Now()`,而是取账本里最新的审计时刻 ——
所以同一账本渲染两次**字节一致**,哈希才有意义。快照行的 `created_at` 才是"什么时候落的",
两件事分开。

验收:两条快照、各自 64 位 sha256、`UPDATE report_snapshots` 被数据库拒绝、
改 passport 后再出快照 → `scope_snapshot` 不同、哈希不同。

## 三 · SARIF 2.1.0

`GET /sarif` → `application/sarif+json`。

- `ruleId` = `youkai/<kind>`,rules 按 id 排序(导出可 diff)。
- `level`:verified → `error`,candidate → `warning`。
- 定位:web 用 `artifactLocation.uri` = URL + `logicalLocations`(含 `param:<name>`);
  binary 用 `file:line` → `region.startLine`。
- 四样塞进 `properties`(request_ids / min_impact / stop_condition / counter / incomplete /
  disclosable),下游不会因为换格式丢掉证据。

验收:结构校验(version/`$schema`/runs/rules/results 必填字段 + level 枚举 + 两种定位都出现)、
两次导出字节一致。**没有跑完整 JSON-Schema 校验器**,这是结构校验,报告里如实写明。

## 四 · 披露包

`GET /disclosure?format=md|html`:

- 只收 `verified` **且四样齐备**的发现;没有就 **409 + 原因**,不产空壳。
- 无 `basis` / 无 `include` → **412**,因为"没有授权依据的披露"是指控不是披露。
- 每条:标题、影响、**CVSS 估计值**(明确标注"估计")、复现步骤(从审计行重建,不含真实凭据)、
  修复建议、以及"可按 request_id 调取"的证据锚点。
- 文首固定授权声明 + 护照摘要(basis/操作员/目标/排除/到期/方法)。
- 正文不含响应正文、不含 cookie、不含 marker。

## 五 · 覆盖声明

从 `audit_log` 投影,不是从护照:测过几个主机、几个端点(方法+路径,查询串不参与计数)、
请求数、允许/阻断/失败。文案固定包含"未在此列出的资产不在本报告范围内",
并且有测试禁止 `全站 / 完整覆盖 / 全部资产` 这类措辞。

## 六 · SPA

"证据 · 报告"面板重做:覆盖声明卡片、不完整清单、每条发现的**四段展开**
(① 证据带审计行回查结果 ② 最小影响 ③ 停止点 ④ 反证说明)、`可披露` 标记、
顶部按钮「出快照报告 / 导出 SARIF / 披露包 md / 披露包 html / 下载 markdown / 下载 HTML」、
底部历史快照表(sha 前 8 + 时间)。

## 七 · 验收(真机)

`scripts/acceptance-v02.ps1` 新增 18 条断言,最后输出:

```
== evidence report ==
ok  report bundle renders / declares its schema
ok  coverage counts the requests that actually happened
ok  the report makes no whole-site claim
ok  finding N carries evidence_block / min_impact / stop_condition / counter
ok  at least one finding resolved its request_id against the audit log
ok  two renders of an unchanged ledger are byte-identical
ok  markdown carries the four evidence sections
ok  snapshot created / carries a sha256 anchor
ok  the snapshot table refuses UPDATE at the database level
ok  SARIF export declares version 2.1.0
ok  SARIF results carry youkai rule ids
ok  the four evidence pieces survive the SARIF export
ok  disclosure refuses to ship with no verified finding
ok  operator verdict recorded (candidate -> verified)
ok  disclosure states the authorisation / labels CVSS as an estimate
ok  the second snapshot hashes differently after a scope change
ALL ACCEPTANCE ASSERTIONS PASSED
```

## 落实中修掉的两个真问题

1. **`findingSelect` 列数不一致**:加 `counter` 列时只改了 `SCAN` 目标,`findingSelect`
   常量漏改 → "number of field descriptions must equal number of destinations"。
   已修,`internal/ledger` 全部测试恢复。
2. **四样里的 min_impact 对只读能力全是 unknown**:`wording` 只认识 v0.1 的 `web_*` 名字,
   而 `scan/browser/headers/...` 全部落到 unknown → 所有只读发现都被标
   `incomplete:min_impact`,导致披露包永远空。补齐能力名 + 按 kind 补齐 counter 模板后,
   真实发现变成可披露。**这是验收断言逼出来的,不是猜的。**

## 与 DEVPLAN-v0.5 的差异 / 未做

- **SARIF 只做结构校验**,没有引入完整 JSON-Schema 校验器(依赖太重)。导出的字段严格按 2.1.0
  必填项 + 我们自己的 properties,能过常见消费方,但没有对全部 schema 约束做机器验证。
- **披露包的 CVSS 是按严重度带宽映射的估计值**(critical 9.0 / high 7.5 / medium 5.0 / low 3.0),
  没有做向量分解,也没有存 `cvss` 字段到账本;正式定级仍需人工。
- **快照没有"删除/保留期"策略**:append-only 意味着它只增不减,长期运行需要归档策略。
- **`report_snapshots` 的 bundle 是整份 JSON**;大账本会变大,目前没有压缩或分页。
- **SPA 的快照下载**走 `?token=` 打开新标签,和 v0.4 的下载路径一致;没有做一次性签名链接。
