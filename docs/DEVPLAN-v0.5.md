# DEVPLAN-v0.5:证据闭环与可披露报告(Proof-Carrying Pentest 落地)

> 交付对象:实现者(DeepSeek)。配 ADR-002/003/004、STRATEGY(Fairy)、IMPL-STATUS-v0.4 读。
> 目标:把现在"账本投影式报告"补成**第三方能独立复核、能修复、能披露的证据成品** ——
> 这是 youkai 愿景的最后一公里:"把只读取证链走完,留下一份能复核、能修复、能披露的证据"。

## 0. 为什么是现在做这个

脊柱 / 账本 / web+binary 能力 / 引擎 / 账号层 / 浏览器 / 配置都齐了。youkai 已经能**自主走只读链、停在档 2、
人一步步批利用**。但产物端还停在:`GET /report`(JSON/MD 投影)——够看,不够**交付**。愿景要的不是"扫到什么",
而是"每一发都能被别人照着复核、能定级、能披露"。STRATEGY 的 **Proof-Carrying Pentest** 要求每条结论携带四样:
**① 证据(请求/响应片段 + request_id + 审计位置)② 最小影响 ③ 停止点 ④ 反证说明**,缺一不进报告。
现在四样在数据结构里有雏形,但没有成品化、没有不可变快照、没有标准格式(SARIF)、没有披露包。本轮补齐。

## 0.5 不可动摇(继承)

- 报告永远是**账本的投影**,不是另一份真值;同一账本重复出报告字节一致(可复现)。
- 凭据 / 响应正文 / cookie / marker **绝不进报告**;证据只到 request_id、审计位置、必要的最小片段(已脱敏)。
- 只报**实际测过**的资产,不写"全站";candidate 与 verified 分开呈现,candidate 不得被措辞成已证。
- 披露包只收 **verified** 发现,且随附授权 scope 快照;无 scope、无授权依据不出披露包。
- 不新增任何目标请求能力;报告/披露是纯读账本 + 渲染,不发包。

## 1. 四样证据成品化 `internal/report`(P0)

**目标**:把 `handleReport` / `renderMarkdown` 从 `internal/api` 抽进独立 `internal/report`,每条 finding **强制**带齐四样,缺项的 finding 要么补、要么降级呈现,绝不伪装成完整证据。

**涉及**:新增 `internal/report/{bundle,markdown,html}.go` + 测试;`internal/api/intents.go` 的 report 处理器改为调它。

**四样证据的账本落点(校验,不是新造)**:
- **证据**:finding.Evidence 里的 `request_id[]` + 审计行定位(engagement+request_id 可查 audit_log)+ 可选最小片段(已脱敏)。渲染时对每个 request_id 反查 audit_log 坐实"这条请求真的发生过且在 scope 内"。
- **最小影响**:intent 的 `min_impact`(若无则从能力默认模板取,如"只读一次/双账号对比/canary 带外")。
- **停止点**:intent 的 `stop_condition`(已有)。
- **反证说明**:finding 的 `counter`(为什么可能误报、还缺什么才能定级)——**新增字段**,确定性能力给模板默认,LLM/人可补。

**实现要点**:report 包是纯函数(账本数据进、文本出),不碰网络、不碰 gate;finding 缺四样中任一 → 标 `incomplete` 并在报告里显式列出缺什么,**不静默**。

**验收**:一条完整 finding 渲染出四段;构造一条缺 counter 的 → 报告标 `incomplete:counter` 且不计入"可披露";report 包无网络/ gate 依赖(可加静态检查);同账本两次渲染 MD 字节一致。

## 2. 不可变 run 快照 `internal/report` + ledger(P0)

**目标**:每次"出报告"落一份**不可变快照**到 PG + 产物目录,带内容哈希,事后可按哈希复核、可 diff。

**涉及**:`internal/ledger/schema.sql` 加 `report_snapshots` 表;`internal/report/snapshot.go`。

**schema**:
```sql
CREATE TABLE IF NOT EXISTS report_snapshots (
  id            BIGSERIAL PRIMARY KEY,
  engagement_id BIGINT NOT NULL REFERENCES engagements(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  content_sha256 TEXT NOT NULL,       -- 快照 JSON 的哈希,复核锚点
  scope_snapshot JSONB NOT NULL,      -- 出报告那一刻的护照(可审计边界)
  bundle        JSONB NOT NULL        -- 完整 ReportBundle(含四样 + 发现 + 覆盖声明)
);
```

**实现要点**:快照 append-only(同 audit_log,触发器禁 UPDATE/DELETE);`scope_snapshot` 固化"这份报告是在什么授权边界下得出的";产物目录另写一份自包含 HTML（`report-<sha8>.html`）。

**验收**:出两次报告 → 两条快照、各带 sha256;改了 scope 再出 → scope_snapshot 不同;快照表拒绝 UPDATE;HTML 自包含(无外链、无 inline script)。

## 3. SARIF 导出 `internal/report/sarif.go`(P1)

**目标**:web + binary 的 verified/candidate 发现导出 SARIF 2.1.0,接入 CI / 代码扫描视图(对齐 Verdex 的 SARIF 能力)。

**实现要点**:每条 result 带 ruleId(能力+发现类型)、level(verified→error / candidate→warning)、locations(web 用 URL+参数,binary 用 file:line)、以及四样证据塞进 `properties`。不杜撰 CWE,能映射才写。

**验收**:SARIF 通过 schema 校验;web 的 `GET <url>(param:q)` 与 binary 的 `file:line` 都能定位;candidate 是 warning 不是 error。

## 4. 披露包 `internal/report/disclosure.go`(P1)

**目标**:生成**只含 verified 发现**的披露文档(给厂商/SRC),随附授权 scope 快照,不带证据正文、不带凭据。

**实现要点**:
- 只收 `verified`;candidate 一律不进披露包(愿景:不把疑似说成已证)。
- 每条:标题、影响、定级(CVSS 为**估计值**并标注"估计")、复现步骤(从 intent/能力重建,不含真实凭据/数据)、修复建议、以及"证据可向授权方按 request_id 调取"的指针——**正文不塞原始响应**。
- 文首固定一段授权声明 + scope 快照摘要(授权依据 basis、目标、过期),无 basis/无 scope 拒绝生成。
- 输出 Markdown + 自包含 HTML。

**API**:`GET /api/engagements/{id}/disclosure?format=md|html` —— 无 verified 发现时返回明确空态("尚无已验证发现,披露包不生成"),不产出空壳。

**验收**:只含 verified;candidate 不出现;无 scope/basis 拒绝;CVSS 标"估计";正文无凭据/响应正文;HTML 自包含。

## 5. 覆盖声明(P2,诚实度)

**目标**:报告头部给"测过什么"的诚实声明,杜绝"全站已测"的暗示。

**实现要点**:从 audit_log 聚合"实际请求过的 host/endpoint 集合 + 请求数 + 每类发现数",渲染成"覆盖:测过 N 个端点、M 个资产;未声明覆盖的不在此列"。纯 audit 投影,不夸大。

**验收**:覆盖数字与 audit_log 一致;报告不出现"全站/完整"等绝对措辞(可加文案检查)。

## 6. SPA 证据面板增强 + 文档(P2)

- "证据 · 报告"面板:每条 finding 展开显示四样;顶部按钮"出快照报告 / 导 SARIF / 出披露包";列出历史快照(sha8 + 时间 + 可下载)。
- README 补「证据与披露」段:四样证据、快照可复核、SARIF、披露包只收 verified。
- `scripts/acceptance-v02.ps1` 增断言:出报告→落快照→改 scope→再出→两快照 scope 不同;披露包拒绝 candidate;SARIF 过 schema。

## 落地顺序

1. 模块一(四样证据成品化 + report 包抽离)—— 先把"每条带齐四样、缺则显式标注"立住。
2. 模块二(不可变 run 快照 + scope 固化)。
3. 模块三(SARIF)、模块四(披露包)。
4. 模块五(覆盖声明)、模块六(SPA + 文档)。

**每步验收锚点**:报告是账本投影且可复现(字节一致);凭据/正文零泄漏;candidate 与 verified 分离、candidate 不进披露;快照不可改、带 scope 固化与 sha256;只报测过的资产;report/披露全程不发包。

## 一句话

youkai 已经能自己把只读链走完、停在人前;v0.5 让它走完之后**留下的东西配得上这条路** ——
一份第三方照着就能复核、能定级、能披露的证据,而不只是一次扫描的回显。
