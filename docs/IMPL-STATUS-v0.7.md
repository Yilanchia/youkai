# IMPL-STATUS v0.7 — worker trace 跨轮检索(把执行过程变成可复用的记忆)

> 日期:2026-11-14 · 承接 DEVPLAN-v0.7 · `go test ./...` 全绿 · `scripts/acceptance-v02.ps1` 全通过
> 新增:`internal/ledger/trace.go`(`SearchTraces` / `Covered` / `TargetKey`)、
> engine 的 `PriorWork` + 派生守卫、planner 的「已执行」prompt 段、SPA 的 trace 展示。

## 一句话

youkai 以前每轮从零开始规划;现在它会**记得自己走过哪** —— 同目标已做的只读检查不再重复派生,
规划预算留给没探过的地方。纯读账本,不碰墙,不发包。

## 一 · 检索(`internal/ledger/trace.go`)

```go
type TraceHit struct { IntentID, Capability, Tier, Status, Target, Summary, RequestIDs, At }
func (s *Store) SearchTraces(ctx, engagementID, TraceQuery) ([]TraceHit, error)
func Covered(hits []TraceHit, capability, target string) bool   // 派生守卫用
func TargetKey(args map[string]any) string                       // host/path 归一(与检索共用)
```

- **只读**:一条 SELECT,不发包、不碰 `guard`/`gate`。
- **不跨作业**:`WHERE engagement_id = $1`;`TestSearchTracesIsScopedOrderedAndFilterable` 用两个作业钉住。
- **稳定排序**:按 `intent_id` 升序,`Limit` 保留**最新的尾部**(历史近的更有用);同一账本两次检索结果一致。
- **目标归一**:`host/path`,去掉 scheme 与 query —— query 正是标记与参数所在,同一 endpoint 的不同 query 视为同一处。
- **只收跑过的**:`status IN (done/skipped/needs_approval/blocked/active)` 且有 trace;排队中的意图是计划不是结果。
- `Summary` 取 trace 首行并截到 240 字符;`RequestIDs` 从 `request_ids=` 解析。trace 本来就是结构化行(能力/计数/id),
  不含正文与凭据,投影不新增任何敏感内容。

## 二 · 喂规划器

**确定性守卫(engine)**:每轮 `derive` 开始时取一次 trail 快照;派生时若
`capability+target` 已有完成记录 → 不派生。

守卫刻意**只覆盖"检查这个 endpoint"这类能力**(`probe/fingerprint/scan/headers/cors/exposures/redirect_check/browser`),
并且**带选择器的一律不拦**:`param`/`marker`/`session*`/`headers` 是"同一处的新问题";
`method` 只在非只读(POST 等)时才豁免 —— 因为每个 probe 都带 `method=GET`,那是同一次检查,
而 POST probe 是另一个(档 2)问题,必须还能被提出。

**LLM(planner)**:`ProposeRequest.PriorWork` 带最近 40 条 trace,prompt 新增一段:

```
已执行过的步骤(不要重复;只有出现新事实使重做更有价值时才可以再做):
- probe 127.0.0.1:18080/.git/config → capability=probe ok=true tier=1 facts=1 findings=1
- scan 127.0.0.1:18080/search → capability=scan ok=true tier=1 facts=9 findings=7
```

这段由我们自己的 trace 行拼成,**不取目标响应正文**,因此不引入新的 prompt injection 面;
`PriorWork` 仍只是输入,任何据此产生的提议照旧判档、照旧要人批。

**可回放**:planner 存档的 `prompt` 字段就是这个完整输入(含「已执行」段),所以回放看到的就是模型当时看到的。

## 三 · SPA

探索图面板:意图表上方一行「已执行步骤按目标:`127.0.0.1:18080 × 11 · localhost:18080 × 2`」,
下方「已执行步骤(N)」表逐条显示 `intent_id / capability / trace`。无凭据、无正文。

## 四 · 验收

```
TestSearchTracesIsScopedOrderedAndFilterable   跨作业不串 / 按 id 稳定 / 三种过滤 / Limit 取尾部 /
                                              空结果不报错 / 目标归一 / Covered 命中与不命中
TestDeriveDoesNotRepeatACoveredCheck           已 probe 过的 endpoint 不被再派生
TestPromptCarriesPriorWork                     prompt 含「已执行过的步骤」与具体条目,且明确"不要重复"
TestPromptWithoutPriorWorkHasNoSection         空 trail 不渲染段落
TestPromptIsBoundedAndOrdered                  最多 40 条且保留最新
```

验收脚本新增 5 条(全过):

```
ok  a probe of the git path already ran in this engagement
ok  the same endpoint was not probed twice (trace guard)
ok  executed steps carry a trace
ok  traces carry no credentials
```

## 顺带修掉的一个真问题

`TargetKey` 一开始在 engine 和 ledger 各写了一份(大小写/路径归一不同),守卫会**静默永不命中**。
现在共用 `ledger.TargetKey`,两边不可能再分叉;`SearchTraces` 与守卫用同一函数归一。

## 与 DEVPLAN-v0.7 的差异 / 未做

- **没有新建 `prior_work` 列**:PriorWork 直接进 prompt(存档的 `prompt` 即全文),回放足够。
  结构化查询目前只能从 `trace` 文本反解。
- **守卫按"能力+目标"判,不按"是否出现新 fact"判**。DEVPLAN 要求"有新 fact 时允许重做不被误杀",
  实现上把这条落在**选择器**上:带 `param/marker/session/headers` 或非只读方法的派生一律不拦,
  所以新证据引出的新问题不会被吞。但"同一 endpoint、同一只读能力、确实因为新 fact 值得重跑"这种情况,
  现在会被跳过 —— 属于已知的保守取舍。
- **`SearchTraces` 没有 HTTP 端点**:检索只在引擎与 planner 内部用,操作员通过探索图看 trace。
- **跨作业记忆不共享**:v0.7 明确"不跨作业",跨作业的经验要等未来的 host 级 memory。
