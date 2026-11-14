# DEVPLAN-v0.7:worker trace 跨轮检索(把执行过程变成可复用的记忆)

> 交付对象:实现者(DeepSeek)。配 ADR-002(借 ARTEX 的"过程级信息交换")、DEVPLAN-v0.2 模块三/四、IMPL-STATUS-v0.6 读。
> 目标:让已执行步骤的 trace 能被后续 planner 轮次**检索复用**,减少重复探测、让自治链更像"脑"而不是"每轮从零"。
> 不加任何目标请求能力、不碰档位墙:这是纯读账本 + 喂给 planner 的上下文增强。

## 0. 现状与缺口

- trace **写得全**:`engine` 每个 intent 执行后 `AppendTrace`(capability/tier/facts/findings/request_ids/SENSITIVE/失败原因),存 `intents.trace`。
- 但 trace **从没被读回来**:planner 的 `ProposeRequest` 只喂 facts 计数,不含历史 trace。于是:
  - LLM 每轮看不到"这条链之前试过什么、结果如何",可能重复派同类探测;
  - 确定性规则也无从"看到前一步已证实某事"而跳过冗余步骤。
- ARTEX 的强项之一正是 worker 之间按关键字检索彼此过程、复用观察。youkai 有数据、缺检索。本轮补检索,**只读、只增强规划输入**。

## 0.5 不可动摇(继承)

- 纯读:trace 检索不发任何目标请求、不碰 `discipline.Guard`、不碰 `gate`。
- 不放松自治边界:检索只改变"planner 看到什么上下文",**不改变**档位判定、审批门、candidate→verified。
- 不喂凭据:trace 里本就只有能力名/计数/request_id/判定,无正文无 cookie;检索输出同样不得引入敏感值。
- 可复现:同账本下检索结果确定(稳定排序),让 planner 调用仍可回放(LLM 存档含它看到的 trace 上下文)。
- LLM 仍只提议:trace 让它提议得更省,但放行仍归闸门代码。

## 1. trace 检索 API `internal/ledger`(P0)

**目标**:给账本加"按关键字/能力/host 检索已执行 trace"的只读查询,输出结构化、脱敏、稳定排序。

**涉及**:`internal/ledger/trace.go`(新)、`internal/ledger/schema.sql`(给 `intents.trace` 或新投影建检索索引)、`trace_test.go`。

**接口**:
```go
// TraceHit 是一条可复用的过程记忆:哪个能力、打到哪、结论计数,不含正文/凭据。
type TraceHit struct {
    IntentID   int64    `json:"intent_id"`
    Capability string   `json:"capability"`
    Tier       int      `json:"tier"`
    Status     string   `json:"status"`
    Target     string   `json:"target,omitempty"`     // 从 intent.args 提取的 url/host,已归一
    Summary    string   `json:"summary"`              // trace 文本的单行摘要(能力=.. facts=.. findings=..)
    RequestIDs []string `json:"request_ids,omitempty"`
    At         string   `json:"at"`
}
// SearchTraces 按可选 capability / host / 关键字过滤,返回稳定排序(按 intent_id)的命中。
func (s *Store) SearchTraces(ctx context.Context, engagementID int64, q TraceQuery) ([]TraceHit, error)
type TraceQuery struct { Capability string; Host string; Keyword string; Limit int }
```

**实现要点**:
- 纯 SQL 读 `intents`(status in done/skipped/needs_approval 等已执行过的),按 `engagement_id` 限定,**不跨作业**。
- `Target` 从 `args` 里提 url/host 并归一(复用现有归一逻辑),便于"这个 host 我是不是已经 probe 过"。
- `Limit` 默认(如 50)防止喂爆 planner;超限截断并稳定排序。
- 不返回 trace 原文里任何可能的大段文本以外的东西 —— trace 本就是我们自己写的结构化行,确认无凭据。

**验收**:执行若干 intent 后,`SearchTraces(capability=probe)` 只回 probe 命中;`host=127.0.0.1:18080` 只回该 host;跨作业不串;结果按 intent_id 稳定;空结果不报错。

## 2. 喂给 planner `internal/engine` + `internal/planner`(P1)

**目标**:planner 每轮在构造 `ProposeRequest` 时,带上**相关 trace 摘要**(同 host / 同能力的已做步骤),让 LLM 和确定性规则都能"看到历史"。

**涉及**:`engine.go`(构造 ProposeRequest 处)、`planner/schema.go`(prompt 增一段"已执行步骤")。

**实现要点**:
- 在派下一步前,对候选目标 host 调 `SearchTraces`,把摘要(能力+target+结论计数,**不含 request_id 之外的细节**)放进 `ProposeRequest.PriorWork []TraceHit`。
- prompt 增一节"已执行(不要重复):`probe 127.0.0.1:18080/.git/config → 200, facts=1` …",明确要求 LLM **不要重复派已覆盖的只读探测**,除非有新 fact 使其值得重做。
- 确定性规则侧:派生规则加一个"去重守卫" —— 若同 capability+target 已有 done 的 trace,则不再派生同一步(幂等,避免空转)。
- **LLM 存档要含它看到的 PriorWork**,保持可回放。

**安全**:trace 摘要是我们自己生成的结构化文本,不是目标响应正文,**不构成新的 prompt injection 面**(不把目标可控内容塞进去);PriorWork 仍经 gate,LLM 据此的任何提议照样判档。

**验收**:构造"git 链已 probe 过"的账本 → planner 不再派第二次同目标 probe(确定性去重);LLM 分支:prompt 里出现"已执行"清单且 LLM 不重复派;planner 存档含 PriorWork;有新 fact 时允许重做不被误杀。

## 3. SPA 探索图/任务台展示(P2)

- 任务台或探索图节点上展示该 intent 的 trace 摘要(已有 trace 字段,改成可读呈现)。
- "这个 host 已覆盖 N 个只读探测"的小结,帮操作员看自治链到哪了。

**验收**:UI 能看到每个已执行 intent 的 trace 摘要;无凭据/正文。

## 4. 文档与验收

- README「引擎」段补:trace 跨轮检索让自治链少重复探测;纯读、不碰墙、不喂凭据。
- `scripts/acceptance-v02.ps1` 增断言:同 host 第二轮不产生重复 probe intent;SearchTraces 跨作业不串。

## 落地顺序

1. 模块一(SearchTraces 只读检索 + 稳定排序 + 不跨作业)。
2. 模块二(喂 planner:确定性去重守卫 + LLM PriorWork + 存档可回放)。
3. 模块三(SPA 展示)、模块四(文档 + 验收)。

**每步验收锚点**:检索纯读不发包;不跨作业;结果稳定可复现;确定性去重不误杀(有新 fact 可重做);LLM 存档含 PriorWork;trace 摘要零凭据/正文;档位墙与审批门不受影响。

## 一句话

youkai 已经会"走只读链、停在人前";v0.7 让它**记得自己走过哪** ——
不是多一种打法,是少走冤枉路:同一个目标不重复探,把规划预算留给没探过的地方。
