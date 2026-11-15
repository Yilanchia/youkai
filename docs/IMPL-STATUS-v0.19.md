# IMPL-STATUS v0.19 — 规划智能加深(会想,不只是会做)

> 日期:2026-11-15 · 承接 DEVPLAN-v0.19 · `go test ./...` 全绿
> 新增:`chainlib.go`(链型表)、`reflect.go`(结果复盘)、`plan` 卡片带推理与依赖、
> `order.go` 两个新维度、`POST /intents` 支持 `deps`。

## 一句话

youkai 现在会**先说自己怎么想的**,再给一条**有顺序**的链 —— 而链上的每一个档 2 节点,
仍然各自停在你面前等你点头。

## 模块一 · 多链型(不止 IDOR)

`chainlib.go` 把链做成一张**声明式表**(前置条件 + 步骤模板 + 依赖),而不是 if 语句:

| 链型 | 前置条件 | 步骤 |
|---|---|---|
| `idor` | 代码侧入口 + 两个身份 + 资源 URL | provision → provision → **compare** |
| `bfla` | 代码侧入口 + 两个身份 | provision → provision → **role_matrix** |
| `ssrf` | 白盒 `sink=ssrf` 线索 | **param(ssrf)**,档 2 |
| `authz-after-weak-auth` | JWT/OAuth 发现 + 两个身份 | provision → provision → **role_matrix** |

- **覆盖所有 pair**,不只第一个(测试:两个对象 → 两条 compare);
- 同类同目标同身份**只组一次**;
- 节点**共享**:两条链都要"alice 登录",就只有一个登录 intent —— 去重靠指纹,不靠人;
- 每个节点仍 `gate.Classify` 定档,tier-2 一律 park。

### 评审点名的那条:组链 ≠ 自动执行

我在实现时**真的踩到了这个坑**,也因此把它焊死了:

> 普通规则 `ruleBolaCompare` 先派生了 compare(没有依赖),链再给它补依赖时它**已经跑完了**。

修法两层:

1. **链在规则表里排在 bootstrap 之后、其余规则之前** —— 先建带依赖的版本,后面的规则自然去重;
2. **链与普通规则用完全相同的参数形状**,于是它是"采纳"那条 intent 并挂上依赖,而不是造第二条;
3. 补一条硬规则:已执行(`done`)的节点**不再被追挂依赖**(不许假装它当时在等)。

测试 `TestChainNeverRunsItsOwnTierTwoNodes` 直接钉这条:跑完一轮后,两个登录必须仍在
`needs_approval`,compare 必须仍未 `done`,且 dispatcher 从没收到过 `accounts_provision`/`compare`。

## 模块二 · 结果复盘(会想的核心)

`reflect.go`:每一步跑完,产一条**复盘**,写进 trace 和图(Fact,tag `reflection`)。

| 情形 | 复盘说什么 |
|---|---|
| 线索命中 | "线索 #N 已被黑盒证实 —— 代码与运行双证据"(`hypothesis-confirmed`) |
| **线索没命中** | "白盒线索 #N **未被证实** —— 代码看着可疑但运行没复现,如实记为未证实,**不据此继续推断**" |
| 源码摄取完成 | "白盒线索进入账本,后续探测按线索优先级排列" |
| 普通步骤 | **不说话**(沉默好过噪音) |

`TestReflectionIsHonestOnAMiss` 显式禁止这些词:`可能还需要`、`值得再试`、`建议继续`、`换个载荷` ——
一旦有人在复盘里写"再试试",测试就红。这正是"没命中就说没命中"的机械化。

复盘还会影响排序:`lastReflections` 里出现"被证实"时,同类探测 +1 权重。

## 模块三 · 把"为什么"讲给人听

`plan` 卡片长出了三样东西:

- `reasoning`:**"我是这么想的"** —— 从哪几条事实/线索推出来;
- `after`(每步):依赖前面第几步 → 前端显示"依赖第 1、2 步";
- `stops_at`:**由服务端按 `gate.Classify` 算出** —— 模型不能靠"忘了说"让档 2 步骤看起来能自走。

对话界面按这个渲染:`理由块` → 编号步骤(每步带"需你点头"或"只读,自动跑")→ 一键按序排入
(排入时把依赖 id 一起提交,`POST /intents` 新增 `deps` 字段,校验必须属于本作业)。

状态行也会显示最新一条复盘,例如"这一轮跑完了:22 次请求、7 条发现 · 复盘:线索 #11 已被证实…"。

## 模块四 · 排序维度加深

新增两项,理由仍然可读:

- **链上关键步 +4**:别的步骤在等它(`dependedOn` 直接读依赖图,不是猜);
- **刚有线索被证实 +1**:让探测集中在有回报的方向,而不是四处撒网。

## 验收

```
engine  TestChainNeverRunsItsOwnTierTwoNodes   链组好后档 2 仍 park,compare 不跑
        TestMultipleChainTypesAssemble        idor/bfla/ssrf 同时组装,各自有终点步
        TestChainsCoverEveryPair              两个对象 → 两条 compare
        TestChainCriticalStepRanksFirst       阻塞步排第一且理由可读
        TestReflection* (4)                   命中/未命中的措辞、沉默、落图
planner TestPlanCardCarriesReasoningAndStops   reasoning + after + stops_at
        TestPlanDependencyMustPointBackwards   前向/越界依赖被丢弃
        TestPlanStillCannotSmuggleTierTwo      plan 仍不能夹带档 2
```

## 没做的(如实)

- **规划质量 bench**(模块五)没做:bench 还没有"到一条 verified 用了几步/几次点头"的指标。
- **复盘驱动组链**这一层只做了排序影响:复盘不会**新组**一条链(新链仍靠证据出现时的规则)。
- **对话里的链式提案依赖模型主动写 `after`**:模型不写,就是一条扁平计划(仍是合法计划,只是没有顺序)。
- **`authz-after-weak-auth` 的"认证弱点"判据**只看 findings 里有 jwt/oauth 类,没有细到"哪种弱点该配哪种链"。

## 一句话

聪明长在"想清楚下一步"和"把想法讲明白"上 —— 三个模块都只改了**选路和解释**,
没有一处让它多走一步它本来不该走的路。
