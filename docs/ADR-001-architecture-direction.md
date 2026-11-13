# ADR-001:对标 ARTEX 的架构方向 — 造脑,不造平台

> 迁移说明(2026,随 youkai 项目新建时补):本决策原写于 Fairy 仓库,假设"脑"作为模块
> 内建进 Fairy 的 `src/auto.js`。现已决定**另起独立项目 youkai 做"脑"**,Fairy 原封不动留在
> `D:\fairy_fairy` 继续当"手"(MCP 工具)。因此下文"要造的(脑)"部分在 youkai 里是**新建**,
> 不是改 Fairy;凡提到"Fairy 内部循环 / 改 src/auto.js"的,在 youkai 语境下理解为"youkai 的编排层,
> 通过 MCP 调用 Fairy 的 planner/worker/auto_run"。决策本身(造脑不造平台、不追利用深度、
> 只读到影响成立即停)完全不变。

> 状态:已决定(2026)。本文件是方向性决策,优先级高于具体实现;与 DEVPLAN-v0.18 配套。
> 读者:维护者 + 实现者(DeepSeek)。自包含,不依赖对话上下文。

## 背景:ARTEX 到底是什么(从官方仓库核实,非二手转述)

ARTEX(RuoJi6/ARTEX,源 Autumn-27/ARTEX,**AGPL-3.0**)是 LLM 多 agent 自主渗透系统。
核实到的真实架构:

- **技术栈**:Go 单体后端(`go:embed` 把 Next.js 前端内嵌成单二进制)+ **PostgreSQL**;
  Docker / 预编译二进制部署,`http://localhost:8787`。
- **agent 能力来自独立 SDK [`norma`](https://github.com/Autumn-27/norma)**:
  `agentcore / tool / permission / harness / memory / transcript`。**ARTEX 没有手搓 agent 循环,
  而是把可复用框架拆成了 SDK** —— 这是你问的"它有没有自己的 agent 框架"的确切答案:有,叫 norma。
- **双图**:资产图(全局跨任务真值)+ 探索图(每任务,goal/intent/fact/finding/hint 血缘链),
  靠 `exploration_anchors` 锚点相连。
- **事件驱动引擎**:每任务一个 `plannerLoop` + N 个 worker goroutine;图一变 debounce 唤醒
  planner → 派意图 → worker 领一条、真实工具执行、写回两图 → 触发下一轮,**直到 `prove_goal`**。
  planner 是唯一意图生成者,每次唤醒是全新会话。
- **worker 过程级信息交换**:`search_all_worker_traces` / `get_worker_trace`。
- **planner 共享 todolist**:按任务跨唤醒常驻,串行利用链记录一次、按依赖逐步派。
- **完整 Next.js 控制台**:仪表盘/任务/资产/覆盖图/流量录制/人在环路对话/Agent 管理/LLM 配置/
  拦截审批/日志。有在线 mock demo。
- **配套**:MITM 流量录制代理、工具审批门、ScopeSentry 资产同步、漏洞归并统一报告、复测 Agent、
  任务情报(可记凭据,默认关)。
- **许可姿态**:LICENSE 声称"仅本地学习、禁止对任何线上系统(含自有/授权)测试"。这与它内置
  Kali/MITM/24x7 自治 fork 的事实冲突,是法律免责挡箭牌。

## 决策

**追 ARTEX 的"规划自治",不追它的"平台形态",更不追它的"利用深度"。一句话:造脑,不造平台。**

### 为什么不追利用深度(最重要)

ARTEX"走得远",很大一部分是因为它**做危险的事**:利用、提权、横向、外带、记凭据、24x7 无人
值守狩猎。Fairy 刻意不做。所以:

- Fairy 在"利用深度"上**永远追不上,也不该追**。
- Fairy 唯一的护城河是 **授权 + 只读默认 + 写死闸门 + 证据可复核**。加自动利用 = 亲手拆掉护城河,
  还背上 ARTEX 自己都紧张的法律暴露。
- **"能走多远"要重新定义**:不是朝利用深度走多远,而是朝 **"自主的、可辩护的、授权范围内的取证"**
  走多远。这是一条 ARTEX 没走、也走不了(它的定位决定了)的路。

### 要造的(脑)——真正的能力缺口

Fairy 的 planner/worker/auto_run 现在是**一组函数**,得靠外部模型一轮轮调;ARTEX 的对应物是一个
**常驻的事件循环**。缺口就在这里。按 DEVPLAN-v0.18:

1. **账本驱动推断**(模块一):planner 从账本 host/endpoint/已存会话名派生 context,不再等人喂。
2. **观察回灌 fact**(模块二):worker 把 probe/compare/param 的可判定观察归一成 observed fact。
3. **常驻只读循环**(本 ADR 新增,见下):写回 → 自动再 tick → 领下一步,直到停止点。

**与 ARTEX 的本质区别(必须写死)**:ARTEX 的循环跑到 `prove_goal`(含利用/外带);
**Fairy 的循环跑到"影响成立即停",每到审批门 / 写方法 / 敏感数据就停,交还人类,永不自动 approve、
永不自动利用。** 这不是性能差异,是定位差异,不可妥协。

### 不造的(平台)——会毁掉定位的东西

- **不做 Next.js UI**。ARTEX 需要 UI 因为它是**产品**(pentest team in a box);Fairy 是**挂在 AI 手上
  的授权工具层**。UI 会把 Fairy 从"工具"推成"平台",模糊定位、暴增维护面。要可视化,就出**账本的
  只读 HTML 时间线**(账本已是 JSON,生成一个自包含 HTML 即可),到此为止。
- **不上 PostgreSQL**。JSON 账本在 Fairy 的规模(单算子、单 engagement)完全够用,且"可读 / 可 diff /
  不联网"本身就是安全属性。ARTEX 上 PG 是为了并发多 worker goroutine + 跨任务共享资产图,Fairy 没有
  这个并发模型。
- **不做常驻 MITM 代理 / 守护进程式产品**。Fairy 保持 CLI + MCP(stdio)+ 零运行时依赖。
  "循环"是一次调用内跑完的有界循环,不是后台长驻服务。

### 可借鉴,不可抄

ARTEX 与 norma 都是 **AGPL-3.0**;Fairy 是 **MIT**。只借架构**思想**(双图、planner/worker、
共享 todolist、事件循环),**不复制任何代码**。STRATEGY.md 已有此约束,这里重申。

## 新增实现:常驻只读循环(模块八,接在 DEVPLAN-v0.18 模块一、二之后)

**目标**:把"写回 → 再 tick → 领下一步"做成 Fairy 内部的有界自动循环,让 `fairy_auto_run` 真正
自走只读链,而不是每步回到外部模型。

**涉及文件**:`src/auto.js`(改)。不新增守护进程、不新增依赖。

**改法要点**(在现有 `autoRun` 的 for 循环基础上):
- 每执行完一步 worker action 并写回 fact 后,**不返回**,继续下一轮 `plannerTick`——因为新 fact
  可能让下一条链 ready / 让 deriveContext 派生出下一步 work。
- 循环的**硬停止条件**(命中任一即 `return`,绝不跨越):
  1. `recommendation !== "claim_next"`(没有可领的只读下一步);
  2. 领到的意图 `requires_approval && !approved`(审批门)——返回 `status:"approve"`;
  3. 意图的 work 是**写方法 / 主动探测 / 需额外授权的动作**(param/param_adaptive/compare 写向、
     登录、seed、register)——返回 `status:"needs_approval"`,**即使 scope 开了开关也要人确认**;
  4. worker 结果里出现敏感数据命中标志——返回 `status:"sensitive_stop"`;
  5. 达到 `max_steps`(保留现有上限 10)。
- **永不**在循环里调用 `approveIntent`;**永不**把 candidate 改成 verified;失败不重试(保留现状)。

**验收测试(tests/auto.test.mjs 扩展)**:
- 账本有 git-source-leak 链 + host 资产,不喂 context、不预声明 work,`fairy_auto_run` 自动:
  派生 context → 落单 → 领 step1 probe → 执行 → 命中 `.git/config` 回灌 fact → 再 tick,
  **直到遇到需审批的 step 停下**,全程无人工介入且无一次自动 approve。
- 构造一个 work 是写方法的意图,循环在它之前停在 `needs_approval`,不执行。

## 落地顺序

1. DEVPLAN-v0.18 模块一(账本派生 context)+ 模块二(观察回灌)。
2. 本 ADR 模块八(常驻只读循环)。做完 = Fairy 能自主走完**只读**链、遇写/审批即停。
3. DEVPLAN-v0.18 模块三(账号清单层),解决测试账号痛点。
4. 其余按 DEVPLAN 优先级。

## 一句话

ARTEX 证明"AI 能自己跑到 prove_goal";Fairy 要证明的是"AI 能自己把**只读取证链**走完,然后在
该停的地方停下,留下一份能复核、能修复、能披露的证据"。前者已有人做且已出事;后者还没人做好,
这就是 Fairy 能走的、且只有 Fairy 能走的路。
