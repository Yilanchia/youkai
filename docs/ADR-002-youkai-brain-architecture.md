# ADR-002:youkai 架构 — 独立的只读取证脑,Go 事件引擎 + LLM planner

> 状态:已决定(2026)。承接 ADR-001(造脑不造平台、不追利用深度、只读到影响成立即停),
> 把"脑"从"改 Fairy 的 src/auto.js"升级为**独立 Go 项目 youkai**。与 ADR-001 冲突处以本文件为准。
> 读者:维护者 + 实现者。自包含,不依赖对话上下文。
> **更新(ADR-003)**:youkai 已转向 ARTEX 形态的自托管平台(Go 后端 + PostgreSQL + `go:embed` SPA)。
> 本文件的"CLI-only / 零依赖 / JSON 账本"被 ADR-003 更新;脑的四角色、两只手、档位模型、安全不变量全部保留。
> **再更新(ADR-004)**:"两只手 via MCP"改为**原生吸收** Fairy/Verdex 的单体实现(闸门成 youkai 原生脊柱);脑的四角色与安全不变量仍保留。

## 背景

ADR-001 把"脑"设想成 Fairy 内的一段有界 for 循环(模块八改 `src/auto.js`)。现已决定**另起项目**:
youkai 是独立的**事件驱动编排脑**,通过 MCP(stdio)调用两只"手":

- **Fairy**(MIT,v0.19,`D:\fairy_fairy`):web 手。scope 护照 / 逐请求审计 / 数据最小化 / 审批门 都是它的职责。
- **Verdex**(MIT,`D:\漏洞挖掘工作台`):二进制 / 固件 / 移动端 / 源码审计手。只读、只生成文本、离线、授权目标闸。

两只手都是 MIT、同作者、同一套"只读默认 + 人在环路 + 证据优先"哲学。youkai 原封不动复用,不改它们。

ARTEX 的强来自一套事件引擎:常驻 plannerLoop + N worker goroutine + 跨轮共享 todolist +
worker trace 检索 + 双图血缘,一路推到 `prove_goal`(含利用/横向/外带)。youkai 借这套**思想**
(不抄 AGPL 代码),但把终点从 `prove_goal` 换成"只读取证链走完、影响成立即停"。

## 决策总览

1. **定位**:"比 ARTEX 强" = 在它走不了的只读路上更强(自主度、覆盖、证据、不虚报),**不是**利用深度。
2. **能力分三档,按版本切**:
   - 档 1 只读取证(探测 / 比对 / 浏览 / 只读可达性)。
   - 档 2 证明级利用:HMAC 高授权 + 单次 `confirm`,单次最小动作,留证据,立即停。
   - 档 3 深度利用(getshell / 横向 / 外带):**不进开源版**,编译期隔离。
   - OSS 版 = 档 1 + 档 2。
3. **形态**:独立 Go 事件引擎 + 内嵌 LLM planner。
4. **真值**:Fairy 权威(scope / assets / 闸门);youkai 只持探索图 + planner 记忆 + worker trace。
5. **并发**:actor 模型(ledger-owner goroutine / planner goroutine / worker pool),零 Postgres,append-only JSON。
6. **技术栈**:Go,零运行时依赖,手搓最小 JSON-RPC over stdio 做 MCP 客户端。
7. **自带运行时,不依赖 DSH**:youkai 是独立 agent 运行时(自己的事件循环 + LLM 驱动 + MCP 客户端 + CLI),不作为 DeepSeek Harness 等宿主的插件运行;DSH 仅作架构参考。此处"独立平台"指**自带运行时**,**不是** ADR-001 拒绝的产品平台(UI / 守护进程 / 多租户);若日后要后者,须重开 ADR-001 专门决策。

## 写死的不变量(任何改动不得违反)

- **youkai 永不自己发请求打目标。** 每个碰目标的动作都是一次 Fairy MCP 调用,由 Fairy 重校 scope + 闸门。
  这一条让"比 ARTEX 安全"是**构造上成立**,不靠自觉。
- **自治循环只跑档 1。** planner 一旦想派档 2 动作,循环返回 `needs_approval` 停下,交还人类;
  人过 HMAC 高授权 + 单次 `confirm` 才执行,执行完即停。**档 2 永不进无人循环。**
- **LLM 只提议,不放行。** planner LLM 只能产出类型化 intent;批不批、领不领由闸门代码决定,与 LLM 无关。
  目标响应攻击者可控(prompt injection 面),所以安全不能靠 prompt,只能靠 Fairy 的闸门 + youkai 内的代码闸。
- **永不自动 approve、永不自动利用、永不把 candidate 改成 verified、失败不重试。**
- **档 3 自动利用内核不随本仓库发布,也不在本仓库实现。** 自治循环结构上无法调用任何档 3 动作:
  档 3 走 Go build tag(如 `//go:build youkai_full`)编译期隔离,不是运行时开关能翻的;循环遇任何利用动作一律停、交人。
  本文件及一切 OSS 文档不描述档 3 内部。隔离的"墙"属于安全机制;墙后的自动深度利用内核不在本仓库、由维护者在别处自理。
- 每条结论携带四样:证据(`request_id` + 审计位置)、最小影响、停止点、反证说明。否则不进报告。

## 架构:四个 goroutine 角色

```
ledger-owner   串行所有写入,append-only JSON(.youkai/explore.json);唯一可写探索图的角色
planner        被"账本变了"的 debounce 信号唤醒;读探索图 → 调 LLM 产 intent → 落单(只读)
worker pool    领依赖已满足且已放行的 intent → 调 Fairy/Verdex MCP 执行 → 把观察送回 owner
mcp-client     手搓 JSON-RPC over stdio,拉起 Fairy(web)与 Verdex(binary)两个子进程,两套工具都走这里
```

- **探索图节点**:goal / intent / fact / finding / hint,边记血缘(ARTEX 式),锚到 Fairy 账本的 asset/endpoint。
  图跨 web 与 binary 两域:web 侧样本经 `fairy_handoff` 落成 artifact 资产,youkai 据此派生 Verdex 只读分析 intent,
  binary 侧的 `file:line` 发现再回灌同一张图。
- **worker trace**:每个 worker 执行过程存进探索图,planner 下轮可检索复用,减少重复探测。
- **LLM planner 可复现**:每次调用(prompt / model / temperature / 原始补全 / 解析出的 intent)全部落账当证据。
  否则内嵌 LLM 会毁掉 Fairy 现在的"可复现"领先项。

## 安全边界与两只手的分工

- **Fairy(web 手,权威)**:scope 护照、逐请求审计、数据最小化、审批门、worker 动作白名单、high-auth 闸。
- **Verdex(binary 手,权威)**:只读、只生成文本、离线、不执行样本、授权目标闸;`pwn_*` / `impact_proof` 只产人工审阅后亲自运行的文本。
- **youkai(脑,无特权)**:调度、探索图、LLM 规划、事件循环。youkai 没有任何绕过 Fairy 闸门的路径,
  因为它根本不发目标请求。档 2 的放行仍是 Fairy 的 high-auth + `confirm`,youkai 只是停下来等人。

## 与 ARTEX 的本质区别(必须写死)

ARTEX 循环跑到 `prove_goal`(含利用/外带),planner 和 worker 都能直接打目标;
youkai 循环跑到"影响成立即停",自治段只读,利用段必须人过闸,且脑**无直接打击能力**。
这不是性能差异,是定位差异,不可妥协。

## 落地顺序

1. MCP 客户端(stdio JSON-RPC)+ 拉起 Fairy 与 Verdex + 跑通 `fairy_scope_init` / `fairy_planner_tick` / `fairy_worker_run` 和 `verdex` / `analyze_target`。
2. ledger-owner + 探索图(append-only JSON)+ 把 Fairy 账本锚进来。
3. 确定性事件循环:worker pool 领只读 intent、调 Fairy/Verdex、回灌 fact、debounce 唤醒 planner,
   直到遇档 2 / 审批 / 敏感数据停。web 侧样本自动经 `fairy_handoff` 交 Verdex 做只读分析,结果回灌同图。
4. 内嵌 LLM planner:类型化 intent schema + 调用全落账;先只在确定性规则没覆盖时补位。
5. worker trace 检索 + 探索图可视化(只读 HTML 时间线,延续 ADR-001 的"要可视化就出只读 HTML")。
6. 档 2 人控利用闸(复用 Fairy high-auth),自治循环在它前面停。

**验收锚点(每步)**:越界请求 0;自治段无一次自动 approve / 自动利用;每条 finding 带 `request_id`;
planner LLM 调用可回放。

## 一句话

ARTEX 证明"AI 能自己跑到 `prove_goal` 并因此出事";youkai 要证明"一个没有直接打击能力的脑,
能自己把只读取证链走完、在该停的地方停下,利用只在人过闸时发生一次"。前者已有人做且已出事,
后者还没人做好 —— 这就是 youkai 能走、且只有 youkai 这种定位能走的路。
