# DEVPLAN-v0.21:像 harness 一样,看得见 agent 每一步在做什么

> 交付对象:实现者(DeepSeek)。配 v0.20(对话开工)、ADR-006(点头)读。**纯体验改造,不加能力、不碰红线。**
> 目标:让对话/界面像 Claude Code 那种 harness —— AI 每调一个工具、每出一个结果,操作员**实时看得见**,
> 而不是点了开始盯着闷界面等 run 憋完。这直接治"看起来啥也没干"的病根。

## 0. 现状与缺口(已核实)

- SSE 管道**通的**:`broadcaster` + `/…/events` + 前端 EventSource,token 走 query。
- run **后台 goroutine 跑**(`startRun` 里 `go func()`),引擎每步产一个 `StepRecord`(能力/档位/结果/request_id)。
- **缺口**:事件只在"大节点"发 —— 建作业、批准、执行档2、**run 整个跑完**(`run_finished`)。run 跑的中途十几步(scan→发现→probe→命中…)**一个都不播报**。所以从"开始"到"跑完",界面是哑的。harness 的爽感正来自这些中间步骤的实时流,而现在没有。

## 0.5 不可动摇(继承)

- 事件只是**播报**,不改变执行:仍过 Guard、档 2 仍停人前、candidate≠verified、AI 不自执行。
- 事件内容**脱敏**:只带能力名/目标 URL/档位/结果摘要/request_id/facts 计数,**不含响应正文、cookie、凭据、token、marker**(和账本/报告同一条数据最小化纪律)。
- 不新增打击能力;这一版只是把已经发生的步骤实时讲出来。

## 1. 引擎每步回调 hook `internal/engine/engine.go`(P0)

**目标**:引擎每执行完一步(含失败、跳过、停人前),就回调一个 `OnStep` 钩子,把这一步的脱敏摘要吐出去。

**改法**:
- `Config` 加可选字段 `OnStep func(StepEvent)`(nil 时零行为,确定性/测试不受影响)。
- `StepEvent` 脱敏结构:`{run_id, seq, phase, capability, tier, target, status, summary, facts, findings, request_id, reason}`。`phase` ∈ `derive|exec|reflect|stop`。
- 在 `execOne`/`execBatch` 每步完成、`reflect` 复盘、`park`/停止点处各发一个事件。**summary 复用现有 StepRecord 的脱敏摘要,不新读正文。**
- hook 必须非阻塞(发事件不拖慢 run);引擎不关心谁在听。

**验收**:单测用假 OnStep 收集事件,断言一轮 run 产出 derive→exec→reflect→stop 一串有序事件,且事件里无正文/凭据字段;OnStep=nil 时 run 行为完全不变。

## 2. 接到 SSE 广播 `internal/api/server.go`(P0)

**目标**:`startRun` 的后台 goroutine 把引擎 `OnStep` 接到 `hub.publish("run_steps", …)`,前端 SSE 实时收。

**改法**:
- 建引擎时传 `OnStep: func(ev){ s.hub.publish("run_steps", ev) }`。
- 新 SSE topic `run_steps`(或并进现有 run topic,带 `type:"step"`);保留 `run_finished` 作收尾。
- publish 仍非阻塞、丢弃满的订阅者(现有 broadcaster 语义)。

**验收**:起一个 run,SSE 端能实时收到一串 step 事件,顺序与执行一致,收尾有 finished;事件无敏感字段。

## 3. 前端像 harness 一样滚动展示 `web/chat.js` + `web/style.css`(P0,体验核心)

**目标**:对话里开工后,出现一个**实时滚动的步骤流**,每步一行,像终端 agent 那样:

```
▸ 扫描 https://target            tier1  ✓ 发现 5 个端点
▸ 探测 /search?q=                tier1  ✓ 命中参数反射 (R0007)
▸ 读 /.git/config                tier1  ✓ 200,git 配置可读 (R0009)
⏸ 想对 ?id= 做 SQL 存在性探测      tier2  等你批准 ▸[批准][拒绝]
```

**改法**:
- 订阅 `run_steps`,每事件追加一行:图标(进行/成功/未命中/停人前)+ 能力中文名 + 目标 + 档位 + 结果摘要 + request_id。
- 档 2 停人前的那行**内联批准/拒绝按钮**(复用 v0.20 的 approve+execute+resume)。
- 顶部活动指示:`正在扫描(第 N 步)… / 停在档 2 等你 / 完成`。
- 每行只渲染事件里的脱敏字段;**前端拿不到正文,也不显示**。
- run 跑完后这段步骤流留在对话历史里(持久),刷新还在(复用 chat 历史或新的 run-steps 读取)。

**验收**:对话开工→步骤一行行实时冒出来(不是跑完才一次性出现);档 2 那行能就地批准继续;刷新后历史步骤还在;界面无正文/凭据。

## 4. 把"它在想什么"也播出来(P1,接 v0.19 复盘)

**目标**:不只播"做了什么",也播"为什么走下一步"(复用 v0.19 reflect 的复盘结论)。

**改法**:reflect 复盘结论作为 `phase:"reflect"` 事件播出,前端用浅色小字显示在对应步骤下:`↳ 命中确认了"git 泄露"假设,接下来看 /config 目录`。没命中就如实显示"未证实,不继续推断"(延续诚实纪律)。

**验收**:命中/未命中的复盘都实时显示;措辞诚实不臆造;无正文。

## 5. 收尾

- README「对话式用法」配一张步骤流示意;bench 不涉及。

## 落地顺序

1. 模块一(引擎 OnStep hook)+ 模块二(接 SSE)—— 管道,先通。
2. 模块三(前端滚动步骤流 + 内联批准)—— 体验核心。
3. 模块四(复盘播报)。

**每步验收锚点**:步骤实时流出(非跑完才出)、顺序正确、档 2 就地点头;事件/界面零正文零凭据;OnStep=nil 行为不变;
过 Guard、档 2 停人前、candidate≠verified 全不变;`go test ./...` 全绿;门禁仍过。

## 一句话

把 youkai 从"点了开始、盯着闷界面等结论",变成"像看终端 agent 一样,它每扫一下、每发现一点、每要冒险一步,你都当场看见" ——
看得见,才信得过;信得过,才用得下去。能力一点没加,但它第一次像个真的 agent。
