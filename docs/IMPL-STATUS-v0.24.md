# IMPL-STATUS v0.24 — 模型当大脑,平台当闸

> 日期:2026-11-16 · 承接 ADR-007 + DEVPLAN-v0.24 · `go test ./...` 全绿
> **这是方向校正,不是新能力**:主循环从"规则派单、模型补位"翻成"模型主导规划、规则兜底"。

## 一句话

以前模型只在规则想不出东西时被叫来补一刀;现在**每一轮它先说话**,规则退成兜底。
但每个动作能不能真跑,仍然由 `gate` + `Guard` + 人决定 —— 模型被策反,也只能"想",发不出越界的包。

## 模块一 · 主循环翻转(`internal/engine/derive.go`)

```
derive():
  ① 模型规划(modelShouldPlan → propose)   ← 现在是第一顺位
  ② 规则表(bootstrap/chains/…/proof)      ← 只在①不可用时兜底
```

三个"不打扰模型"的条件(`modelShouldPlan`):

- 没配模型;
- 本轮 run 的**规划预算**用完了(`-plan-rounds`,默认 24 —— 成本上限,不是安全边界);
- 已经有**可领取的档 1 工作**在排队(边跑边重新规划只是空转)。

模型不可用/报错 → 记一行"模型不可用,改用内置规则:…",然后**照旧用规则跑**。平台不瘫。

### 一个必须焊死的洞(这次真踩到了)

`propose()` 原来**原样接受**提议里的 `Tier`。也就是说:一个被注入的模型把 `param` 标成
`tier: 1`,它就能绕过审批直接执行。

现在 proposal 进账本之前**重新过 `gate.Explain`**:档位、是否需批准、gate 理由,全部由平台重算。
测试 `TestModelProposalStillPassesTheGate` 直接把"模型自称 tier 1 的 param"喂进去,断言它照样
`needs_approval`。**这正是 ADR-007 那句话的代码形态:模型决定想做什么,闸决定那要付什么代价。**

## 模块二 · 让模型看得全(`ProposeRequest` + prompt)

`ProposeRequest` 新增(全部是账本投影,零正文):

| 字段 | 内容 |
|---|---|
| `Hypotheses` | 白盒线索(entry/param/sink/path),prompt 里明确标注"未证实" |
| `Pairs` | 已声明的身份与归属(owner/viewer/资源/标记) |
| `Tools` | 能力白名单**带档位**,让模型自己知道哪一步会停下等你 |

prompt 开头现在是角色说明,不再是表单:

> 你是这次授权渗透测试的规划大脑…… **边界由平台强制,不由你自觉**:档 1 直接执行,档 2 停下等点头,档 3 不存在。

## 模块三 · 对话/托管

v0.22 的托管循环原样保留,只是每轮 derive 改成模型先说话;`derive` 事件现在播的是
**"模型规划:N 个新步骤"**,失败时播"模型不可用,改用内置规则:…" —— 时间线上能直接看出
这一轮是谁在拿主意。

## 模块四 · 可回放与兜底

- 每次规划(prompt / raw / parsed / rejected)照旧落 `planner_calls`;
- 拔掉 key:`modelShouldPlan` 直接 false → 规则主导,行为退回 v0.23;
- 模型报错:同上,并留一行原因。

## 验收

```
engine  TestModelPlansBeforeRules          模型先被问,它的提议成为实际执行的工作,且标 Inferred
        TestModelProposalStillPassesTheGate 模型自称 tier1 的 param 被重判为 tier2,停在 needs_approval
        TestRulesStillRunWithoutAModel     没模型时规则照跑
        TestBrokenModelFallsBackToRules    模型报错 → 兜底 + 记录原因
        TestModelSeesTheFullSanitisedPicture 提议请求里带假设/身份/带档位的工具
planner TestPromptGivesTheModelTheBrainRole 角色 + 档位边界 + per-tool tier
        TestPromptDoesNotCarryBodies       无 HTTP/1.1、无 Set-Cookie、无 Bearer,证据流水号还在
        TestPromptShowsHypothesesAndIdentities 线索标"未证实",身份可见
```

## 没做的(如实)

- **没接真实模型做端到端验证**:仓库里没有可用的 API key,这次的"模型主导"由
  `recordingProposer`(假模型)证明管线正确;真模型下的**规划质量**要等有 key 时测。
- **`planner_calls` 的 UI 回放没有做**:表里有记录,界面上还没有"看它当时怎么想"的入口。
- **规划预算按轮计**:一个托管会话有很多轮,每轮各自 24 次;没有做"整个会话总共几次"的全局上限。
- **规则表没删**:它仍然存在,是兜底;没有按 ADR-007 的"规则退居二线"再做精简。

## 一句话

**智能是模型给的,敢托付是平台给的。** 这一版把前半句兑现了,后半句一个字没松。
