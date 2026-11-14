# IMPL-STATUS v0.12 — 拆签名墙、对话历史、自主跑通

> 日期:2026-11-15 · 承接 DEVPLAN-v0.12 / ADR-006 · `go test ./...` 全绿
> 新增:`chat_messages` 表、`GET /chat`(历史)、`POST /intents/{id}/reject`、
> 对话面板里的"需要你点头"卡片、`require_high_auth` 开关(默认关)。
> **这是一次减负,不是一次放松** —— 见下面"没变的四样东西"。

## 一句话

把那道逼你签名的墙拆了,换成一句"批不批?"的点头。AI 自己在只读里跑完,碰到有风险的就停下等你 ——
人类把关一分没少(还是一次批准、一次执行、批准即焚),折腾没了。

## 一 · 拆掉签名墙(默认 UI 点头)

| | 之前(ADR-005) | 现在(ADR-006) |
|---|---|---|
| 档 2 执行前置 | 批准行 **+ 签名记录** | 批准行(**一次点击**) |
| 没有 `FAIRY_AUTH_KEY` | 网络目标一律 412 拒绝 | 正常执行,只用批准行 |
| 钥匙弄丢了 | 整个工具卡死 | 无影响 |

- `executeIntent` 的高危前置从"必须有签名记录"降级为"**只有** `require_high_auth=true` 时才要"。
- 新开关:`-require-high-auth` / `YOUKAI_REQUIRE_HIGH_AUTH=1`(默认 **关**)。
  打开后逐字恢复 ADR-005 的行为,签名校验一个字没删。
- `approveIntent`:`high_auth_path` 变成可选;`basis` 空或过短时自动填
  `operator approved in the UI @ <时间>`,让审计行可读,而不是把点击打回去。

**没变的四样东西**(都有测试钉住):

1. 批准行必须存在,且绑定指纹 —— 没有批准行的 execute 仍然 403;
2. 批准一次性消费 —— 第二次 execute 403(有测试);
3. `candidate → verified` 仍然只能人点;
4. `discipline.Guard`、逐请求审计、档 3 墙,一个字没动。

**红线**:对话/规划器代码路径不得触碰审批。新增 `TestChatPathCannotApprove`,
直接读 `chat.go`、`planner/chat.go`、`web/chat.js` 的源码,出现
`ApproveIntent`/`ConsumeApproval`/`executeIntent`/`approveIntent` 就失败。

## 二 · 对话历史:持久化 + 渲染

- 新表 `chat_messages`(engagement_id / role / content / cards / created_at),
  **append-only 触发器**:`UPDATE`/`DELETE` 直接抛异常 —— 历史是记录,不是草稿纸。
- `POST /chat` 先存 user 一轮,再存 assistant 一轮(**即使模型失败,问题也留在记录里**);
  `GET /chat` 按时间返回全部。
- 面板进入时先拉历史,刷新、切面板再回来都还在;卡片按原样重新渲染(每个按钮都能再点)。
- 存的只有"人说的话"和"模型说的话":**没有响应正文、没有 header、没有凭据**。

实测:问了两轮 → 刷新页面 → 四条消息按序回来。

## 三 · 自主跑通 + 对话里点头

对话面板现在有三段,从上到下:

1. **状态行**:`正在自主跑只读检查…` / `停在第 N 个动作前,等你点头` / `这一轮跑完了:22 次请求、7 条发现`
2. **点头卡**:要做什么、对哪个目标、为什么停、「批准并执行」/「拒绝」
   - 批准 = `approve` + `execute` 两步(仍然是同一个一次性批准行)
   - 拒绝 = 新端点 `POST /intents/{id}/reject`,`blocked` + 一行 trace
3. **对话流**:历史消息 + 卡片

实测(无 `FAIRY_AUTH_KEY`):

```
只读自治  → 9 步 / 16 请求 / 7 条发现,自己跑完
param 排队 → 引擎停在 needs_approval
点批准    → 200,执行一次(trace: approval=2, operator=operator)
再点      → 403(批准已消费)
```

## 四 · 和 ADR-005 的关系(说明白,不含糊)

ADR-006 **回收**了"签一份委托书、整站预授权动作类"。落地方式:

- 委托书代码保留(有测试),但**引擎默认根本不读它** —— `RequireHighAuth=false` 时
  `loadMandate` 直接返回空(新测试 `TestMandateIsIgnoredWithoutHighAuthMode` 钉住)。
- 也就是说:默认构建里**不存在**"整站预授权"这条路径;只有显式打开
  `require_high_auth` 的部署才恢复它。
- 对话面板对 `mandate_draft` 卡片也改了口吻:标注"高级用法,默认不需要"。

## 验收

```
api       TestExecuteNeedsOnlyAnApprovalByDefault   一次点击即可执行、再执行 403
          TestExecuteWithHighAuthRequired           开开关后恢复 412/403/签名校验
          TestChatHistoryOverHTTP                   历史落库、按序返回
          TestRejectClosesTheStep                   拒绝 → blocked,不派发
          TestChatPathCannotApprove                 对话路径不许碰审批(读源码)
          TestMandate* (6 个)                       委托书仍只在 high-auth 模式生效
ledger    TestChatHistoryRoundTrip / TestChatMessagesAreAppendOnly
engine    TestMandateIsIgnoredWithoutHighAuthMode  + 原有 7 个委托书测试
CI        invariants 增加 chat_messages_append_only_trg 与对应拒绝测试
```

## 与 DEVPLAN-v0.12 的差异 / 未做

- **委托书没有删代码,只是默认不生效**。删掉它要动引擎、API、UI 三处并重写 9 个测试;
  用 `require_high_auth` 关住它,风险小得多,而且 ADR-006 想恢复的语义(默认没有整站预授权)已经达成。
- **`reject` 是新端点**(DEVPLAN 只说"标 blocked",没给端点)。做成端点是为了让拒绝进审计。
- **对话仍是"一问一答"**,没有流式输出,也没有多轮上下文记忆(每次只带账本摘要)。
- **点头卡只覆盖需要批准的步骤**,不覆盖敏感命中(sensitive_stop)的单独提示 ——
  敏感命中目前通过发现本身和运行记录体现,下一轮可以做成同样的卡片。
