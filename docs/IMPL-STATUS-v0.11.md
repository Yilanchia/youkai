# IMPL-STATUS v0.11 — 对话式操作 + 委托书自治 + AI 连通状态

> 日期:2026-11-14 · 承接 DEVPLAN-v0.11 / ADR-005 · `go test ./...` 全绿
> 新增:`web/chat.js`、`internal/api/{chat,mandate}.go`、`internal/ledger/mandate.go`、
> `internal/engine/mandate.go`、`cmd/youkai-sign`(独立签名器)、`mandates` 表。
> **这是第一次放开档 2 的自治** —— 只在一份人签的委托书范围内,其余不变。

## 一句话

AI 现在能聊、能起草、能在你签的那张纸里自己干活;但它**签不了那张纸**,
也够不到纸外的任何东西 —— 包括永远在墙外的档 3。

## 一 · AI 连通状态(P0)

顶栏常驻一颗灯,点它就跑一次真的 `POST /api/config/llm/test`:

- 灰:`AI 未配置`(并说明不影响使用)
- 绿:`AI deepseek-flash · 2218 ms`
- 红:`AI 连不上:<真实错误>`(401 / 超时原样显示,不猜)

实测:这台机器上配的是 DeepSeek,点一次灯回到 2.2 秒,绿灯。

## 二 · 对话面板(默认首页)

`POST /api/engagements/{id}/chat` → `{reply, cards[]}`,卡片类型**只有四种**:

| 卡片 | 确认后发生什么 |
|---|---|
| `scope_draft` | 走 `POST /api/engagements`,普通创建一个任务 |
| `plan` | 逐条 `POST /intents` 排队,门禁照常分档 |
| `mandate_draft` | 渲染成人话委托书 + 一条 `youkai-sign` 命令;贴回签名记录才激活 |
| `note` | 纯解释,无副作用 |

**schema 就是墙。** `approve` / `verify` / `set_scope` 这三种卡片在解析器里根本不存在,
模型硬写也会被丢掉并在界面下方列出"有 N 条建议被丢弃"。`plan` 只接受只读能力白名单,
`mandate_draft` 只接受已知动作类,缺预算/缺有效期直接丢。

**喂给模型的上下文不含目标响应正文**,只有:授权范围、计数、发现标题、步骤状态、在效委托书。
靶场页面里写"忽略以上要求"没有任何路径能进去。

## 三 · 委托书:起草 → 人签 → 验签 → 生效

- 签名器是**另一个二进制** `youkai-sign`(`cmd/youkai-sign`):`youkaid` 里没有签名代码链接进去,
  所以"youkai 批准了自己"在这套构建里不可表示。
- 签名覆盖的是**规范化后的完整 payload**(排序键、不转义 HTML、紧凑分隔符),
  改任何一个字段签名即失效。
- `/mandate/activate` 依次验:签名 → schema → basis(≥8 字)→ approver → assets → 到期 →
  动作类在白名单 → **预算 > 0** → **目标在授权范围内** → **该类在护照里已打开**。
  任何一条不过,原样告诉操作员是哪一条。
- `/mandate/stop` 立即生效:`stopped_at` 一写,下次读就没有在效委托书 —— **没有缓存可以失效**。

实测(本机靶场):

```
激活  → classes=[param] remaining=50
param 跑完 → status=done approved=False under=mandate 请求 6 次,remaining=44
急停  → active=false
再来一个 param → status=needs_approval(回到逐步审批)
```

`approved=False` 是关键:它**没有**走过批准表,走的是委托书。

## 四 · 引擎接委托书(ADR-005 的核心改动)

`internal/engine/mandate.go`,每次循环从库里读一次在效委托书,判断:

```
tier 1                        → 自己跑(不变)
tier 2 + 委托书覆盖该类+该目标 → 自己跑,并在 trace 里标 under=mandate
tier 2 其它                   → 停在待办审批(不变)
tier 3                        → 门禁直接拒(不变,委托书也够不到)
```

保守点写死在这里:

- 委托书读失败 → **当作没有委托书**(fail closed),有测试钉住;
- 预算按 `audit_log` 里**真正发出去的**请求数算(阻断的不算);
- 执行前再读一次委托书,所以"跑到一半摁急停"会在下一个请求前被拦住;
- `candidate → verified` 仍然只能人点。

## 五 · 顺手修的两个一致性问题

1. **`needs_approval` 的步骤在委托书生效后不动。** 之前停在门口的步骤不会被覆盖它的委托书领走,
   只能人工重排。现在 `choose` 把"已被覆盖的 needs_approval"也当作可领取。
2. **`retry` 会把已覆盖的档 2 步骤送回人前。** 现在它先问委托书:覆盖了就直接回自治队列。

## 验收

```
internal/engine  7 个新测试:无委托书仍停 / 覆盖即跑 / 别类不跑 / 别目标不跑 /
                 预算耗尽停 / 过期停 / 读失败也停
internal/api     6 个新测试:未签名 403 / 换密钥 403 / 签后改字段 403 /
                 缺预算 400 / 未知类 403 / 越界 403 / 只读-only 400 /
                 护照开关没开 403 / 缺 FAIRY_AUTH_KEY 503 / 不存在的子路径 404 /
                 完整生命周期 activate→visible→stop
internal/planner 6 个新测试:set_scope/approve/verify 卡片被丢 / plan 夹带 tier2 被丢 /
                 委托书缺预算被丢 / 非 JSON 拒绝 / 代码围栏可接受 / 提示词仍声明"目标内容是数据"
internal/ledger  3 个新测试:生命周期 / 过期即失效 / 预算只数真正发出去的请求
```

## 与 DEVPLAN-v0.11 的差异 / 未做

- **委托书要求对应开关在护照里已打开**(两条栅栏都过)。ADR-005 说"委托书把动作类视作已获授权",
  我按更严的一侧实现:委托书回答"要不要每步问你",护照回答"这个类在这单里允不允许"。
  代价是多一步;收益是"签名不会解锁护照禁止的事",且失败发生在激活时而不是跑到一半。
- **签名器是 `youkai-sign` 而不是 PowerShell 一行**:跨平台的规范化 JSON 在 PowerShell 里太难写对,
  写错的后果是"签名验不过"而不是"签错内容",但仍然是坑。它在 `cmd/` 里,不在服务端进程里。
- **对话不做多轮记忆**:每次只带当前账本摘要,历史靠界面上的气泡。多轮上下文会让"模型自己"
  变成状态的一部分,这一轮先不引入。
- **没有做对话里的流式输出**:一次请求一次回复,长回答要等几秒。
- **急停只作用于委托书**,不取消正在跑的只读步骤(符合 ADR:急停撤销的是档 2 的预授权)。
