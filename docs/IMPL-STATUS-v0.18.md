# IMPL-STATUS v0.18 — 补全 v0.15/16/17(反致盲闭环 / 多步链 / 认证补齐)

> 日期:2026-11-15 · 承接 DEVPLAN-v0.18(A/B/C 三组)· `go test ./...` 全绿
> 新增:`blind_context.go`(致盲标签下发)、`binflow.go`(二进制数据流线索)、
> `chain.go`(多步链)、`SetIntentDeps`、OAuth 流程加项、`header` 反射探针。

## A 组 · 反致盲闭环(先做的那块)

### 1. 标签真正用起来了

`blindForPath` 在 `secrets` 与 `dataflow` 之前跑一次同样的结构测量,拿到的
`clean / suspected-blinded / heavily-blinded` 决定**表面证据怎么算**:

| 原样 | blinded 之后 |
|---|---|
| 直接成为 finding(candidate) | 降一档 severity,并附 counter:"样本疑似经过对抗处理:这条属于**表面证据**,可信度降低" |
| info 级 / low 级命中 | 变成 `fact`,标签 `blinded, surface-only`,**不再计为发现** |

也就是说:被投毒的样本里,"我在字符串里找到一个 AWS key"这句话不再是发现,而是
"一条需要结构证据或人工复核的线索"。位置、规则号、脱敏预览都还在 —— 记录没丢,结论降级。

### 2. 二进制 source→sink 线索 `binflow`

- source:`argv` / `recv` / `read` / `fgets` / `gets` / `getenv` / `scanf` / `fread`
- sink:`system` / `popen` / `execve` / `execl` / `execvp`(命令执行)、
  `strcpy` / `strcat` / `sprintf` / `memcpy`(内存)、`printf` / `syslog`(格式化串)
- 产出**只有 fact**,tag `binflow, code-only, hypothesis`,**绝不产 finding**;
  证据里写 `executed:false`、`confidence:code-only`
- 有 objdump 就用反汇编文本(结构侧),没有就用字符串(表面侧),并在 fact 里标明
- blinded 样本的每条线索带 `blinded:true`

## B 组 · 多步链

`internal/engine/chain.go`:**两个前提**同时满足才组链 —— 代码侧有入口线索,且至少两个
身份带声明归属。组出来的是:

```
accounts_provision(alice)   ← 档 2,人点头
accounts_provision(bob)     ← 档 2,人点头
compare(session_a, session_b, url)  ← 档 1,依赖前两步
```

关键实现与红线:

- `compare` 的 `Deps` 指向两个登录步骤 —— **依赖没完成,它连"可领取"都不是**;
- 链不是执行计划:两个档 2 节点各自停在人前,批一个走一个;
- 若普通规则**已经**派生过同一个 `compare`,链不会再造一个重复步骤,而是给已有的那条
  **补上依赖**(新增 `SetIntentDeps`)—— 链是排序,不是加活;
- 组链动作写一条 trace,说明"从哪条线索 + 哪两个身份组出来"。

## C 组 · 认证补齐

### OAuth 流程加项(仍然只读、绝不换 token)

| 新增 | 判据 | 说明 |
|---|---|---|
| 隐式流残留 | `response_types_supported` 含 `token` | 令牌会落在 URL fragment |
| scope 面过宽 | 命中 `admin/write/offline_access/*` ≥2 个,或 scope 总数 >20 | 一次同意可能给太多 |
| `state` 熵不足 | 长度 <16,或不同字符 <6 | 只统计,不解码不重放 |
| `response_mode=query/fragment` | 记录为事实 | 令牌/code 可能进 URL |

### header 反射拆成独立项

新 class `header`:把带标记的值放进参数,**判据是响应体里出现同一个标记**。
与 CRLF 探针分清楚:CRLF 看的是**响应头**(真·头注入),header 看的是**响应体**(回显)。

## 验收

```
binary   binflow 5 个测试:argv→system/strcpy 出两类线索 / 无 source 不出线索 /
         blinded 标记随线索走 / 只产 fact 不产 finding / 降档逻辑(high→medium, low→fact)
engine   链 2 个测试:双身份+线索 → 3 步链且 compare 带两个依赖 / 缺任一半不组链
web      OAuth 3 个测试(隐式流+scope / 弱 state / 既有两项仍绿)、header 反射 1 个
```

## 没做的(如实)

- **会话管理探针**(`session_probe`:固定/登出失效/sid 熵)仍然没做 —— 它需要真实登录流程
  与凭据注入,不是纯只读观察;C 组只补了不依赖凭据的那一半。
- **对话里的链式提案**没做:planner 的 `plan` 卡片仍是单层步骤;链目前由引擎组装,
  对话只报告"引擎组了一条链"。
- **bench ground truth / 规划质量维度**没加;报告里二进制假设与链血缘还没单列。
- **README 能力清单**未更新(下一轮收口一起做)。

## 一句话

A 组让"认出被投毒"真的影响结论;B 组让"线索+身份"变成一条会按顺序走、每步该停就停的链;
C 组把认证面补到能看见。三组都没有多给 AI 一寸权限。
