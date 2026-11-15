# IMPL-STATUS v0.15 – v0.17 — 认证深度 / 反致盲 / 证据排序

> 日期:2026-11-15 · 三份 DEVPLAN 一天内落地,`go test ./...` 全绿,bench 越界 0。
> 这一轮**没有新增"更狠的动作"**:JWT/OAuth 仍然只读,反致盲只识别不绕过,
> 规划只改"先做哪一步"。

## v0.15 · 认证/会话与注入变体

### JWT 深度(`internal/web/jwt.go`)

在 v0.9 的四项之上补了四项,**全部只读判定**:

| 新增检查 | 判据 | 红线 |
|---|---|---|
| `kid` 含路径/查询字符 | 出现 `/` `\` `..` 或 SQL 片段 | 只记形状,不构造载荷 |
| 时间字段不自洽 | `exp<iat` / `nbf>exp` / `iat` 在未来 | 只标不一致 |
| 非对称算法(RS\*) | 配置风险提示(公钥被当 HMAC 密钥) | **不伪造令牌去验证** |
| 对称密钥强度 | 明确写"无法从令牌判断" | **不跑字典、不爆破** |

后两项特意写成 `info`,并且 counter 里写明"证实需要伪造/爆破,那属于越界" —— 让读者知道这是提示不是结论。

### 注入变体(`internal/web/inject_variants.go`)

`param` 的 class 再扩两格:

- `nosql`:用 `{"$ne":""}` / `[$ne]=1` / `{"$gt":""}` 三种形状各发一次,比状态码与体量差异(>20%);
  **不取任何记录**;
- `crlf`:在参数里塞 `%0d%0a` + 自造头名,**判据是响应头里出现这个头**;不注入 Cookie、不覆盖已有头。

连同 v0.14 的五类,`param` 现在覆盖 **8 类**:sqli / ssti / ssrf / path / cmdi / xxe / upload / nosql / crlf。
`deserialize` 仍然是"拒绝探测"。

### 没做的(v0.15 剩余)

- **会话管理探针**(会话固定 / 登出失效 / sid 熵)未做 —— 它需要账号层会话,比只读探针多一层状态。
- **OAuth 流程加项**(response_mode / 隐式流 / scope 过宽 / state 熵)未做,现有 well-known + state + PKCE + redirect 观察保持。
- **header 注入与 CRLF 合并**已做(CRLF),但"响应体里的头反射"未单独成项。

## v0.16 · 反致盲

### 识别(`internal/binary/antiblind.go`,能力 `blind_screen`)

**这是这一轮最想要的东西**:认出"样本被做过手脚",而不是被它带走。

五类结构信号,纯统计 + 特征匹配:

| 信号 | 判据 | 权重 |
|---|---|---|
| `poison` | 读起来像给模型下指令的字符串(`ignore previous` / `safe to run` / `flag_is_here` …) | 3 |
| `noise` | 字符串重复发生占比 >50%,或单串重复 >50 次,或总量 >2000(上下文轰炸) | 2 |
| `anti-debug` | `IsDebuggerPresent` / `ptrace` / `TracerPid` … | 2 |
| `packer` | UPX / MPRESS / Themida / VMProtect 特征 | 3 |
| `obfuscation` | 整体熵 > 7.2 bits/byte 且 >4 KiB | 2 |

累加权 ≥6 → `heavily-blinded`,≥2 → `suspected-blinded`,否则 `clean`。

产出:`fact(signal=...)` 若干 + 一条 `info` 级 `finding(kind=anti-analysis)`。
**这条 finding 说的是"样本形态",不是漏洞**,counter 明写"这是对样本的判断,不是可利用性"。

`.pgsm` 关键纪律:**不执行、不脱壳、不绕过**。命中 packer 时输出"需人工脱壳后再 handoff"。

### 没做的(v0.16 剩余)

- **抗干扰分析**(blinded 样本里把符号/字符串降权、优先结构证据)只落了"提示"这一半:
  `blind_screen` 会给出提示,但 `secrets`/`dataflow` 还没自动引用这个标签降权。
- **二进制 source→sink 假设**(`binflow.go`)未做。
- **架构扩展**(ARM/MIPS/WASM/.NET)未做。

## v0.17 · 证据加权排序

`internal/engine/order.go`:**只改顺序,不改权限**。

分数构成(全部带理由,写进 trace):

| 项 | 分 |
|---|---|
| 由白盒线索派生(`hypothesis_id`) | +5 |
| 有来源标注(`provenance`) | +3 |
| 只读可自走 | +2 |
| `code_ingest`(能扩大视野) | +4 |
| `scan`/`crawl`/`api_spec`(铺面) | +1 |
| trace 已覆盖同端点 | -4 |

同分按 intent id 排序 —— **同输入必然同顺序**,否则"AI 为什么先做这个"无法审计。

### 没做的(v0.17 剩余)

- **多步链组装**(白盒假设 + 双身份 → IDOR 验证链)未做:它需要在图里表达依赖与血缘,
  比排序大一个量级。
- **对话里的链式提案**:`plan` 卡片仍是单层步骤列表。
- **规划质量 bench**:没加"到一条 verified 用了几步/几次点头"的维度。

## 验收

```
binary  blind_screen 7 个测试:干净样本仍 clean / 投毒串被识别 / 噪声+壳升级为 heavily /
        反调试只标注不绕过 / 产物是 info 且带 counter / 注册为只读 / 端到端能跑
engine  排序 2 个测试:线索支撑的步骤排在前面且理由非空 / 同分按 id 且多次运行一致
web     nosql 与 crlf 各 2 个测试,含"普通参数零误报"
```

真机 bench 仍 `recall 1.000 / precision 1.000 / 19 请求 / 越界 0`。

## 一句话

认证与反致盲这两块,做的是"看清楚";排序那块,做的是"先看哪里"。
三件事都没碰"能做什么" —— 该停的地方一步没少。
