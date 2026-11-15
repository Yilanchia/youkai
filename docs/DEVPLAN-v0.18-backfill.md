# DEVPLAN-v0.18:补全 v0.15/16/17 的剩余模块(一次做完,别再分轮等)

> 交付对象:实现者(DeepSeek)。这是一份**补全清单**,把 v0.15/v0.16/v0.17 里已标注"没做"的模块集中、排序、一次性连续做完。
> 配 DEVPLAN-v0.15/16/17 原文读(每块的红线以原文为准,这里只列剩余范围 + 顺序 + 验收)。
> **连续推进,不要每做一小块就停下等审**;一轮把下面 A/B/C 三组做完再交付,中间保持 `go test ./...` 全绿。

## 做事总则(每一块都适用,别重复犯)

- 红线全继承对应 DEVPLAN:只判存在/只读静态、过 Guard、档 2 停人前(ADR-006)、candidate≠verified、不利用/不取数据/不 hack-back。
- **被致盲/无法确证处如实标"不可靠",绝不臆造**(v0.16 命门)。
- 每块都要有测试;`IMPL-STATUS` 如实记做了什么、没做什么,不假装完成。
- `invariants.yml` 安全门禁必须仍过。

## A 组(先做):v0.16 抗干扰闭环 —— 把反致盲真正接上

这是最该先补的,因为识别(blind_screen)做了,但下游没用上标签,反致盲还是半截。

1. **secrets / dataflow 按致盲标签自动降权** `internal/binary/`:
   - 分析样本前先取 blind_screen 的 level(clean/suspected/heavily)。
   - blinded 样本里,基于**符号名/字符串**的命中一律附 counter "样本疑似投毒,此表面证据可信度降低,需结构证据或人工复核",并在可信度上降档(不直接当 candidate)。
   - 优先引用**结构证据**(调用图/交叉引用/常量/系统调用序列)下结论;纯表面命中标"仅参考"。
2. **二进制 source→sink 数据流假设** `internal/binary/binflow.go`(v0.16 模块三):
   - source:argv / `recv`/`read` / 文件读 / 环境变量;sink:`system`/`exec*`/`popen`、`strcpy`/`sprintf`/`memcpy`、格式化串。
   - 产 `hypothesis(code-only)`,和 web 白盒一样**只是线索不是发现**;可利用性人工验证(Verdex pwn_* 档 2 产文本)。
   - blinded 样本的假设附"结构推断,表面数据可能投毒"。

**A 组验收**:blinded 样本里 secrets/dataflow 命中都带降权 counter、不自动 candidate;argv→system 出命令执行假设(code-only)、strcpy 无边界出内存破坏假设;假设不自动升发现;只读不执行;`go test` 全绿。

## B 组:v0.17 多步链组装 —— youkai 的"质变",从排序到组链

证据加权排序(v0.17 模块一)已做,这是它的自然延续。

1. **多步链组装** `internal/engine`(v0.17 模块二):
   - 把"白盒假设 + 账号归属 + 已确认 fact"拼成**有依赖的多步链**(依赖图)。
   - 例:白盒"/orders 可能 IDOR" + 双身份 + 归属 → 链:登录两身份(档2,点头)→ compare(档1)→ 命中升 candidate。每步依赖上一步产物。
   - **关键红线**:组出的链**不等于自动执行链** —— 任一步是档 2 就在那停人前,人批后才推进下一步(ADR-006 的"自主只读+遇险点头"在链上同样成立)。链每步标"为什么走这步"的血缘。
2. **对话里的链式提案** `web/chat.js` + `internal/planner`(v0.17 模块三):
   - AI 的 `plan` 卡片可以是**一条链**(多步+依赖+每步理由),操作员整体看、逐步批。
   - 卡片仍受限 schema:不能出 approve/改 scope/升 verified;prompt 不含目标正文。

**B 组验收**:给"白盒假设+双身份"→ 组出 IDOR 验证链;链含档2步时停人前、逐个点头;每步血缘可查;对话能给带理由的多步链提案;schema 无越权卡片;planner 调用可回放;确定性兜底在。

## C 组:v0.15 会话类补齐 —— 补覆盖面

1. **会话管理探针** `internal/web/session_probe.go`(v0.15 模块三):会话固定(登录前后 sid 是否轮换)、登出失效(登出后旧会话是否仍有效,用自己测试账号单次只读复验)、sid 熵(只统计,不预测利用)。
2. **OAuth 流程加项**(v0.15 模块二剩余):response_type/response_mode 风险组合、隐式流残留、scope 过宽、state 熵弱标注、redirect_uri 更多绕过形状**只观察一次**。红线:不换 token、不劫持。
3. **header 反射单独成项**:响应体里反射的头(在 CRLF 之外),只判存在。

**C 组验收**:会话固定/登出不失效各命中一条候选、只用测试账号、不劫持不预测;OAuth 加项出配置候选、绝不换 token;header 反射成项;接入假设映射;越界=0。

## 收尾(三组做完一起做)

- **bench ground truth** 补入 A/B/C 的新类(lab-target.py / lab-source 增对应样例);规划质量维度(v0.17 模块四:到达一条 verified 用几步/几请求/几次点头)。
- 报告/SARIF 纳入新类与二进制假设、链血缘;反致盲可信度在报告里显式。
- README 能力清单更新;各 IMPL-STATUS 收口。

## 落地顺序

**A(反致盲闭环)→ B(多步链)→ C(会话补齐)→ 收尾**。A 先做因为它把"不甘心"那块真正做扎实;B 是最高价值质变;C 补面。
三组连续做,中途保持测试绿,一次性交付审查。

**总验收锚点**:只判存在/只读、过 Guard、档2停人前、candidate≠verified、不利用/不取数据/不hack-back;
致盲处如实标不臆造;链不等于自动执行链、档2逐个点头;LLM 只提议、prompt 无目标正文;
越界=0;`go test ./...` 全绿;`invariants.yml` 门禁仍过。

## 一句话

把三条线上没啃完的硬骨头一次啃完:反致盲真正闭环、规划真正会组链、认证覆盖补齐 ——
连续做、别分轮,但一步都不许越过那些让 youkai 之所以是 youkai 的闸门。
