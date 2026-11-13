# ADR-004:单体化 — 吸收 Fairy/Verdex 精华的原生实现(不再外挂 MCP 手)

> 状态:已决定(2026)。**更新 ADR-002/003 中"youkai 通过 MCP 驱动 Fairy/Verdex 两个子进程手"的模型**:
> 改为 **youkai 原生实现 Fairy(web)与 Verdex(binary)的能力**,合成一个自包含 Go 平台。
> 安全教条、档位模型、档 3 墙全部保留。读者:维护者 + 实现者(DeepSeek)。自包含。

## 决策

youkai 不再把 Fairy、Verdex 当外部 Node MCP 子进程调用,而是**把它们的精华原生吸收进自己的 Go 代码库**,
做成单体自托管平台(承 ADR-003:Go + PG + `go:embed` SPA)。Fairy、Verdex 作为**能力蓝本**(都是 MIT、我们自己的代码),
按模块移植;不再有运行时 MCP 握手、不再依赖 Node。

## 一个必须正视的安全后果(以及怎么守住)

ADR-002 的"比 ARTEX 安全"曾**靠委托成立**:youkai 不碰目标,闸门在 Fairy 这个独立权威进程里。
单体化之后,**youkai 自己发请求、闸门成了 youkai 自己的代码** —— 委托式保证没了。

守法:**吸收精华,先吸收纪律。** Fairy/Verdex 的"精华"本来就不是扫描器,是它们的纪律
(scope 护照、逐请求审计、数据最小化、只读默认、审批门、high-auth)。所以:

- **纪律脊柱先建、且不可旁路**:任何目标请求只能经 `discipline.Guard`(scope 校验 + 逐请求审计 + 限速)发出;
  没有第二条发包路径;任何能力模块都挂在脊柱上,不能绕过。
- 档位分类器 + 墙、high-auth、四样证据、无 scope 不动作 —— 全部原生保留,语义不变。
- 自治循环仍只读;档 2 仍一步一批人控;档 3 仍 build tag 墙外。
- 结论:"比 ARTEX 安全"从"委托成立"变成"**youkai 自身构造成立**" —— 这要求纪律是地基,不是补丁。

## 吸收什么(能力蓝本)

- **Fairy(web)**:scope / guard / http / crawl / scan / fingerprint / checks / compare / browser(CDP)/ probe /
  param / waf / matrix / ledger / report / ingest / accounts / highauth / reachability。
- **Verdex(binary)**:artifact 识别与 handoff、静态分析(strings / checksec / decompile)、mobile / firmware 解包、
  secrets、source→sink 数据流、SARIF;全程只读、离线、只生成文本。
- **不吸收** ARTEX / norma 的任何代码(AGPL);只借其平台 / 事件架构思想。Fairy/Verdex 是 MIT、我方代码,
  移植时保留 MIT 版权与 notice。

## 与两只手模型的差异

- 没了:`internal/mcp` 客户端、拉起 Node 子进程、MCP 握手、`fairy_ref` 跨进程锚。
- 变成:`internal/web`(Fairy 精华)、`internal/binary`(Verdex 精华)、`internal/discipline`(脊柱),
  引擎(ADR-002 四角色)直接调它们的 Go 函数。
- 真值统一在 youkai 的 PG 账本(不再有"Fairy 账本权威 + youkai 增强层"的分层)。

## 落地

详见 **DEVPLAN-v0.2**。核心顺序:**先脊柱(discipline)+ 墙 → PG 账本 → web 只读子集 → 引擎 →
审批台 + 证据 → web/binary 其余 → 人控步进利用 → LLM**。纪律不先立住,后面一律不许接目标。

## 一句话

youkai 单体化,把 Fairy/Verdex 的精华收进一个平台 —— 但收进来的第一样东西是它们的纪律,不是它们的扫描器。
自己发请求了,所以闸门必须是自己的骨头,不是别人的插件。
