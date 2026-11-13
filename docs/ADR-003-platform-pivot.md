# ADR-003:平台化转向 — ARTEX 形态的自托管控制台(安全教条不变)

> 状态:已决定(2026)。**取代 ADR-001"不造平台"整节**,**更新 ADR-002 技术基线中"CLI-only / 零依赖 / 不上数据库"几句**。
> 其余(安全教条、两只手、档位模型、脑的四角色)全部保留。读者:维护者 + 实现者(DeepSeek)。自包含。
> **后续(ADR-004)**:两只手模型改为原生吸收 Fairy/Verdex 的单体实现;本文件平台决策(PG / SPA / 本机单操作员)不变。

## 背景与转向

ADR-001/002 刻意不做平台(无 UI、无守护进程、JSON 账本),以守"工具不是平台"的定位。
现决定反过来:**youkai 做成 ARTEX 那种自托管控制台** —— 常驻 HTTP 服务 + 仪表盘 / 任务 / 图谱 / 审批台 / 日志,
自带运行时(不依赖 DSH),就在 `D:\youkai` 做。知道这条路更重,是有意为之。

## 推翻了什么 / 保留了什么

**推翻(仅这几条)**:
- ADR-001:不做 UI、不做常驻守护进程、不上数据库(零依赖 JSON)。
- ADR-002 技术基线:CLI-only、零第三方运行时依赖。

**保留(写死,一个字不改)**:
- youkai 永不直接碰目标,所有目标动作走 Fairy/Verdex 受闸 MCP。
- 自治循环只跑档 1(只读);档 2 每步人批;档 3 编译期墙外(build tag)。
- LLM 只提议、闸门代码放行;永不自动 approve / 自动利用;candidate 不自动转 verified。
- 每条结论带四样证据;无 scope 不动作。
- **UI 是控制面,不是自治许可**:界面里永不出现"一键自动利用 / 自动打穿"入口。ARTEX 的平台外形要,自动利用不要。

## 决策

1. **形态**:自托管单二进制控制台 —— Go 后端 + `go:embed` 的 SPA,常驻 HTTP,听 `127.0.0.1`。
2. **后端状态**:PostgreSQL(ARTEX 同款)。双图(资产图 + 探索图)+ 任务编排落 PG;另留 **append-only 审计表**作不可改真值,支持导出可 diff 快照。
3. **前端**:SPA(React 或 Svelte,实现者定)构建后 `go:embed` 进二进制。
4. **访问**:v1 **本机单操作员**,只听 127.0.0.1,无登录;schema 预留多用户,v1 不做 RBAC。即使单机也要 API 本地令牌 + Origin 校验,挡住恶意本地网页顺手打 127.0.0.1(平台自身是新攻击面)。
5. **两只手不变**:Fairy(web)、Verdex(binary)仍是 MCP 子进程手。
6. **真值分层不变**:Fairy 账本仍是 scope/assets/findings 的权威;PG 存 youkai 的任务 / 探索图增强 / UI 查询态,每个 youkai 记录存 `fairy_ref`。报告仍以 `fairy_report_bundle` 为准。

## 架构:ADR-002 的脑 + 平台三层

```
前端 SPA         任务台 / 探索图可视化 / 审批台 / 证据·报告 / LLM 配置 / 审计日志
HTTP/API 层      REST + SSE;把引擎状态推给 UI,把操作员动作(approve/stop/新任务)收下来
引擎层(ADR-002) ledger-owner / planner / worker pool / mcp-client 四角色,跑在后端进程里
持久层           PostgreSQL(双图 + 任务 + append-only 审计)
两只手           Fairy / Verdex(MCP 子进程)
```

- ADR-002 的四 goroutine 脑**不变**,从"CLI 进程"变成"HTTP 服务里的引擎"。
- 探索图从 `.youkai/explore.json` 迁到 PG 表,append-only 语义保留(审计表 + 可重放)。

## UI v1 面板(按"服务安全故事"排序)

1. **审批台(最高优先)**:档 2 人控闸搬到界面 —— 一次一个待批动作,显示它会发的确切请求 + 最小影响 + 证据,操作员逐个 approve(配 Fairy high-auth)。**不可批量 approve、无"全部放行"。**
2. 任务台:建 / 看 / 停任务,状态与停止点。
3. 证据 / 报告视图:`fairy_report_bundle` 跨工具报告 + 四样证据。
4. 探索图 / 覆盖可视化:血缘图,只读。
5. LLM 配置:provider/model/key(key 只存环境变量引用,不回显)。
6. 审计日志:逐请求 + 逐审批,只读。

**明确不做**:ARTEX 的常驻 MITM 流量代理(除非另开决策);任何自动利用入口。

## 部署现实(诚实)

单 youkai 二进制(含 SPA)+ **一个本机 Postgres 实例**。不再是"零外部依赖" —— Postgres 要起起来(本地装或 Docker)。这是选 PG 的代价,换多任务并发与跨任务资产图。

## 落地顺序

1. 先把 ADR-002 / DEVPLAN-v0.1 的**引擎跑通**(headless,先不接 UI)。
2. 加 PG 持久层(双图 + 审计表),引擎状态落库。
3. 加 HTTP/API 层(REST + SSE),本地令牌 + Origin 校验。
4. 加 SPA:**审批台 + 证据视图先行**,再任务台,再图谱。
5. LLM 配置、审计日志面板。

平台细节另出 **DEVPLAN-v0.2**(PG schema、API 契约、SPA 面板);DEVPLAN-v0.1 仍是引擎核心规格。

## 一句话

youkai 从"只有脑的 CLI"长成"ARTEX 形态的控制台",但长出来的是一块**看得见、批得动**的控制面 ——
自治只读、利用一步一批、深度利用永远在墙外。平台像 ARTEX,底线不像。
