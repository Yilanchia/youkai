# DEVPLAN-v0.2:youkai 单体平台实现文档 — 原生吸收 Fairy/Verdex,PG + SPA

> 交付对象:实现者(DeepSeek 等)。配 ADR-002(脑)、ADR-003(平台)、ADR-004(单体化)读。
> 覆盖**单体平台 OSS 范围**:纪律脊柱 + 原生 web/binary 能力 + 双图(PG)+ 引擎 + HTTP/SPA + 档 1/2 + 墙。
> 档 3 内核不在本文,只留墙。能力按 Fairy/Verdex(MIT,我方)源码逐模块移植;不含 ARTEX/norma(AGPL)代码。

## 0. 不可动摇(承 ADR-002/003/004)

- 任何目标请求只能经 `discipline.Guard` 发出;无第二条发包路径;无 scope 不动作。
- 自治循环只读(档 1);档 2 一步一批人控(high-auth + 单次 confirm);档 3 build tag 墙外。
- LLM 只提议、代码放行;永不自动 approve / 利用;candidate 不自动转 verified;失败不重试。
- 每条结论带四样证据(request_id + 审计位置、最小影响、停止点、反证)。
- 平台只听 127.0.0.1;API 本地令牌 + Origin 校验;key 只走环境变量。

## 技术基线

- Go >= 1.22;PostgreSQL;前端 SPA(React/Svelte)`go:embed` 单二进制。
- 浏览器能力用 CDP(对齐 Fairy 的零依赖无头浏览器);二进制反编译走可选后端(Ghidra/IDA/jadx),预检缺失即降级(对齐 Verdex `doctor`)。
- 目录:`internal/discipline`、`internal/web`、`internal/binary`、`internal/ledger`(PG)、`internal/engine`、`internal/gate`、`internal/api`、`internal/step`、`web/`(SPA)、`cmd/youkaid`(服务入口)。

## 1. 纪律脊柱 `internal/discipline`(P0,先于一切;蓝本:Fairy scope/guard/auth/highauth)

**目标**:把 Fairy 的 scope 护照、逐请求 guard、数据最小化、high-auth 原生化,成为**唯一**发包与放行通道。

- `Scope`:护照(目标清单、允许方法、`allow_active_probes`/`allow_waf_probe`/`allow_object_seeding`/`allow_account_provisioning`、过期)。无护照拒绝一切。
- `Guard.Request(ctx, req)`:发请求前校 scope(越界直接阻断并记审计)、限速、逐请求审计(`request_id` + 落 PG 审计表);**是唯一出口**。浏览器网络层也走它(越界 fetch 阻断)。
- `HighAuth`:HMAC 签名授权文件校验(basis/approver/assets/expiry/actions),**只验不签**;档 2 放行与 `reachability` 读图依赖它。
- 数据最小化:响应只留判定所需片段,凭据/正文不入库、不入报告、不入日志。

**验收**:无 scope → 任何能力调用被拒;越界 URL → Guard 阻断 + 审计留痕;审计表每请求一条带 request_id;high-auth 签名/过期/资产不符分别拒绝;代码里除 Guard 外无直接 HTTP 发包点(可加静态检查)。

## 2. 双图账本 `internal/ledger`(P0,PostgreSQL;蓝本:Fairy ledger.js 语义)

**目标**:资产图 + 探索图 + facts/findings/intents + append-only 审计,落 PG。

- 表:`assets`、`facts`、`findings`、`intents`、`edges`(血缘)、`audit_log`(只插不改)、`runs`、`planner_calls`。
- 幂等 ingest:`source_run_id`/`source_id` 去重(对齐 Fairy ingest)。
- 单写者语义改用 PG 事务 + 约束实现(取代 ADR-002 的 owner goroutine);并发写靠事务,审计靠 append-only 表。
- `candidate→verified` 只能由操作员确认写入,代码层禁止自动升级。

**验收**:并发写不坏账、不丢写;重复 ingest skipped;`audit_log` 不可 UPDATE/DELETE(约束/触发器);candidate 无操作员确认不得转 verified。

## 3. web 能力 `internal/web`(P0 只读子集先行;蓝本:Fairy 各同名模块)

**目标**:原生实现 Fairy 的 web 能力,**全部经 `discipline.Guard`**,移植时保留其判定与停止语义。

- **档 1(先做)**:fingerprint / scan / crawl / checks(头·CORS·跳转·泄露)/ probe / compare / browser(CDP 渲染+XHR+DOM+截图)/ role_matrix(多账号只读 GET)/ reachability(high-auth 后只读图)/ proof(DOM 上下文+CSP)。
- **档 2(人控)**:param / param_adaptive(SQLi/SSTI 存在性,需 `allow_active_probes`+confirm)、waf(需 `allow_waf_probe`+confirm)、login / accounts_seed / accounts_register(写方法)。
- 每个能力只读默认,结果归一成 fact 写账本,带 request_id。

**验收**:本机靶场复现 Fairy bench 同类(git 泄露/CORS/跳转/反射/SSTI/越权候选);越界 0;档 2 能力缺 confirm 或缺 scope 开关即拒。

## 4. binary 能力 `internal/binary`(P1;蓝本:Verdex)

**目标**:原生吸收 Verdex 静态分析,**全程只读、离线、只生成文本**。

- artifact 识别(魔数)、handoff 登记(sha256、隔离目录、不执行)、静态分析(strings/checksec/符号/反编译经可选后端)、mobile/firmware 解包、secrets、source→sink 数据流、SARIF 输出、`doctor` 预检。
- 档 2:`pwn_*`/`impact_proof`/`frida_script` 只产人工审阅后亲自运行的文本,循环不自动派。
- 下载样本经 `discipline.Guard`(scope 内、单文件上限、confirm)。

**验收**:PE/ELF/APK 各一跑通只读分析链;样本不执行、不联网;缺后端预检标红降级;secrets 不回显明文。

## 5. 档位闸门 + 墙 `internal/gate`(P0;承 DEVPLAN-v0.1 模块五)

- `Classify(capability, args) int`:web/binary 每个能力入表(对齐 DEVPLAN-v0.1 分档);未知归档 3。
- 墙:`exploit_stub.go`(默认 `Available()=false`)/ `exploit_full.go`(`//go:build youkai_full`,不在本仓库)。循环遇 `tier>=2` 一律停,不论墙后有无。
- `grep -r youkai_full` OSS 零命中。

**验收**:分档表单测;默认构建 `Available()==false`;循环对 tier>=2 零自动执行;`youkai_full` 零命中。

## 6. 引擎 `internal/engine`(P0;承 DEVPLAN-v0.1 模块三/四,去 MCP)

**目标**:事件驱动循环,worker 直接调 `internal/web`|`internal/binary` 的 Go 函数(不再 MCP)。

- planner(确定性 + LLM 补位;LLM 调用落 `planner_calls` 表、可回放)。
- worker pool:领 intent → `gate` 判档 → 调能力 → 归一 fact 入账 → 账本变触发下一轮。
- 硬停止:`tier>=2` 未批 / 敏感命中 / 无可领 / `max_steps`。
- LLM 安全同 DEVPLAN-v0.1 模块四(只提议;注入兜底靠 gate,不靠 LLM 自觉)。

**验收**:不喂 context 自走只读链到遇档 2 停;注入不越闸;无 LLM key 确定性照跑。

## 7. 平台 `internal/api` + `web/`(P1;承 ADR-003)

- HTTP + SSE,听 127.0.0.1,本地令牌 + Origin 校验。
- SPA `go:embed`。面板顺序:**审批台(档 2 一步一批,无批量/全部放行)→ 证据·报告 → 任务台 → 探索图 → LLM 配置 → 审计日志**。
- `cmd/youkaid` 启动:校 PG、校安全态、起服务。

**验收**:审批台逐条批 + 配 high-auth;无令牌/跨 Origin 请求被拒;报告以账本为准可复现。

## 8. 人控步进利用 `internal/step`(P1;承 DEVPLAN-v0.1 模块八)

同 DEVPLAN-v0.1 模块八,改为**原生能力 + 审批台 UI**:一次一个动作,操作员在审批台 `approve` + Fairy 式 high-auth 签名**双条件齐备**才执行这一步;不连跑、不批量、不自签、LLM 不可触发;打到影响成立即停。

**验收**:提议 step1 并停;双条件缺一即拒;批准后只执行一步、回灌证据、再停在 step2;verified 升级须操作员确认。

## 落地顺序

1. **纪律脊柱(模块一)+ 档位墙(模块五)** —— 先立地基;之后任何能力才允许接目标。
2. PG 账本(模块二)。
3. web 只读子集(模块三档 1)+ 引擎确定性循环(模块六)。
4. 平台:审批台 + 证据视图(模块七首屏)。
5. web 档 2 + binary(模块三档 2 / 模块四)+ 人控步进利用(模块八)。
6. LLM 补位、探索图可视化、审计日志面板。

**每步验收锚点**:越界请求 0;自治段无一次自动 approve/利用;每条 finding 带 request_id 或 file:line;审计表不可改;`youkai_full` OSS 零命中;无 scope 不发包。

## 一句话

把两把手收进一个身体,但**先长骨头(纪律)再长手(能力)**。youkai 自己发请求之后,安全靠的是自己的骨头,不是别人的进程。
