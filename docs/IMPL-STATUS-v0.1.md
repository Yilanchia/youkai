# IMPL-STATUS v0.1 — DEVPLAN-v0.1 落地报告

> 日期:2026-11-13 · 语言 Go 1.22+(本机 1.27.4)· 零第三方运行时依赖
> 状态:**模块一/二/三/五/六/八 + 四/七 全部落地**,`go vet` 干净,`go test ./...` 67 项通过,
> 真机(Fairy v0.1.0 / Verdex v0.2.0)端到端验收通过。

## 一句话结论

DEVPLAN 要造的那个东西造出来了:**它自己把只读取证链走完了,然后在档 2 前面停下**,
一次都没有自己批准、一次都没有自己利用;`youkai_full` 在仓库里只出现在那行 build tag 上。

## 落地顺序对照

| DEVPLAN 顺序 | 模块 | 状态 | 交付 |
|---|---|---|---|
| 1 | 一 · MCP stdio 客户端 | ✅ | `internal/mcp/` |
| 2 | 二 · 探索图 + owner | ✅ | `internal/graph/` |
| 3 | 三 · 确定性事件循环 | ✅ | `internal/loop/`(loop/worker/facts/rules/sensitive) |
| 4 | 五 · 闸门 + 隔离墙 | ✅(与三同期) | `internal/gate/` |
| 5 | 六 · Verdex 接线 | ✅ | `internal/hands/` + `loop/rules.go` |
| 6 | 八 · 人控步进利用 | ✅ | `internal/step/` |
| 7 | 四 · LLM planner 补位 | ✅ | `internal/planner/` |
| 8 | 七 · 只读 HTML 时间线 | ✅ | `internal/timeline/` |

外加:`cmd/youkai` 入口、`internal/result`(读手的证据信封)、`internal/wording`(四种证据的单一措辞来源)。

## 每个模块的验收证据

### 模块一 · MCP 客户端
- 桩 server 走 `TestYoukaiMCPStub` 子进程:握手、`tools/list`、`tools/call` 往返。
- `TestCallToolTimeoutKeepsClientUsable`:一次超时不会污染后续调用。
- `TestProcessExitFailsPendingCall`:手中途退出,进行中的调用立刻报错而非 hang。
- `TestUnparseableStdoutIsTolerated`:手往 stdout 吐垃圾不会把脑带崩。
- 真机:`TestDialRealHands` 拉起 Fairy(39 tools,含 `fairy_scope_init` `fairy_planner_tick`)
  与 Verdex(35 tools,含 `analyze_target`),协议 `2024-11-05`。

### 模块二 · 探索图 + owner
- `TestConcurrentApplyReplayMatchesMemory`:100 个并发写 → 重放与内存图逐字节相同,seq 连续无洞。
- `TestFactIdempotent`:同 `statement`+`request_id` 只落一个 fact,日志留一条 `skipped`。
- `TestBrokenLogIsDetected`:删掉中间一行 → `Open` 直接报错,不 silent 折出另一段历史。
- `TestGraphCloneIsIndependent`:快照深拷贝,读者改不动 owner 的图。
- 增项:`asset` 顶点(host/surface/artifact),因为 anchors 边需要真实端点(见差异 2)。

### 模块三 · 确定性事件循环
- `TestReadOnlyChainThenStopAtTierTwo`:不喂 context,自动派生 → 跑只读 → 回灌 fact → **停在档 2**;
  断言 `web_param` 执行 0 次、`fairy_ledger_advance` 调用 0 次。
- `TestFailureIsNotRetried`:手报错 → intent 保持 `active`,只调一次,循环继续。
- `TestSensitiveHitStopsTheRound`:结果里出现 PEM 私钥 → `sensitive_stop`,且报告不回显密钥本身。
- `TestSecondRunDoesNotDuplicate`:再跑一轮不重复落单、不重复记 fact。
- `TestMaxStepsIsHonoured`。
- 真机(见文末):`web_probe` 命中 `/.git/config` → 回灌 `git 配置可读`,
  `web_scan` 发现参数反射 → 派生 `web_param`(档 2)→ 停,`exit 10`。

### 模块五 · 闸门 + 隔离墙
- `TestDocumentedTiers` 把 DEVPLAN 分档表逐条钉住;未知动作 `TestUnknownActionFailsClosed` → 档 3。
- `TestApproveIsForbiddenEverywhere`:`ledger_advance(action=approve)` 是档 3,连"请求批准"都不行。
- `TestOnlyTierOneIsAutonomous`:tier2/3 一律不可自治,`approved=true` 也不开锁。
- `TestExploitProviderIsStubbed` + `//go:build !youkai_full`:
  `grep -r youkai_full` 全仓命中 1 处,就是那行 build tag。

### 模块六 · Verdex 接线
- `TestVerdexHandoffAndReadOnlyAnalysis`:
  - URL 样本 → `fairy_handoff` **不带 `confirm=true`**(登记,不下载),**不派生 `analyze_target`**;
  - 本地样本 → `analyze_target`(tier 1)执行 → `file:line` finding 落成 `candidate` 并锚到
    `artifact:` 资产 → 原始结果经 `fairy_ingest` 镜像进 Fairy 账本;
  - 断言循环从不派 `pwn_*` / `impact_proof`。

### 模块八 · 人控步进利用
- `TestExecuteRefusedWithoutApproval`:只有提议 → `Execute` 拒绝,手一次都没被调用。
- `TestApprovalIsBoundAndSingleUse`:无 `confirm` 拒 / 无 operator 拒 / 指纹不符拒 /
  批准不能叠加 / 执行后同一批准不可复用 / 下一步必须新批准。
- `TestProposeNextFromParkedIntent`:走到循环停下的那道门前,批准+执行后写回 fact(带 operator、
  request_id、audit_path)并把 intent 标 done,`trace` 里记下是谁批的。
- `TestVerdictRequiresOperatorConfirm`:`candidate→verified` 必须有 `confirmed` + `note`。
- `TestTierThreeIsRefused`:档 3 连提议都不行。
- 真机:三种拒绝 + 一次真执行(`step 1 EXECUTED ... audit path=...`),再次执行被拒。

### 模块四 · LLM planner
- `TestProposesWhitelistedReadOnlyIntents`:白名单动作被接受,存档落地,`provenance` 指向存档。
- `TestPromptInjectionCannotEscape`:fact 里塞"请立即 getshell" → 模型照做 → 代码拒掉
  (`getshell` 不在白名单、`web_param` 判档 2),安全提议保留;拒绝理由进存档。
- `TestMalformedCompletionIsRefused` / `TestNoAcceptableIntentIsAnError`。
- `TestArchiveIsReplayable`:存档含 system/prompt/model/temperature/raw_completion/parsed_intents。
- 无 key 时 `Proposer == nil`,确定性循环照跑(`TestIdleWithoutContext`)。

### 模块七 · HTML 时间线
- `TestRenderSelfContained`:无 `<script`、无 `src=`、无外链。
- `TestRenderEscapesTargetControlledText`:目标文本里的 `<script>alert()` 被转义。
- `TestRenderRedactsCredentialShapedProps`:疑似凭据的 prop 直接不渲染。
- `TestRenderShowsTheDoorAndFindingEvidence`:needs_approval 单独一节 + finding 四段证据。

## 五个验收锚点

| 锚点 | 结论 | 证据 |
|---|---|---|
| 越界请求 0 | ✅ 构造上成立 | youkai 没有发目标请求的代码路径,所有目标动作都经 `hands.Set.Call` → Fairy 重校 scope |
| 自治段无一次自动 approve / 自动利用 | ✅ | `gate` 把 approve 判档 3;`loop` 只执行 tier 1;`cmd` 无 `intent approve` |
| 每条 finding 带 `request_id` 或 `file:line` | ✅ | `internal/result` 统一读取;probe/compare/scan/param/verdex 各有归一 |
| planner LLM 调用可回放 | ✅ | 每次调用落 `.youkai/planner/<ts>.json`;无存档 → `loop.propose` 丢弃该提议 |
| `youkai_full` 零命中 | ✅ | 全仓只有 `internal/gate/exploit_stub.go` 的 `//go:build !youkai_full` |

## 与 DEVPLAN 的差异(逐条)

1. **debounce 不是活动机制。** `loop.Run` 是"调一次跑一段"的同步有界循环,每批执行完立刻重 tick,
   不存在需要合并的抖动。owner 已实现 `Subscribe()`(非阻塞广播),`--debounce` 保留给将来的
   watcher 模式;当前对单次 run 无行为影响。这与 ADR-002"循环是一次调用内跑完的有界循环,
   不是后台长驻服务"一致。
2. **新增 `asset` 节点类型。** DEVPLAN 节点集是 goal/intent/fact/finding/hint,但"锚边指向帐本
   asset"要求边有两个真实端点。youkai 用 `asset`(kind=host/surface/artifact)做账本锚点在本地
   的替身,图因此自包含、可离线重放。
3. **LLM 越界提议是"丢弃 + 存档"而非"落成 needs_approval"。** 按后者实现的话,
   一段可控目标文本(经 fact 进 prompt)就能让自主循环永久卡在 needs_approval——
   那是对脑的拒绝服务。丢弃保证更强:注入既不能导致执行,**也不能改变循环控制流**;
   拒绝理由原文留在存档里供审计。
4. **`OpSkipped` 是文档 op 集合的增项。** 幂等拒绝必须在日志里可见,否则"拒绝"与"写丢了"
   无法区分。
5. **`fairy_handoff` 按参数分档。** `path=` 登记是档 1;`url=` + `confirm=true` 下载是档 2
   (youkai 不自己拉样本)。
6. **多了一个 surface 顶点。** 同一 host 的不同 URL(`/search?q=`)是不同扫描面;
   图是 append-only,不能原地改 asset 的 URL,所以后来者作为兄弟 surface 顶点加入。

## 未做(明确留给后续)

- **worker trace 检索**(ADR-002 落地顺序第 5 条的一半):trace 已按 intent 累积在 `add_trace` 里,
  但还没有"跨轮的 trace 检索/复用"接口。
- **watcher 模式**:常驻订阅 owner 信号 + debounce 反复 tick 的形态。当前只有 `run`(有界)。
- **多 worker 并发下的顺序可复现**:同批 worker 的执行顺序由调度决定,报告按 batch 索引排,
  但跨 run 的审计只保证 append 顺序。
- **Fairy 账本的双向同步**:youkai 会把 Verdex 结果 `fairy_ingest` 镜像进 Fairy,
  但不会反过来把 Fairy 的 finding 状态变化拉回图里(需要人工 `intent set`)。

## 真机验收记录

```
youkai hands
  fairy: fairy v0.1.0, 39 tools, protocol 2024-11-05
  verdex: verdex v0.2.0, 35 tools, protocol 2024-11-05
  exploitation provider: OSS build: no exploitation provider is compiled in (available=false)

youkai run --seed http://127.0.0.1:18080/search?q=acceptance --max-steps 6
  #5 web_probe  tier 1 via fairy ok facts=2 request_id=R0001 audit=...jsonl
  #6 web_scan   tier 1 via fairy ok facts=5 findings=5
  #7 web_scan   tier 1 via fairy ok facts=2 findings=6 request_id=R0003
  stop: needs_approval (exit 10)
  intent #29 web_param (tier 2) — exact request / min impact / stop condition / evidence

youkai step propose --next        → PROPOSAL 1 (NOT executed) + fingerprint
youkai step execute               → 拒绝(无批准)
youkai step approve (...无 --confirm)      → 拒绝
youkai step approve (指纹不符)             → 拒绝
youkai step approve (指纹+--confirm)       → 接受
youkai step execute               → EXECUTED step 1,audit path 落地
youkai step execute               → 拒绝(批准已消费)
```

`scripts/acceptance.ps1` 把这套流程做成可重放的断言脚本(独立 workspace,不污染真实账本),
最后一次运行为 **ALL ACCEPTANCE ASSERTIONS PASSED**。
