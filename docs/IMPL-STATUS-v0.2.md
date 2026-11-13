# IMPL-STATUS v0.2 — DEVPLAN-v0.2 落地报告

> 日期:2026-11-13 · Go 1.22+(本机 1.27.4)· PostgreSQL 17.6 · 单二进制 + 内嵌 SPA
> 状态:**纪律脊柱 / PG 账本 / 原生 web + binary 能力 / 引擎 / HTTP+SPA / 审批台 / 双条件档 2** 全部落地。
> `go vet` 干净,`go test ./...` 全绿,`scripts/acceptance-v02.ps1` 真机全通过。
>
> **审阅修订(Claude,2026-11-13)**:原先 `go test ./...` 在并行跑多包共用一个 PG 库时会在 `migrate`
> 死锁(SQLSTATE 40P01);已给 `ledger.Migrate` 加会话级 advisory lock 串行化迁移,现 `go test ./...`
> (默认并行)稳定全绿。单独跑各包本就通过。

## 一句话

单体化做完了,**先长的是骨头**:现在 youkai 自己发请求,而它每一次发包都必须穿过
`discipline.Guard`(护照校验 → 解析后 IP 复核 → 限速 → 逐请求审计),审计表在数据库层不可改写,
档 2 执行需要**操作员批准 + high-auth 记录**两个独立条件,批准一次性消费。

## 落地顺序对照

| DEVPLAN-v0.2 顺序 | 模块 | 状态 | 交付 |
|---|---|---|---|
| 1 | 纪律脊柱 + 档位墙 | ✅ | `internal/discipline/`(scope/guard/dialer/highauth)· `internal/gate/` |
| 2 | PG 账本(双图 + 审计) | ✅ | `internal/ledger/` + `schema.sql`(触发器) |
| 3 | web 只读子集 + 引擎 | ✅ | `internal/web/`(22 能力)· `internal/engine/` |
| 4 | 平台:审批台 + 证据 | ✅ | `internal/api/` · `web/`(手写 SPA)· `internal/runtime/` |
| 5 | web 档 2 + binary + 人控步进 | ✅ | web 档 2 · `internal/binary/`(19 能力)· 审批台单步执行 |
| 6 | LLM 补位 + 可视化 + 审计面板 | ✅ | `internal/planner/` · 探索图/审计面板 |

## 逐模块验收证据

### 1 · 纪律脊柱 `internal/discipline`(P0)

测试(`discipline_test.go`,15 项 + 静态检查):

- `TestScopeCheck`:include / exclude / `*.wildcard` / CIDR / 端口约束 / scheme 全部按预期;
  通配符不覆盖 apex,排除项优先。
- `TestScopeValidation`:短 basis、空 operator、无 include、`*`、`*.com`、过期 → 全部拒绝。
- `TestGuardRefusesOutOfScopeWithoutSending`:**目标服务器计数为 0**,拒绝同时写审计(blocked)。
- `TestGuardFollowsInScopeRedirect` / `TestGuardStopsRedirectLeavingScope`:每跳独立审计;
  跳出 scope 的跳转被拦下并记审计。
- `TestGuardTruncatesBody`:响应体按护照上限截断(数据最小化)。
- `TestScopedDialerBlocksPrivateResolution`:解析到私网地址时,dialer 层再拦一次(防 DNS rebinding)。
- `TestSanitizeHeadersKeepsCookieFlagsRedactsValue`:`sid=<redacted>; HttpOnly; Secure; SameSite=Strict` ——
  值打码、属性保留,所以 cookie 标志检查才做得成。
- `TestHighAuthVerify`:错误密钥 / 篡改 payload / 过期 / 越权 actions 全部拒绝;
  `TestHighAuthCanonicalisationMatchesJS` 钉住 `JSON.stringify(payload, sorted keys)` 的字节形态,
  **Fairy 生成的 high-auth 记录可以直接验证**。
- `TestNoEgressOutsideTheGuard`:**静态检查**整个仓库的非测试 Go 文件,
  除 `internal/discipline` 外出现 `http.Client` / `http.Get` / `http.NewRequest` 一律失败
  (唯一例外:`internal/planner` 打模型端点,它永远拿不到目标流量)。

### 2 · 账本 `internal/ledger`(P0,真 PG)

测试在真 PostgreSQL 17.6 上跑(`store_test.go`,10 项):

- `TestIngestIdempotency`:同 fact 二次 ingest → `Deduped=1`、图里只有一条;同 finding 二次 → 去重;
  事实自动锚到 host 资产。
- `TestEnsureIntentDedupes`:同一动作指纹只落一条 intent。
- `TestApprovalRequiresTheApprovalRow`:直接 `UPDATE intents SET approved=true` →
  **触发器报错**;tier-1 不可批准;正常路径写入后 `approved` 翻转;`ConsumeApproval` 第二次 → 报错。
- `TestVerifiedRequiresOperatorVerdict`:直接 `UPDATE findings SET state='verified'` →
  **触发器报错**;缺 operator/缺 note 在代码层也拒;正常路径成功并记录 `verified_at`。
- `TestAuditIsAppendOnly`:`UPDATE` / `DELETE` audit_log → **触发器报错**;读回内容不变。
- `TestGraphViewShape` / `TestRunLifecycle` / `TestPlannerCallArchive`:UI 依赖的投影与存档完整。

### 3 · web 能力 `internal/web`(P1,22 能力)

- 档 1 实现:probe、fingerprint、scan(安全头 / CORS / Cookie 标志 / 跳转 / 6 条暴露面 /
  版本号 / **参数反射**)、crawl、compare、role_matrix、proof(DOM 上下文 + CSP)、
  headers / cors / exposures / redirect_check 单体版、reachability(需 high-auth)、browser(无 CDP 则降级)。
- 档 2 实现:param(SQLi 错误签名 / 布尔差分;SSTI `{{7*7}}`+对照)、param_adaptive、waf、login。
  accounts_* / object_seed 明确"本构建不实现",不伪造。
- 测试 48 例:每个能力断言**审计条数**(即请求确实走了 Guard)、每条 fact/finding 带 `request_id`、
  响应体不落库、凭据值不出现。
- 反射发现:`scan` 对查询参数最多测 3 个,命中产出
  `Finding(kind=reflection)` + `Fact(tags=reflects,param-candidate)` + `Where="GET <url> (param: q)"` ——
  这正是引擎派生档 2 停点的输入。

### 4 · binary 能力 `internal/binary`(P1,19 能力)

- 原生解析:ELF(32/64、LE/BE、PT_GNU_RELRO、BIND_NOW、canary/FORTIFY)、PE(DllCharacteristics →
  ASLR/DEP/CFG/HighEntropy)、Mach-O/APK/DEX/WASM/Java class 识别 + sha256/隔离登记。
- strings / symbols / disasm / decompile / mobile_unpack / firmware_extract / secrets(掩码)/
  dataflow(启发式,标注)/ sarif / doctor(预检降级)。
- 档 2:pwn_* / web_poc / impact_proof / frida_script 只写文本到隔离目录,**不执行**。
- 测试 30 项:手工构造 ELF/PE/APK fixture、zip-slip 拒绝、>64MiB 拒绝、符号链接拒绝、
  密钥掩码(断言完整密钥从不出现)、静态检查"包内无 net/http、无 exec.Command(样本)"。

### 5 · 引擎 `internal/engine`(P0)

- `TestRunsReadOnlyChainThenStopsAtTierTwo`:**不喂 context**,从 scope 护照自举 → 跑 probe+scan →
  回灌 fact → 派生 `param`(tier 2)→ **停在 needs_approval**;断言 `param` 零派发、
  pending 带四样证据、run 以停止原因收尾。
- `TestApprovedTierTwoStillNeverRuns`:`approved=true` 的布尔值也不开锁。
- `TestSensitiveStopsTheRun`:结果含 PEM 私钥 → `sensitive_stop`,报告不回显密钥。
- `TestFailureIsNotRetried`:一次失败 → intent 留 active、只调一次、循环不崩。
- `TestProposalNeedsProvenance`:无 `planner_calls` 存档的 LLM 提议被丢弃。

### 6 · 平台 `internal/api` + `web/`(P1)

- `TestTokenRequired` / `TestForeignOriginRejected` / `TestSPAShellIsPublicButDataIsNot`:
  无令牌 401、跨 Origin 403、SPA 壳公开但带 CSP 且不含数据。
- `TestEngagementScopeIsValidated`:`*` 与短 basis 在建作业时就被拒。
- `TestExecuteRequiresApprovalThenHighAuthThenExecutesOnce`:完整双条件序列 ——
  无批准 403 → 批准 → 无 high-auth **428** → 错密钥 403 → 覆盖不到目标 403 → 双条件齐备 200
  (能力只跑一次)→ 再次执行 403(批准已消费)。
- `TestExecuteRejectsAnOperatorWhoDidNotApprove`:bob 不能执行 alice 的批准。
- `TestTierOneCannotBeApproved`:tier-1 不进审批台。
- `TestVerdictRequiresExplicitConfirmation` / `TestReportIsALedgerProjection`。

### 7 · LLM `internal/planner`(P1)

- 白名单 + `gate` 分档双重拒绝;被拒提议落 `planner_calls.rejected`(证据,不是静默)。
- 每次调用(含失败)都落库 → 无存档则 engine 丢弃该提议。
- 无 LLM 配置时确定性循环照跑(验收脚本里 `planner: false` 一路通过)。

## 真机验收(2026-11-13)

`scripts/acceptance-v02.ps1`(全新数据库、独立 workspace、可重放)最后输出:

```
== autonomous run ==   stop = needs_approval  steps = 2
     the run stopped at the tier-2 door
     the autonomous run executed only tier-1 capabilities
     pending carries the exact request / minimum impact / stop condition
== evidence ==         every request left an audit row
                       the /.git/config probe was recorded
                       all findings are candidates
== tier-2 door ==      execute without an approval is refused (403)
                       operator approval recorded (201)
                       execute without a high-auth record is refused (428)
                       a high-auth record signed with the wrong key is refused (403)
                       execute with approval + high-auth succeeds (200, 能力只跑一次)
                       the approval was consumed (second execute refused, 403)
== database guards ==  audit_log refuses UPDATE at the database level
                       candidate->verified is refused without an operator verdict
                       approved=true is refused without an approval row
                       verdict without an explicit confirmation is refused
                       a confirmed verdict is accepted
== report ==           report bundle renders / markdown report renders
ALL ACCEPTANCE ASSERTIONS PASSED
```

## 与 DEVPLAN-v0.2 的差异(逐条)

1. **SPA 手写,无 React/Svelte、无构建步骤。** `go:embed` 单二进制不变;收益是供应链里没有 Node,
   代价是没有前端生态。ADR-004 要的是"SPA + go:embed 单二进制",两点都满足。
2. **循环是"调一次跑一段"的有界循环,不是常驻 ticker。** 与 ADR-002 定位一致;
   SSE 每秒推一次快照给 UI,不需要常驻 planner goroutine。
3. **`internal/step` 合并进审批台。** v0.1 的会话状态机被 API 的单步执行路由取代
   (一次一个 intent、双条件、批准即消费),避免了第二套状态机。
4. **high-auth 只验不签。** youkai 用与 Fairy 完全一致的 HMAC + 规范化来验证;
   `FAIRY_AUTH_KEY` 不设时,档 2 执行返回 428 直接禁用(而不是降级)。
5. **审计行在拿到响应后写入。** 写入失败 → 丢弃响应并报错。残留窗口:一个请求的字节已离开但未记账。
   换成"发前记账"会让每一行永久缺少结果字段(审计表 append-only),更差。这条写在 `guard.go` 注释里。
6. **findings 也做了幂等**(`dedupe_key = sha256(title|kind|where)`),否则重复跑同一扫描会堆重复候选。

## 未做 / 已知缺口

- **browser 能力恒为 `ErrUnavailable`:没有接入 CDP。** 因为一旦用 Chrome 发页内请求,
  目标流量就绕过了 `discipline.Guard` —— 那会破坏"唯一发包路径"。正确做法是 CDP `Fetch.*`
  拦截 + 逐请求 scope 校验(像 Fairy 那样),这需要一份受闸的本地控制通道,本版没做,
  所以宁可明确降级,也不开第二个出口。
- **`accounts_seed` / `accounts_register` / `object_seed`**:注册了档 2 但返回"本构建不实现"。
  账号层需要凭据存储策略,没在 DEVPLAN-v0.2 的范围内细化。
- **`download` 档 2 是桩**:需要与 Guard 结合的流式下载 + 大小上限,当前只返回原因。
- **disasm/decompile 依赖外部后端**,Windows 批处理包装(jadx.bat / analyzeHeadless.bat)
  无法在不经 shell 的情况下启动,因此在这些机器上返回 `ErrUnavailable`(doctor 会标红)。
- **多用户/RBAC** 仍按 ADR-003 不做:v1 单机单操作员 + 本地令牌 + Origin 校验。
