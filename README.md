# youkai

**一个没有直接打击能力的脑 —— 现在是一个单体平台。**

youkai 把 Fairy(web)与 Verdex(binary)的精华**原生吸收**进一个 Go 二进制:常驻的 HTTP 控制台 +
PostgreSQL 账本 + 内嵌 SPA。它自己发目标请求了,所以那套"只读默认、逐请求审计、档 2 停人前、
档 3 编译期不存在"的纪律,从"委托给另一个进程"变成了**自己的骨头**。

> ADR-004 的一句话:youkai 单体化,把 Fairy/Verdex 的精华收进一个平台 ——
> 但收进来的第一样东西是它们的纪律,不是它们的扫描器。

## 快速开始

```powershell
# 0) 依赖:Go >= 1.22、一个本机 PostgreSQL 17(仓库 .pgsql/ 里有本机实例的数据目录)
#    本机实例:D:\tools\pg\pgsql\bin\pg_ctl.exe -D .pgsql\data -o "-p 55432" start

# 1) 构建(单二进制,SPA 已嵌入)
go build -o youkaid.exe ./cmd/youkaid

# 2) 启动控制面(只听 127.0.0.1)
$env:YOUKAI_DSN = "postgres://youkai:***@127.0.0.1:55432/youkai?sslmode=disable"
$env:FAIRY_AUTH_KEY = "<至少 16 字符,档 2 的 high-auth 校验用;不设则档 2 执行被禁用>"
$env:YOUKAI_SESSION_KEY = "<至少 8 字符,登录会话加密;不设则 base64 落盘并警告>"
$env:ALICE_PW = "<测试账号密码;清单里只写 password_env 的名字>"
.\youkaid.exe -addr 127.0.0.1:8787 -accounts .youkai/accounts.json -sessions .youkai/sessions

# 3) 打开终端打印的地址(令牌在 URL fragment 里,不进服务器日志)
#    http://127.0.0.1:8787/#token=...
```

面板顺序按"安全故事"排:**审批台 → 证据·报告 → 任务台 → 探索图 → 配置·墙 → 审计日志**。
审批台一次只批一个动作,没有批量、没有"全部放行"。

## 纪律脊柱(唯一发包路径)

```
any capability ──► discipline.Guard.Do ──► target
                        │
                        ├─ Scope 护照校验(include/exclude/方法/私有网段/过期/预算)
                        ├─ 解析后 IP 复核(dialer Control,防 DNS rebinding)
                        ├─ 限速 + 请求预算
                        ├─ 逐请求审计 → audit_log(数据库层 append-only)
                        └─ 数据最小化:响应体截断,Set-Cookie 只留属性、值打码
```

**代码里除 `internal/discipline` 外没有第二个发包点** —— 这不是约定,是
`internal/discipline/egress_test.go` 的静态检查:任何包出现 `http.Client` / `http.Get` /
`http.NewRequest` 都会让测试失败(唯一例外是 LLM planner 打模型端点,它永远拿不到目标流量)。

无护照 → 一个请求都不发(`errNoScope`)。越界 URL → 先阻断再记审计。跳转 → 每一跳重新校验。

## 不变量与落点

| 不变量 | 落点 |
|---|---|
| 无 scope 不动作 | `discipline.Guard.Do` → `Scope.Check`;`runtime.Dispatcher` 没有护照直接报错 |
| 逐请求审计 | `Guard.roundTrip` 每跳一条 `audit_log`;触发器禁止 UPDATE/DELETE |
| 自治只跑档 1 | `gate.Tier.AutonomousOK` + `engine.choose` + `engine.execOne` 三处独立检查 |
| 档 2 停人前 | `engine.park` + `Pending`(确切请求/最小影响/停止点/证据),`run` 退出 `needs_approval` |
| 档 2 双条件 | `api.executeIntent`:先验 high-auth 记录,再原子消费一次批准;两者缺一即拒 |
| 永不自动 approve | 数据库触发器:`intents.approved=true` 必须有一条未消费、指纹匹配的 `approvals` 行 |
| 永不把 candidate 改 verified | 数据库触发器:`youkai.operator_verdict` 未置位时拒绝;唯一写入路径是 `Store.VerifyFinding` |
| 失败不重试 | `engine.fail` 只留 trace,intent 保持 `active`(不可再领) |
| LLM 只提议 | `planner/schema.go` 白名单 + 分档双拒;无 `planner_calls` 存档的提议被 engine 丢弃 |
| 档 3 不存在 | `gate/exploit_stub.go` 的 `//go:build !youkai_full`,全仓只有这一处标记 |

## 能力

| 包 | 档 1(自治) | 档 2(人批) |
|---|---|---|
| `internal/web` | probe, fingerprint, scan, crawl, compare, role_matrix, proof, headers, cors, exposures, redirect_check, browser(CDP,页内每请求过 Guard;无 Chrome 即降级) | param, param_adaptive, waf, login |
| `internal/accounts` | accounts_show, reachability(需 high-auth) | accounts_provision, accounts_seed, object_seed, accounts_register |
| `internal/binary` | artifact_identify/register, strings, checksec(原生 ELF/PE 解析), symbols, disasm, decompile, mobile_unpack, firmware_extract, secrets(掩码), dataflow, sarif, doctor | pwn_template, pwn_gdbscript, web_poc, impact_proof, frida_script, download |

二进制全程只读、离线、不执行样本;缺后端会明确降级(`doctor` 预检),不伪造结果。

## 账号层(多身份 / 归属 / BOLA)

`.youkai/accounts.json`(`YoukaiAccounts/v1`)由操作员撰写,密码只走 `password_env`:

```json
{"schema":"YoukaiAccounts/v1","base_url":"http://127.0.0.1:8080",
 "accounts":[
   {"name":"alice","role":"admin",
    "login":{"url":"/login","fields":{"username":"alice"},"password_env":"ALICE_PW"},
    "owns":[{"marker":"ORD-1","url":"/orders/1"}]},
   {"name":"bob","role":"user",
    "login":{"url":"/login","fields":{"username":"bob"},"password_env":"BOB_PW"}}]}
```

- `accounts_provision`(档 2):每个身份**只登录一次**,会话加密存盘,归属写成事实。
- `accounts_seed` / `object_seed`(档 2):需 `allow_object_seeding` + 方法含 POST + `confirm` + 人工批准。
- 归属 → 引擎自动派 `compare`(档 1,两次只读 GET)→ 标记两边可见即 `bola` 候选。
- 会话值**从不进入账本**:意图里记的是 `session_a: "alice"`,headers 在派发前才从加密库取出。

## 浏览器(CDP,且不许绕过 Guard)

```
Chrome(headless)──CDP ws(仅 loopback)──┬─ Fetch.enable(*)→ 每个页内 http(s) 请求
                                        │      ├─ Guard.Authorize → continueRequest(先审计后放行)
                                        │      └─ 拒绝 → Fetch.failRequest(blocked 审计行)
                                        └─ Target.setAutoAttach → 弹窗/OOPIF 也先挂闸
```

比 Fairy 更严:渲染子资源也不放行,所以引用第三方 CDN 的页面会渲染不全 —— 这是有 scope 的作业
应有的结果。`Guard.Authorize` 只做决定与记账,`Guard.Refuse` 记录被拦断的请求;
静态检查 `TestNoEgressOutsideTheGuard` 同时禁止裸 `net.Dial`(唯一例外是 CDP 握手文件)。

## 与 DEVPLAN-v0.2 的已知差异

1. **SPA 是手写的(无 React/Svelte、无构建步骤)。** `go:embed` 单二进制不变,代价是前端没有生态,
   收益是供应链里没有 Node。ADR-004 要求的是"SPA + go:embed 单二进制",这两点都满足。
2. **agent 循环是"调一次跑一段"的有界循环,不是常驻 ticker。** 与 ADR-002 的定位一致;
   SSE 负责把状态推给 UI,不用常驻 planner goroutine。
3. **`internal/step` 已并入审批台。** DEVPLAN-v0.1 的会话状态机被 API 的单步执行路由取代
   (一次一个 intent、双条件、批准即消费),不再有一套并行的状态机。
4. **Fairy high-auth 是"只验不签"。** 记录由人在本机用 `FAIRY_AUTH_KEY` 生成,
   youkai 用同一套 HMAC + `JSON.stringify(payload, sorted keys)` 规范化来验证 ——
   Fairy 生成的记录可以直接用。
5. **审计行在拿到响应后写入**(与 Fairy 一致),写入失败则丢弃响应并报错。
   残留窗口:一个请求的字节已离开但无法记账。换成"发前记账"会让每一行永久缺少结果,更差。

## 验证

```
go vet ./...      干净
go test ./...     全绿(见 docs/IMPL-STATUS-v0.2.md 的逐模块证据)
```

数据库层的保证(在真 PostgreSQL 17.6 上跑):

- `UPDATE audit_log ...` → `audit_log is append-only`
- `UPDATE findings SET state='verified'` → `candidate->verified requires an operator verdict`
- `UPDATE intents SET approved=true` → `intent approval requires an unconsumed operator approval matching fingerprint`

`scripts/acceptance-v02.ps1` 把上面这些连同一轮真机只读链、审批台双条件、报告生成全部做成可重放断言。

## 红线

只对**授权目标**动手:CTF、自建靶场、你拥有或被明确授权的系统。
没有护照,youkai 一个请求都不会发;档 3 不在本仓库,也没有能打开的开关。
