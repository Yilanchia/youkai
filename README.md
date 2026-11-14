# youkai

**一个没有直接打击能力的脑 —— 一个自托管的授权渗透控制台。**

youkai 把 Fairy(web)与 Verdex(binary)的精华**原生吸收**进一个 Go 二进制:常驻 HTTP 控制台 +
PostgreSQL 账本 + 内嵌 SPA。它自己对目标发请求,所以那套"只读默认、逐请求审计、利用停在人前、
自动深度利用编译期不存在"的纪律,从"委托给另一个进程"变成了它**自己的骨头**。

> ADR-004 一句话:youkai 单体化,把 Fairy/Verdex 的精华收进一个平台 ——
> 但收进来的第一样东西是它们的纪律,不是它们的扫描器。

## 它是什么 / 不是什么

**是**:一个授权范围内的、证据优先的 web + 二进制取证控制台。它能**自己把只读取证链走完**,
在该停的地方停下,把每一条结论连同证据、最小影响、停止点、反证一起留下来,让第三方能复核。

**不是**:不是自动攻击器。它不自动利用、不横向、不外带、不窃凭据、不做持久化或隐蔽规避。
"走得远"在这里的定义是**朝可辩护的授权取证走得远**,不是朝利用深度走得远。

## 三档能力模型(全局安全骨架)

| 档 | 含义 | 谁能执行 |
|---|---|---|
| **档 1** 只读取证 | 探测 / 扫描 / 爬取 / 比对 / 渲染 / 静态分析 | 自治引擎**可无人执行** |
| **档 2** 证明级 | 主动探针 / 写方法 / 登录 / 账号播种 / PoC 文本 | **一次一个,人批 + high-auth 双条件**,绝不自治 |
| **档 3** 自动深度利用 | getshell / 横向 / 外带 | **不在本仓库**,编译期 build tag 墙外 |

分类**失败即封闭**:任何不在白名单上的能力一律当档 3。自治循环只跑档 1;档 2 永远停在人手前;
档 3 这个仓库里根本没有它的实现,也没有能打开的开关。

## 架构总览

```
┌─ 前端 SPA(内嵌 go:embed,手写,无构建链)  审批台 / 证据·报告 / 任务台 / 探索图 / 配置·墙 / 审计日志
├─ HTTP + SSE API(internal/api)             只听 127.0.0.1,本地令牌 + Origin 校验
├─ 引擎(internal/engine)                     事件循环:派单 → 判档 → 执行 → 回灌 → 再派,遇档 2/敏感即停
├─ 能力(internal/web · internal/binary)      原生吸收 Fairy / Verdex;每个目标动作都挂在脊柱上
├─ 账号层(internal/accounts)                  多身份 / 归属 / BOLA;密码走环境变量
├─ 纪律脊柱(internal/discipline)   ★唯一发包通道★  scope 护照 / 逐请求审计 / 限速 / 数据最小化 / high-auth
├─ 档位墙(internal/gate)                      分档表 + 档 3 build-tag 隔离
└─ 账本(internal/ledger · PostgreSQL)        资产图 + 探索图 + 发现 + append-only 审计(触发器护栏)
```

### 包速查

| 包 | 职责 |
|---|---|
| `internal/discipline` | 脊柱:`Scope` 护照、`Guard.Do`/`Guard.Authorize`(唯一出口)、`highauth`、防 DNS rebinding 的 dialer |
| `internal/gate` | 档位分类(失败即封闭)、`exploit_stub.go`(档 3 墙) |
| `internal/ledger` | PostgreSQL 账本、`schema.sql` 触发器、append-only 审计 |
| `internal/web` | 原生 web 能力(Fairy 精华)+ CDP 浏览器(`browser.go`/`cdp.go`/`ws.go`) |
| `internal/binary` | 原生二进制静态分析(Verdex 精华),只读、离线、不执行样本 |
| `internal/accounts` | 身份清单、登录、会话加密存储、BOLA 配对 |
| `internal/engine` | 事件驱动循环、确定性派单规则、LLM planner 接入 |
| `internal/planner` | LLM 提议(只提议,放行归 gate);调用全落 `planner_calls` 可回放 |
| `internal/runtime` | 能力派发、会话名→headers 解析、目标解析 |
| `internal/api` + `web/` | HTTP/SSE 控制面 + 内嵌 SPA |
| `cmd/youkaid` | 服务入口(单二进制) |

## 纪律脊柱(唯一发包路径)

```
任何能力 ──► discipline.Guard ──► 目标
                 │
                 ├─ Scope 护照校验(include/exclude/方法/私有网段/过期/预算)
                 ├─ 解析后 IP 复核(dialer Control,防 DNS rebinding)
                 ├─ 限速 + 请求预算
                 ├─ 逐请求审计 → audit_log(数据库层 append-only)
                 └─ 数据最小化:响应体截断,Set-Cookie 只留属性、值打码
```

两条进入目标的路,都收口在这里:
- `Guard.Do` —— youkai 自己的 HTTP 客户端(扫描 / 探测 / 登录等)。
- `Guard.Authorize` —— 别的发送者(CDP 浏览器)逐请求的放行决定,**审计行放行前写、写不成即拒**。

**代码里除 `internal/discipline` 外没有第二个发包点** —— 这不是约定,是 `egress_test.go` 的静态检查:
任何包出现 `http.Client`/`http.Get`/`http.NewRequest`,或裸 `net.Dial*`,都会让测试失败。
唯一例外是 CDP 握手文件 `internal/web/ws.go`(且它 dial 前强制 loopback),和 LLM planner 打模型端点(拿不到目标流量)。

无护照 → 一个请求都不发。越界 URL → 先阻断再记审计。跳转 → 每一跳重新校验。

## 不变量与落点

| 不变量 | 落点 |
|---|---|
| 无 scope 不动作 | `Guard` → `Scope.Check`;`runtime` 没有护照直接报错 |
| 逐请求审计 | 每跳一条 `audit_log`;触发器禁止 UPDATE/DELETE |
| 自治只跑档 1 | `gate.AutonomousOK` + 引擎派单 + 执行三处独立检查 |
| 档 2 停人前 | 引擎 park 成 `Pending`(确切请求/最小影响/停止点/证据),run 退出 `needs_approval` |
| 档 2 双条件 | `api.executeIntent`:先验 high-auth 记录,再原子消费一次批准;缺一即拒 |
| 永不自动 approve | 触发器:`intents.approved=true` 必须有未消费、指纹匹配的 `approvals` 行 |
| candidate 不自动转 verified | 触发器:缺操作员判定即拒;唯一写入路径是 `Store.VerifyFinding` |
| 失败不重试 | 引擎只留 trace,intent 保持 active |
| LLM 只提议 | 白名单 + 分档双拒;无 `planner_calls` 存档的提议被丢弃 |
| 档 3 不存在 | `gate/exploit_stub.go` 的 `//go:build !youkai_full`,全仓仅此一处 |

## 快速开始

依赖:**Go ≥ 1.22** 和一个**本机 PostgreSQL**(ARTEX 同款账本后端)。

> ⚠️ `youkaid.exe` 是控制台服务端,**不是 GUI** —— 直接双击它不会弹窗,而且缺 `YOUKAI_DSN` 会一启动就退出(看着像"打不开")。用下面的启动器,别双击 exe。

### 最简单:双击启动器

双击仓库根目录的 **`start-youkai.cmd`**(或在 PowerShell 里跑 `scripts/start-youkai.ps1`)。它会:
拉起本机 PostgreSQL → 建库 → 配好 DSN 与会话密钥 → 启动 youkaid → 自动用浏览器打开控制台。
出错会停在窗口里显示原因,不一闪就关。

### 手动(看清每一步)

```powershell
# 1) 准备数据库(一次性)
#    建库建角色,例如:
#    createuser youkai; createdb -O youkai youkai
#    仓库 .pgsql/ 里带了一个本机实例的数据目录,可直接拉起:
D:\tools\pg\pgsql\bin\pg_ctl.exe -D .pgsql\data -o "-p 55432" start

# 2) 构建(单二进制,SPA 已 go:embed 进去)
go build -o youkaid.exe ./cmd/youkaid

# 3) 配环境并启动(只听 127.0.0.1)
$env:YOUKAI_DSN        = "postgres://youkai@127.0.0.1:55432/youkai?sslmode=disable"
$env:FAIRY_AUTH_KEY    = "<≥16 字符;档 2 对网络目标的 high-auth 校验用;不设则档 2 执行被禁用>"
$env:YOUKAI_SESSION_KEY= "<会话加密密钥;不设则 base64 落盘并告警>"
$env:ALICE_PW          = "<测试账号密码;清单里只写 password_env 的名字>"
.\youkaid.exe -addr 127.0.0.1:8799

# 4) 打开终端打印的地址(令牌在 URL fragment 里,不进服务器日志)
#    http://127.0.0.1:8799/#token=...
```

> 启动时若 `FAIRY_AUTH_KEY` 未设,控制台会告警:**档 2 对网络目标的执行被禁用**(批准仍会记录,只是不放行)。

## 配置参考

### 优先级:**UI 保存的配置 > 环境变量 > 禁用**

模型怎么连、护照到哪,都可以在控制台的「配置」面板里改,**保存即热生效**(不用重启)。
配置文件存在 PostgreSQL 的 `settings` 表;LLM 的 API key 要么引用环境变量(推荐,不落库),
要么加密存进 `secret_enc`(需 `YOUKAI_SESSION_KEY`,否则拒绝保存 —— 不会退化成明文)。

**环境变量**(也都有同名 CLI flag,flag 优先):

| 变量 | 作用 | 默认 |
|---|---|---|
| `YOUKAI_DSN` | PostgreSQL 连接串(必填) | — |
| `YOUKAI_ADDR` | 监听地址(只应为 loopback) | `127.0.0.1:8799` |
| `YOUKAI_ARTIFACTS` | 产物目录(截图/样本/生成文本) | `.youkai/artifacts` |
| `YOUKAI_ACCOUNTS` | 身份清单路径 | `.youkai/accounts.json` |
| `YOUKAI_SESSIONS` | 加密会话目录 | `.youkai/sessions` |
| `YOUKAI_TOKEN` / `YOUKAI_TOKEN_FILE` | API 令牌 / 令牌落盘路径(0600) | 留空则自动生成 |
| `FAIRY_AUTH_KEY` | high-auth 记录**验签**密钥(只验不签) | 不设 → 档 2 网络执行禁用 |
| `YOUKAI_SESSION_KEY`(兼容 `FAIRY_SESSION_KEY`) | 会话与 secret 的 AES-256-GCM 加密 | 不设 → 会话 base64+告警;直填 LLM key 被拒 |
| `YOUKAI_LLM_BASE_URL/API_KEY/MODEL` | LLM planner 的环境变量来源(可选补位) | 不设 → 确定性循环照跑 |

**CLI flags**:`-addr -dsn -artifacts -accounts -sessions -max-steps -token -token-file -no-planner`。

### LLM 配置(UI 可编辑)

| 字段 | 说明 |
|---|---|
| `enabled` | 关掉也不影响确定性循环(LLM 只是补位) |
| `base_url` / `model` | 必填才能启用;base_url 必须是 http(s) |
| `temperature` / `timeout_s` / `max_tokens` | 默认 0 / 120 / 1200,可调 |
| `key_from_env` | 只存**环境变量名**,key 不落库(推荐) |
| `key` | 直接填则加密存库;响应里永远只回 `key_present` |

- `GET /api/config/llm` 只看状态(无 key 明文);`PUT` 保存并热替换;`POST /api/config/llm/test`
  发一次最小 completion,只回 `{ok, latency_ms, error}`,**不回模型输出、不写账本**。
- 每次保存都写一条 `audit_log`(`method=CONFIG`, `url=config:llm`),detail 只有旋钮、没有 key。

### 护照(scope)字段

`include[]`(必填)、`exclude[]`(排除优先)、`methods[]`(默认 `GET/HEAD/OPTIONS`)、
`allow_private`、`allow_active_probes`(解锁 param/waf 档 2)、`allow_waf_probe`、
`allow_object_seeding`、`allow_account_provisioning`、`max_requests`、`rps`、`expires_at`、
`basis`(≥8 字)、`operator`。

- 非法护照(空 include / `*` / `*.tld` / basis 太短 / 已过期)在保存时被拒,错误回显。
- **放宽护照**(加目标 / 加写方法 / 开档 2 开关)会写一条 `config:scope` 审计;
  它改变的是"能看哪里",不是"能做什么"—— 档 2 仍要人批,档 3 仍不存在。
- 开写方法/档 2 开关只是"允许它发生",能力本身仍停在审批台。
## 一次典型作业

1. **建作业(engagement)+ scope 护照**:给出授权目标(include/exclude、允许方法、速率、请求预算、过期)。
   护照是一切的前提 —— 没有它,一个请求都发不出去。
2. **自治只读推进**:引擎从护照自举,跑 probe/scan/crawl/compare… 回灌 fact,顺着证据往下派下一步。
   全程只读(档 1),无人值守。
3. **停在档 2 门口**:当下一步是主动探针 / 写方法 / 登录 / 播种时,引擎**停下**,把这一步连同
   "确切会发的请求 + 最小影响 + 停止点 + 证据"摆到**审批台**,状态 `needs_approval`。
4. **一次批一步**:操作员在审批台看清楚,用 high-auth 记录 + 一次批准放行**这一个**动作;
   youkai 执行它、回灌证据、再停在下一步。没有批量、没有"全部放行"。
5. **判定与报告**:发现默认是 `candidate`;只有操作员显式判定才升 `verified`(数据库层强制)。
   证据·报告面板按账本投影出跨能力报告,每条带 `request_id`/`file:line`。

档 3 在这条线里不存在:自治段不会走到利用,利用段每一步都在人手上。

## 控制台面板(SPA)

按"安全故事"排序,不按花哨排:

- **审批台** — 档 2 的人控闸,一次一个待批动作;看得见确切请求与最小影响,逐个批。
- **证据 · 报告** — 账本投影出的跨能力报告 + 四样证据。
- **任务台** — 建 / 看 / 停作业,看停止点。
- **探索图** — goal/fact/finding/hint 血缘,只读。
- **配置 · 墙** — LLM 配置(**可编辑**:base_url/model/温度/超时/key 来源/连通测试)、护照编辑器(全部旋钮)、
  只读的档位墙状态。墙不是可配项,面板里没有任何开关能碰它。
- **审计日志** — 逐请求 + 逐审批,只读。

API 面(都在 `127.0.0.1`,需令牌 + 同源):`/api/health`、`/api/config`、`/api/config/llm`(GET/PUT)、
`/api/config/llm/test`(POST)、`/api/engagements`、`/api/engagements/<id>/…`、`PUT /api/engagements/<id>/scope`。

## 能力清单

| 包 | 档 1(自治只读) | 档 2(人批) |
|---|---|---|
| `internal/web` | probe, fingerprint, scan, crawl, compare, role_matrix, proof, headers, cors, exposures, redirect_check, browser(CDP,页内每请求过 Guard;无 Chrome 即降级), accounts_show, reachability(需 high-auth) | param, param_adaptive, waf, login |
| `internal/accounts` | — | accounts_provision, accounts_seed, object_seed, accounts_register |
| `internal/binary` | artifact_identify/register, strings, checksec(原生 ELF/PE 解析), symbols, disasm, decompile, mobile_unpack, firmware_extract, secrets(掩码), dataflow, sarif, doctor | pwn_template, pwn_gdbscript, web_poc, impact_proof, frida_script, download |

二进制全程**只读、离线、不执行样本**;缺后端(Ghidra/jadx 等)会明确降级(`doctor` 预检),不伪造结果。
档 2 的 `pwn_*`/`web_poc`/`impact_proof` 只写**骨架文本**到隔离目录,由人审阅后自己在授权范围内运行。

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

- `accounts_provision`(档 2):每个身份**只登录一次**,每身份独立 cookie jar(防串味),会话加密存盘,归属写成事实。
- `accounts_seed` / `object_seed`(档 2):需 `allow_object_seeding` + 含 POST + `confirm` + 人工批准;每账号一个最小对象,不删不改。
- `accounts_register`(档 2):只提交一次;CAPTCHA/短信/OTP → `needs_human` 不绕过;邮箱验证只接受人工 `verification_url`。
- 归属 → 引擎自动派 `compare`(档 1,两次只读 GET)→ 标记两边可见即 `bola` 候选。
- 会话值**从不进账本**:意图里记 `session_a: "alice"`,headers 在派发前才从加密库取出;`accounts_show` 脱敏,不回 cookie/密码。

## 浏览器(CDP,且不许绕过 Guard)

```
Chrome(headless)──CDP ws(仅 loopback)──┬─ Fetch.enable(*)→ 每个页内 http(s) 请求
                                        │      ├─ Guard.Authorize → continueRequest(先审计后放行)
                                        │      └─ 拒绝 → Fetch.failRequest(blocked 审计行)
                                        └─ Target.setAutoAttach → 弹窗/OOPIF/worker 子 target 也挂闸
```

Chrome 自己开 socket,所以这里不是让 youkai 绕过脊柱,而是把浏览器变成脊柱的**客户端**:每个页内请求都由
`Guard.Authorize` 逐个判 scope + 记账,越界的当场 `failRequest` 并记 blocked。渲染子资源也照判,所以引用第三方 CDN
的页面会渲染不全 —— 这是有 scope 的作业应有的结果。

**子 target 失败即封闭**:`Target.setAutoAttach` 一旦建立失败,弹窗 / 跨进程 iframe / worker 会有各自不受本会话
Fetch 门管辖的 CDP 会话 —— 那就是未受闸出口。"无未闸请求"是绝对不变量,不是尽力而为,所以此时 youkai **直接拒绝渲染**
(fail-closed),而不是带着缺口往下跑。唯一的原始 socket(CDP 握手)锁死 loopback,且被 `TestNoEgressOutsideTheGuard` 静态盯住。

当前限制:浏览器**暂不注入已存会话**(`session` 还没接到 CDP `Network.setCookie`),所以只做匿名渲染 + 闸门;
登录态多身份浏览器是下一步。无 Chrome/Edge → `ErrUnavailable` + 明确原因,不伪造。

## 测试与验收

```bash
export YOUKAI_TEST_DSN="postgres://youkai@127.0.0.1:55432/youkai_test?sslmode=disable"  # PG 相关测试需要
go vet ./...        # 干净
go test ./...       # 全绿(默认并行;migrate 用会话 advisory lock 串行化,不再抢锁死锁)
```

数据库层护栏(真 PostgreSQL 上跑):`UPDATE audit_log` → 被拒(append-only);`UPDATE findings SET state='verified'`
→ 需操作员判定;`UPDATE intents SET approved=true` → 需未消费且指纹匹配的批准行。

`scripts/acceptance-v02.ps1` 把这些连同一轮真机只读链、档 2 双条件(含 high-auth 缺失返 428)、
账号层 provision/seed、浏览器越界拦断、报告生成,全部做成可重放断言(独立数据库、独立 workspace,不污染真实账本)。
逐模块证据见 [docs/IMPL-STATUS-v0.3.md](docs/IMPL-STATUS-v0.3.md)。

## 设计取舍与未做

**与 DEVPLAN 的取舍**:SPA 手写(无 React/Svelte、无构建链 → 供应链里没有 Node);agent 循环是"调一次跑一段"
的有界循环,不是常驻 ticker(SSE 推状态给 UI);`internal/step` 并入审批台的单步执行;high-auth **只验不签**
(记录由人用 `FAIRY_AUTH_KEY` 生成,youkai 用同套 HMAC 规范化验证,Fairy 的记录可直接用);审计行在拿到响应后写,
写不成就丢弃响应并报错。

**未做 / 路线图**:
- 浏览器注入已存会话(`Network.setCookie`)→ 登录态 SPA/DOM 流。
- `accounts_register` 的邮件多步验证 UI 入口(现在只能经能力参数传 `verification_url`)。
- worker trace 的跨轮检索 / 复用。
- 多用户 / RBAC:按 ADR-003 v1 不做,只本机单操作员 + 本地令牌 + Origin 校验。
- 账号清单 / 会话目录单文件跨作业共享(自托管单操作员下合理;要隔离给 `-accounts`/`-sessions` 传不同路径)。

## 许可与血统

youkai 本身 **MIT**。它**原生移植** Fairy 与 Verdex 的能力 —— 两者都是 **MIT、同作者**,移植时保留其版权与 notice。
平台 / 事件架构**只借 ARTEX 与 norma 的思想,不复制其任何代码**(它们是 **AGPL-3.0**)。档 3 的自动深度利用内核
不在本仓库、不在任何 OSS 文档里。

## 延伸阅读(docs/)

- [ADR-004](docs/ADR-004-monolith-absorb.md) 单体化·吸收精华(**最新权威**)· [ADR-003](docs/ADR-003-platform-pivot.md) 平台化 · [ADR-002](docs/ADR-002-youkai-brain-architecture.md) 脑架构 · [ADR-001](docs/ADR-001-architecture-direction.md) 方向总纲
- [DEVPLAN-v0.2](docs/DEVPLAN-v0.2.md) 单体平台实现规格 · [DEVPLAN-v0.1](docs/DEVPLAN-v0.1.md) 引擎核心
- [IMPL-STATUS-v0.3](docs/IMPL-STATUS-v0.3.md) 当前落地报告 · [GAPS-v0.2](docs/GAPS-v0.2.md) 缺口清单

## 红线

只对**授权目标**动手:CTF、自建靶场、你拥有或被明确授权的系统。没有护照,youkai 一个请求都不会发;
利用只在人逐步过闸时发生;自动深度利用不在本仓库,也没有能打开的开关。
