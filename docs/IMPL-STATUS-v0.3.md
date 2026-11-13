# IMPL-STATUS v0.3 — GAPS-v0.2 收口(账号层 + CDP 浏览器)

> 日期:2026-11-13 · 承接 GAPS-v0.2 的两个缺口 · `go test ./...` 全绿 · `scripts/acceptance-v02.ps1` 全通过
> 新增:`internal/accounts/`、`internal/web/{ws,cdp}.go`、`internal/web/browser.go`(真实实现)、
> `discipline.Guard.Authorize/Refuse/Clone`、`runtime` 的会话与目标解析、引擎的 BOLA 派单。

## 一句话

两个缺口都补上了,而且**都是先接骨头再长功能**:账号层的登录/播种走档 2 双条件,
浏览器把**每一个页内 http(s) 请求**都交回 `discipline.Guard` 判 scope —— 页面没有不经 Guard 的出口。

## 缺口 1:账号层 `internal/accounts`

### 形态

```
accounts.json (YoukaiAccounts/v1)
   ├─ name / role / login{url,method,fields,password_env,json,token_field}
   ├─ owns[{marker,url,note}]        ← 归属真值(操作员声明)
   └─ seed{create,extract,marker_path,item_url}   ← 或由账号自建一个最小对象
        │
        ▼
Service.Provision  每身份一个 Guard.Clone(独立 cookie jar、共享预算)→ 只登录一次 → 会话加密落盘
Service.Show       name/role/owns/session_ready + BOLA 配对(**无凭据**)
Service.Seed       allow_object_seeding + POST + confirm + 档 2 人批;每账号一个对象,不删不改
Service.Register   CAPTCHA/短信/OTP → needs_human,不绕过;邮箱验证只接受人工 verification_url
Service.Reachability  high-auth 验签 + 覆盖校验后,多身份只读 GET
```

会话存储:设置 `YOUKAI_SESSION_KEY`(或兼容 `FAIRY_SESSION_KEY`)→ **AES-256-GCM + scrypt**;
未设置 → base64 并在文件里写警告(等同明文),`Show()` 会把它作为 warning 显示出来。
文件 0600,目录 0700,并且**不落在账本里**。

### 验收证据(真机)

`scripts/acceptance-v02.ps1` 的 `== accounts ==` 段:

```
ok  accounts view renders / two identities come from the manifest
ok  declared ownership produces BOLA pairs
ok  the accounts view carries no password
ok  provision intent queued / is classified tier 2
ok  provision without high-auth is refused (precondition required)   ← 428
ok  provision executed once with approval + high-auth
ok  both identities now have a stored session
ok  the accounts view leaks no session value          ← sess-alice / sess-bob / Cookie 都不出现
ok  seeding executed once with both conditions
ok  BOLA pairs are available after provisioning
```

单元测试(`internal/accounts/accounts_test.go`,12 项)另外钉住:

- `TestProvisionLogsInOnceAndRecordsOwnership`:每账号**恰好一次**登录(服务器计数),
  观察里没有密码/会话值,归属 fact 存在。
- `TestProvisionFailsCleanlyWhenThePasswordIsMissing`:缺 `password_env` → 明确失败,**零请求**。
- `TestShowNeverReturnsSecrets`:序列化后不含密码/Cookie。
- `TestSeedRequiresAllThreeGates`:缺 `allow_object_seeding` / 缺 `confirm` / 缺 POST → 全部拒绝且零请求。
- `TestRegisterStopsAtACaptcha`:带 captcha 字段的表单**不提交**;响应里出现校验 → needs_human + 证据。
- `TestReachabilityNeedsHighAuthAndOnlyReads`:无记录/覆盖不到 → 拒;正确记录 → 只有 GET。
- `TestSessionStoreEncryptsAndHidesValues`:磁盘上无明文、错密钥解密失败、列表不含值。

### 越权闭环

归属 → BOLA 配对 → 引擎派 `compare`(档 1,两次只读 GET)→ 真实发现。真机结果:

```
ok  the engine derived compare intents from ownership
ok  the comparison ran and was recorded
ok  the deliberately broken object produced a BOLA candidate
```

靶场故意保留一个**正确受限**的对象(`/orders/1`,只有 alice 能读)和一个**故意越权**的对象
(`/orders/2`,任何登录态都能读)。前者产出 `marker-in-a-only`(不出 finding —— 不虚报),
后者产出 `bola` 候选。**证据是真的,不是脚本自己造的。**

## 缺口 2:CDP 浏览器 `internal/web/{ws,cdp}.go` + `browser.go`

### 为什么不能简单起个 Chrome

浏览器自己开 socket、自己解析域名、自己跟跳转 —— 那是 guard 看不见的第二条出口。
所以本实现的形状是:浏览器是 **guard 的客户端**,不是绕过它的方式。

```
launch(headless, --remote-debugging-port=0)
   └─ 从 stderr 解析 DevTools ws://127.0.0.1:PORT/...
        └─ dialWS:仅 loopback(硬检查,非 loopback 直接拒)
             └─ Target.createTarget → attachToTarget(flatten) → 每 session:
                  Page/Runtime/Network.enable
                  Fetch.enable{patterns: "*", requestStage: Request}   ← 拦截一切
                     ├─ http(s) → Guard.Authorize → allowed: continueRequest(审计行已写)
                     │                             refused: failRequest(blocked 审计行)
                     └─ data:/blob:/about: → continue(不出进程,不算 egress)
                  Target.setAutoAttach(waitForDebuggerOnStart)  ← 弹窗/OOPIF 也先挂上网关
```

`Guard.Authorize` 是这次给脊柱加的唯一新出口,它**只做决定与记账**:
过期 → 方法 → scope → 预算 → 限速,然后**先写 allowed 审计行再放行**(写不进去就不放行),
返回 `request_id` 给浏览器侧引用。`Guard.Refuse` 记录被拦断的请求。

> 比 Fairy 更严: Fairy 让渲染子资源(图片/CSS/脚本)直接放行以免页面花掉;GAPS 要求
> "每个页内请求",所以这里**所有 http(s)** 都过闸。代价是引用第三方 CDN 的页面会渲染不全 ——
> 这正是一个有 scope 的作业应有的结果。

### 验收证据

单元测试(`internal/web/browser_test.go` + WS 编解码):

- `TestWSFrameRoundTrip` / `TestWSReadReassemblesFragments` / `TestWSHandshake`:帧编解码与握手。
- `TestWSRefusesNonLoopback`:`ws://example.com:9222` 与 `wss://` 直接拒绝。
- **`TestBrowserRendersAndBlocksOutOfScope`(真 Chrome)**:页面标题/链接/XHR 都读到了,
  同一个页面里 `fetch('http://out-of-scope.invalid/beacon')` 被 `failRequest` 拦断,
  审计里有 blocked 行,且观察引用的每个 `request_id` 都能在审计表里查到。

真机验收:

```
ok  browser intent queued / is tier 1
ok  the browser rendered the page title (DOM only)
ok  the browser observed a same-origin XHR
ok  the in-page out-of-scope fetch was blocked and recorded
```

无 Chromium 时 → `ErrUnavailable` + 明确原因(验收脚本对此有单独的降级断言),不伪造结果。

### 静态焊死仍然成立

`TestNoEgressOutsideTheGuard` 现在**同时**禁止:

- 非 `internal/discipline` 包出现 `http.Client` / `http.Get` / `http.NewRequest` / `http.DefaultClient`;
- 非 `internal/discipline` 包出现 `net.Dial` / `net.DialTimeout` / `net.DialTCP` …,
  **唯一例外**是 `internal/web/ws.go`(CDP 握手,且它先检查 loopback)。

加 CDP 没有撞穿这条墙:墙长了一格,把原始 socket 也圈进去了。

## 顺带修掉的三个真问题

1. **档 2 的 high-auth 曾可被绕过**:`accounts_provision` 的目标不在 args 里(在清单里),
   原来的判断 "args 里有 URL 才要 high-auth" 会让它只凭批准就执行。现在改成
   **按能力判定 + 目标解析**(`runtime.TargetsFor`):网络型能力一律要记录,并且逐目标校验覆盖。
2. **批准会被失败的前置条件烧掉**:先把批准消费掉再查 high-auth,导致 428 之后批准就没了。
   现在先验(peek)两个条件,再原子消费。
3. **PowerShell 的 `$args` 陷阱**:验收脚本的辅助函数用 `$args` 当参数名,会静默绑定到自动变量,
   表现为"派生意图失败"。已改名并在脚本里留注释。

## 与 GAPS-v0.2 的差异 / 未做

- **账号清单是单文件、跨作业共享**(`.youkai/accounts.json`),会话目录也是单份。
  GAPS 只写了"清单 `.youkai/accounts.json`",没有要求按作业隔离;多作业共用同一批测试身份
  在自托管单操作员场景下是合理的。若要按作业隔离,给 `-accounts/-sessions` 传不同路径即可。
- **`accounts_register` 只做到"提交一次 + 人工校验检测"**。真正的多步注册(收邮件点链接)
  需要人工把 `verification_url` 交给 API;这一步没做 UI 入口,只能通过能力参数传。
- **browser 不注入已存会话**:`session` 参数尚未接到 CDP 的 `Network.setCookie`。
  当前实现只做匿名渲染 + 闸门;多身份浏览器是下一步。
- **browser 截图落在 artifact 目录**并作为 fact 引用路径,但没有在 SPA 里内联显示(避免把图像塞进 JSON)。
- **`Target.setAutoAttach` 失败时**会在 blocked 列表里留一条 `cdp://auto-attach` 说明,
  不会静默降级;但这也意味着"子 target 未受闸"这一事实需要操作员看那条证据去判断。
