# IMPL-STATUS v0.6 — 登录态浏览器(CDP 注入会话,不破坏唯一发包通道)

> 日期:2026-11-14 · 承接 DEVPLAN-v0.6 · `go test ./...` 全绿 · `scripts/acceptance-v02.ps1` 全通过
> 新增:`internal/web` 的 `Fetch` 闸内 header 注入、`internal/runtime/browser_session.go`、
> SPA「以会话渲染」表单、验收 12 条新断言。

## 一句话

`browser` 现在能"以某个已授权身份去看"页面 —— 会话 header **在闸内、逐请求、按 host** 注入,
不是 `Network.setCookie` 那种把认证流量放出 Guard 之外的写法。登录态是多给了一把钥匙,不是多开了一扇后门。

## 一 · 会话在 Fetch 闸内注入

```
Fetch.requestPaused
  → Guard.Authorize(过)                        ← 先判 scope、先写审计行
      → 请求 host == 该身份的 host ?
          ├─ 是 → Fetch.continueRequest(原 header 合并会话 header)
          └─ 否 → Fetch.continueRequest(不带会话 header)
  → Guard 拒绝 → Fetch.failRequest(blocked 审计)
```

关键实现点:

- `Fetch.continueRequest` 的 `headers` 参数是**覆盖**语义,所以先 `mergeHeaders(请求原 header, 会话 header)`,
  再按名字排序渲染成 `[{name,value}]`(可复现)。header 名大小写不敏感,会话值覆盖同名旧值。
- **没有 `Network.setCookie`**:浏览器自己不持有该凭据,也就不可能在闸外带它发包。
- **host 绑定**:`injection.matches()` 比较 `url.Host`(含端口,忽略大小写)。跨 host 一律不注入 ——
  即使那个 host 也在 scope 内(验收里用 `localhost:18080` vs `127.0.0.1:18080` 钉住)。
- **fail-closed**:`session` 给名但会话加载不到 / header 为空 → 能力返回错误,不渲染。
  "以身份 X 渲染"若实际是匿名的,那是伪造证据。

## 二 · 会话从哪来(runtime)

- 意图里只有 `session: "alice"`;**header 由 `Dispatcher.sessionIdentityFor` 在派发时从加密会话库取出**,
  通过 `web.Env{SessionName, SessionHeaders, SessionHost, SessionWatch}` 传给能力,不进 args、不进图。
- host 归属从清单推导:账号 `login.url` 的 host,退一步用 `owns[0].url` 的 host;
  再退一步(无清单)才用"首个导航目标的 host",并有注释说明这是降级。
- `SessionWatch`:该身份作为 **viewer** 的归属配对(`owner/marker/url`),用于越权视角判定。

## 三 · 登录态证据

- 渲染后追加 fact:`以身份 alice 渲染 <url>(注入 N 个请求;请求逐个过 guard 后才注入)`,
  evidence 含 `session` / `authenticated` / `injected_requests` / `request_id` —— **只有名字,没有值**。
- 越权视角:页面正文(取自 `document.body.innerText`,**只在内存里用于标记比对,不落账本**)出现
  owner 的 marker,且 URL 与该配对的 endpoint 相同 → 产出 `bola` 候选,
  title 里写明"bob 以 bob 看到了 alice 的 ORD-2",evidence 含 `session`/`owner`/`marker`/`request_id`。
  仍是 candidate,不自动 verified(与 v0.5 的规则一致)。

## 四 · 验收

单元 + 真机(`internal/web`,5 项):

```
TestHeaderMergeKeepsRequestHeadersAndWins   合并保留原 header、同名(不分大小写)被替换
TestInjectionOnlyMatchesItsOwnHost          端口/host/userinfo 场景;无 host 绑定或无会话名则不注入
TestInjectionForRefusesAnEmptySession        有名字无 header → 报错(不匿名)
TestBrowserSessionInjection(真 Chrome)      alice 的 cookie 只上 127.0.0.1;localhost 同服务器 0 注入;
                                            观察里没有 cookie 值;每个 allowed 请求都有审计行
TestBrowserViewerBolaCandidate(真 Chrome)   bob 看到 ORD-9 → bola 候选,证据含 session/owner/marker
```

验收脚本新增 12 条断言(全过):

```
ok  authenticated browser intent queued / still tier 1
ok  the render recorded WHO it rendered as
ok  the fact carries the session name
ok  at least one request carried the credential
ok  the authenticated fact cites a request_id
ok  no cookie value reached the ledger
ok  viewer-side render produced a BOLA candidate
ok  the viewer-side finding stays a candidate
ok  the finding names session and owner, not the cookie
ok  an unknown session does not render (no anonymous fallback)
ok  scope widened to cover the second host name
ok  the credential did NOT follow to another host
```

`TestNoEgressOutsideTheGuard` 仍然绿:注入走的是 `Fetch.continueRequest`,没有引入新的 socket 或客户端。

## 与 DEVPLAN-v0.6 的差异 / 未做

- **`session` 走的是 args(名字)+ Env(header)**,不是把 header 放进 args:图里永远只有名字。
  DEVPLAN 写的是"运行期参数传给 browser 能力",实现上选了更窄的那条路。
- **host 归属只认清单**;清单缺失时退回"导航目标 host"。没有 `login.url` 也没有 `owns` 的账号,
  其 host 归属要靠导航目标 —— 这是降级路径,已在代码注释里写明。
- **不注入 `Authorization` 之外的其它凭据来源**:会话 header 里有什么就注入什么(通常是 `Cookie`)。
- **没有做"以身份渲染后再自动 compare"** 的联动;越权判定仍靠现有的 `compare` 链,浏览器侧只补证据。
- **SPA 的浏览器表单**放在账号面板里(与身份列表同屏),没有单独的"浏览器任务"页。
