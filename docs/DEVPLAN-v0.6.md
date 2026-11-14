# DEVPLAN-v0.6:登录态浏览器(CDP 注入会话,且不破坏唯一发包通道)

> 交付对象:实现者(DeepSeek)。配 ADR-004、DEVPLAN-v0.2(模块二 CDP 闸)、IMPL-STATUS-v0.3、E2E-RESULT-v0.5 读。
> 目标:让 `browser` 能力带**已登录会话**渲染页面(登录态 SPA / DOM / 越权视图),补上路线图里 CDP 的明确缺口 ——
> 现在只能匿名渲染,`session` 参数没接到 CDP。**前提红线:注入会话绝不打开第二条发包路径。**

## 0. 现状与缺口

- `internal/web/browser.go`:CDP 渲染 + `Fetch.enable(*)` 逐请求过 `discipline.Guard.Authorize`,`setAutoAttach` 失败即
  fail-closed。但它**只做匿名渲染** —— `session` 参数未实现,跑不了需要登录态的页面(登录后 SPA、越权对象页、带认证的 XHR)。
- 账号层 `accounts.SessionStore.Load(name)` 返回**解密后的 `Headers`**(含 `Cookie`),每身份一份,加密存储。注入要从这里取,**不新建凭据来源**。

## 0.5 不可动摇(本轮红线,逐条适用)

- **唯一发包通道不破**:注入会话后,页内每个请求**仍全部经 `Fetch.requestPaused → Guard.Authorize`**;
  会话 header 只在 Guard **放行之后**由拦截器加到该请求上,**不通过 `Network.setCookie` 让浏览器自带 cookie 自由发包**
  (那等于把认证流量放出 Guard 之外)。注入 header 的动作发生在闸内,不是闸外。
- **cookie 作用域收紧**:注入的会话 header 只加到 **scope 内、且与会话归属 host 匹配**的请求;跨 host 的请求即使在 scope 内,
  也**不带**该会话 cookie(防止把 A 站 cookie 漏给 B 站)。
- **会话值零泄漏**:cookie/header 值不进账本、不进审计 detail、不进报告、不进日志、不进截图旁注;审计只记"注入了会话 `<name>`"这一事实,不记值。
- **仍 fail-closed**:`setAutoAttach` 失败照旧拒绝渲染;会话加载失败(名不存在/未就绪/解密失败)→ 能力报错,不退化成匿名偷偷跑。
- **档位不变**:`browser` 仍是档 1(只读渲染)。登录态只读浏览**不自动触发**任何写方法;若页面脚本发起写请求,仍受 scope `methods` 限制,越界即 `failRequest`。

## 1. 会话接入 `internal/web/browser.go` + `internal/runtime`(P0)

**目标**:`browser` 接受 `session` 参数(会话名),从账号层取解密 header,在**闸内**注入。

**派发接线(runtime)**:和其它能力一样,`session` 名在派发时由 `runtime` 解析成 header(复用现有 "会话名→headers" 解析,见 compare/worker 的做法),**解析出的 header 不进意图、不进图**,只作为运行期参数传给 browser 能力。浏览器能力拿到的是 `sessionHeaders map[string]string` + `sessionName string`(名用于审计记录,header 用于注入)。

**注入点(关键,在 Fetch 闸内)**:改 `installFetchGate` 的放行分支 ——
```
Fetch.requestPaused → Guard.Authorize(通过)
  → 若 sessionHeaders 非空 且 请求 host == 会话归属 host 且 in-scope
      → Fetch.continueRequest 时带上 headers(把会话 header 合并进该请求头)
  → 否则 continueRequest 不加会话 header
```
即**用 `Fetch.continueRequest` 的 `headers` 覆盖参数注入**,而不是 `Network.setCookie` 预置全局 cookie。这样:① 每个被注入的请求都是先过 Guard 才被放行;② 注入严格逐请求、按 host 收敛;③ 没有"浏览器自带 cookie 自行发包"的闸外路径。

**会话归属 host**:从会话对应账号的 `login.url` / `owns.url` 推导(账号层已有归属信息),或退一步用"首个导航目标的 host"。跨 host 不注入。

**验收**:带 `session=alice` 渲染 `/orders/1` → 请求头含 alice 的 Cookie、页面拿到 `ORD-1 owned by alice`;同一会话渲染一个**跨 host**(仍在 scope)的目标 → 该请求**不带** alice cookie;会话名不存在 → 能力报错不渲染;审计行只记 `session=alice` 不记 cookie 值。

## 2. 登录态证据产出(P1)

**目标**:登录态渲染的观察,归一成 fact/finding,仍带 request_id,且不漏会话值。

- 渲染结果里新增 `authenticated: true` + `session: "<name>"`(仅名),fact 里体现"以身份 alice 渲染 /orders/1 → 200 可见 ORD-1"。
- 越权视角:带 `session=bob` 渲染 alice 的对象 URL,若可见 → `bola` 候选(与现有 compare 链一致,浏览器侧作为补充证据,仍 candidate,不自动 verified)。
- 截图落 artifact 目录,**截图不含 cookie 旁注**;finding evidence 只到 request_id + 截图路径。

**验收**:登录态 finding 带 request_id 与 session 名;截图与账本都无 cookie 值;bob 看 alice 对象可见 → candidate(非 verified)。

## 3. SPA 接线 `web/app.js`(P2)

- browser 能力的参数表单加"以会话渲染"下拉(列 `accounts_show` 回的 session 名,**不回 cookie**)。
- 证据面板展示登录态 finding 的 `session` 名与 `authenticated` 标记。

**验收**:下拉只列会话名;选 alice 渲染后 finding 显示 `session=alice`;界面任何位置无 cookie/密码。

## 4. 文档与验收

- README「浏览器」段补:登录态注入在 Fetch 闸内逐请求进行、按 host 收敛、cookie 不经 `Network.setCookie`、会话值零泄漏。
- `scripts/acceptance-v02.ps1` 增断言:`session=alice` 渲染 `/orders/1` 拿到 `ORD-1`;跨 host 不带 cookie;审计无 cookie 值;`TestNoEgressOutsideTheGuard` 仍过(注入不得引入新出口)。
- 靶场 `lab-target.py` 如需:`/orders/1` 已按 cookie 区分 alice/非 alice,够用;必要时加一个需登录态的 SPA 页。

## 落地顺序

1. 模块一(会话在 Fetch 闸内注入 + 按 host 收敛)—— 红线所在,先立住。
2. 模块二(登录态证据产出)。
3. 模块三(SPA 下拉)、模块四(文档 + 验收)。

**每步验收锚点**:注入请求仍逐个过 Guard(`TestNoEgressOutsideTheGuard` + 新测);cookie 零泄漏(账本/审计/截图/日志);跨 host 不带 cookie;会话加载失败即 fail-closed;browser 仍档 1、写方法仍受 scope 限;同账本渲染证据可复现。

## 一句话

让 youkai 能"以某个已授权身份去看"页面,但"看"这件事的每一个请求照样走纪律脊柱 ——
登录态是多给了一把钥匙,不是多开了一扇后门。
