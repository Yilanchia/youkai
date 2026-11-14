# IMPL-STATUS v0.9 — 检测覆盖深化(API 文档 / GraphQL / JWT / OAuth)

> 日期:2026-11-14 · 承接 DEVPLAN-v0.9 · `go test ./...` 全绿 · `scripts/acceptance-v02.ps1` 全通过
> 新增:`internal/web/{apispec,graphql,jwt,oauth}.go`、引擎的两条派生规则、靶场的
> `/openapi.json` `/graphql` `/jwt-cookie` `/authorize` `/.well-known/openid-configuration`。

## 一句话

把授权越权引擎从"只能测爬到的端点"升级成"能测整份文档化 API",同时补上 JWT / OAuth 的
只读配置审计 —— **覆盖变宽,纪律不变**:仍是只读、只判存在、停在影响成立。

## 一 · API 文档接入 `api_spec`(档 1)

- 经 guard 拉一份 OpenAPI 2/3(**JSON 或 YAML**;YAML 先转 JSON,只保留一条解码路径)。
- 把 `paths × methods` 登记成端点资产 + 事实,标注:需认证、含路径参数(需样本 id)、
  写方法(`tier-hint=proof`,自治不碰)。
- **spec 是数据不是指令**:不执行、不跟随外部 `$ref`(只记"未解析"),解析出的每个 URL
  **重新过 scope**,越界的只记事实"超出 scope 不登记",不进入可测面。
- 上限:4 MiB / 500 个操作,超出即截断并说明。
- **不验证端点**:登记完就停,后续由 scan / role_matrix 决定碰什么。

## 二 · GraphQL 自省 `graphql_introspect`(档 1)

- 只发**一条**常量 introspection 查询(POST,所以护照的方法集里必须有 POST)。
- 登记 root query / mutation 字段;mutation 标 `write` + `tier-hint=proof`;非 root 类型不登记。
- introspection 关闭 / 报错 / 空 → 如实记"不可用",不猜 schema。
- 实测:靶场 `Query.order` / `Mutation.deleteOrder` 入账,introspection 开放出 info 候选。

## 三 · JWT 结构审计 `jwt_audit`(档 1,纯本机)

- token 从**已解析的会话 header** 里取(Cookie / Authorization),不作为参数传入,也不输出。
- 检查:alg=none(high)、对称算法(low)、缺 exp(medium)、有效期 >30 天(low)、
  敏感 claim **名**(low,只记名字)、kid(info)、jku/x5u(medium)。
- **没有签名代码可调**:不爆破、不做 alg 混淆、不改签。弱密钥只写"需人工验证"。
- 需要一个**请求锚点**(审计行):给 `url` 就发一次只读 GET(带该会话),或给 `request_id`。
  没有锚点就报错,不产出一条无法复核的发现。
- 实测:靶场登录同时下发一个 `alg=none`、无 `exp`、含 `role` claim 的弱 JWT,
  alice 的会话因此可审;token 原文从未进入账本。

## 四 · OAuth 配置审计 `oauth_audit`(档 1)

- 读 `/.well-known/openid-configuration`,登记 authorization/token/jwks 端点;
  未声明 PKCE 支持 → low 候选。
- 给 `authorize_url` 时审一次:缺 `state`(medium)、`response_type=code` 缺 `code_challenge`(low)。
- `redirect_uri` **一次**只读观察:追加一段路径再请求一次,若被接受 → medium 候选。
  **不完成授权码交换、不换 token、不跟随授权重定向**(有测试钉住:回调端点从未被访问)。

## 五 · 接回引擎

- `ruleAPISpec`:对每个 host 试一次 `<base>/openapi.json`(成本是一个 404),接入后整份文档进入账本;
  v0.7 的 trace 守卫保证不会重复试。
- `ruleDocSurfaceMatrix`:存在 `source=openapi` 事实且**至少两个身份就绪**时,派 `role_matrix`
  对这些端点做只读矩阵 —— 这就是"文档化 API × 多身份"的越权扫描。

## 验收

新增 12 个单元测试(`internal/web/coverage_test.go`):

```
TestAPISpecRegistersTheDocumentedSurface / MarksOutOfScopeEndpoints / AcceptsYAML /
TreatsTheDocumentAsData(坏 JSON / 循环 $ref / 外部 $ref:不崩、只发一次请求)
TestGraphQLIntrospectionRegistersFields / DisabledDegradesHonestly
TestJWTAuditFindsConfigRisksWithoutTheToken / NeedsAnAnchor / UsesOneReadOnlyRequestWhenGivenAURL /
IgnoresANonJWTSession
TestOAuthAuditFlagsMissingStateAndPkce / DoesNotFollowTheRedirect
```

验收脚本新增 18 条,全过:

```
ok  api_spec / graphql_introspect / jwt_audit / oauth_audit is registered
ok  *_is classified tier 1
ok  the OpenAPI document was parsed
ok  documented endpoints were registered as assets
ok  GraphQL mutations were registered and labelled / queries were registered
ok  OAuth configuration findings were produced / missing state / loose redirect_uri
ok  the JWT audit produced findings / alg=none / exp / findings are candidates
ok  the token itself never reached the ledger
```

基准(`bench`):ground truth 加了 `api-doc`,recall 1.000(8/8)、precision 1.000、
19 次请求、越界 0、每发现 2.38 次请求。

## 顺带修掉两个真 bug

1. **`assets.props` 被写成 JSON 数组**。`upsertAsset` 对 nil props 会 `json.Marshal(nil)` → `null`,
   而合并语句是 `assets.props || EXCLUDED.props`;PostgreSQL 里 `'null'::jsonb || {...}` 产生**数组**,
   于是"先无 props 创建、后有 props 更新"的资产全部变成 `[{...}, null, null]`,
   `a.Props["base"]` 读不到 —— 新加的 `api_spec` 规则因此一条都派不出来。
   修法:永远写 `{}` 而不是 `null`,并让合并只在左侧是对象时才做。
2. **旧的 youkaid 二进制**导致第一次验证把新能力判成 `unknown capability → tier3`:先 `go build -o`
   再验,别用上一次的进程。

## 与 DEVPLAN-v0.9 的差异 / 未做

- **OpenAPI 只解析 `paths` 与 `security`**;requestBody schema、parameters 的详细定义没有进账本。
- **没有自动跨外部 `$ref` 拼接**:外部引用只记"未解析",不递归(这是刻意的,见红线)。
- **`jwt_audit` 需要锚点**:没有 `url`/`request_id` 就报错。这是四样证据规则的结果,不是遗漏。
- **`graphql_introspect` 需要护照允许 POST**:GraphQL 就是这样工作的;scope 不允许时能力会被 guard 拒绝。
- **OAuth 的 `redirect_uri` 观察只看"是否被接受"**,不判定 OAuth 流程本身;正式利用需人工。
- **bench 不覆盖这四项**:它们要么需要会话(JWT)、要么需要显式的 authorize_url(OAuth),
  不在自治只读链里;验收脚本覆盖它们。
