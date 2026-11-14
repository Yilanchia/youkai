# DEVPLAN-v0.9:检测覆盖深化 — API schema 接入 + JWT/OAuth 配置审计

> 交付对象:实现者(DeepSeek)。配 ADR-004、DEVPLAN-v0.2(web 能力)、v0.7(trace)、COMPETITIVE 读。
> 目标:补 youkai 当前最弱、也最贴合"授权只读取证"的两块检测覆盖 —— **API schema 接入**(把文档化端点面喂给
> 权限矩阵/BOLA 引擎)和 **JWT/OAuth 配置审计**(只读、只判存在)。两块都在纪律闸内,不加任何利用。

## 0. 为什么是这两块

- COMPETITIVE 自列真实差距:API schema/GraphQL、JWT/OAuth 不完整。youkai 的皇冠是**授权/越权检测**
  (账号层 + role_matrix + compare + BOLA),但它现在只能对**爬到的**端点做矩阵。
- **API schema 接入是放大器**:一份 OpenAPI/Swagger 或 GraphQL introspection 就是整个文档化端点面。喂进账本后,
  role_matrix/compare 立刻能对**全量文档端点 × 多身份**做只读越权扫描(OWASP API #1 BOLA / #5 BFLA)—— 这正是
  youkai 授权纪律最出彩、商业 DAST 最容易做脏(乱发请求)的地方。
- **JWT/OAuth 审计**是高价值、近乎零风险的只读检查器:alg=none、缺 exp、敏感 claim、redirect_uri 宽松、缺 state/PKCE。

## 0.5 不可动摇(继承,逐条适用)

- 全部经 `discipline.Guard`;schema 拉取与 introspection 都是**只读 GET/标准查询**,在 scope 内;越界即阻断记审计。
- **只判存在、不利用**:JWT 只读结构标风险,**绝不爆破密钥、不伪造令牌**(弱密钥只"疑似"并建议人工);
  GraphQL introspection 只读 schema,**不批量抽数据**;发现的端点进账本当**候选**,越权判定仍走现有 compare/role_matrix(停在影响成立)。
- schema 里的端点若需主动请求验证,**档位照旧**:只读 GET 是档 1;任何写方法/参数探测是档 2,停在人前。
- 不喂凭据/正文进账本;JWT 的 payload 只记非敏感元数据(alg/typ/有无 exp/claim 名),**不记 claim 值、不记 signature**。
- schema 内容是**目标可控数据**:解析要防注入(当数据不当指令),解析出的 URL 仍逐个过 scope 校验,不因"schema 里写了"就放行越界。

## 1. OpenAPI / Swagger 接入 `internal/web/apispec.go`(P0,先做,放大器)

**目标**:拉取并解析 OpenAPI 2/3(JSON/YAML)或 Swagger,把路径+方法+参数登记成账本资产/端点,驱动后续矩阵。

**能力**:`api_spec`(档 1)—— 参数 `url`(spec 地址)或 `path`(本地)。经 Guard 拉取(只读 GET),解析出 `paths × methods × params`,
每个端点落 `asset(type=endpoint)` + fact,标注来源 `source=openapi`、认证要求(securitySchemes)。

**实现要点**:
- 解析器把 spec **当纯数据**:不执行、不跟随外部 `$ref` 到别的 host(外部 ref 只记"未解析"不拉取)。
- 解析出的每个端点 URL 用现有 scope 校验归一;**越界端点不登记为可测目标**,只记"spec 声明了但超出 scope"。
- 只登记**只读 GET** 端点为自治可探;含路径参数的端点生成"需要样本 id"的提示(交给账号层 seed 或人工)。
- 不自动发请求验证每个端点(那是 crawl/role_matrix 的事);`api_spec` 只做"把面铺开"。

**接 role_matrix/BOLA**:登记后,`role_matrix` 能对这些端点 × 账号清单做只读 GET 矩阵;带 `owns` 归属的生成 compare 配对。
引擎派生规则加一条:见到 `source=openapi` 的 GET 端点 + ≥2 身份 → 派 role_matrix(档 1)。

**验收**:喂一个 OpenAPI 3 JSON → 端点入账、带方法/认证标注;spec 里一个越界 host 的端点被标"超 scope 不可测";
登记后 role_matrix 能覆盖这些端点;解析恶意 spec(超大/循环 ref)不崩、不发外部请求。

## 2. GraphQL introspection `internal/web/graphql.go`(P0)

**目标**:对 GraphQL 端点发**标准 introspection 查询**(只读),拿到 schema,登记 query/mutation 字段,标注哪些是 mutation(写)。

**能力**:`graphql_introspect`(档 1)—— 参数 `url`(GraphQL 端点)。经 Guard POST 标准 introspection query(只读语义),
解析 types/queries/mutations,登记为端点资产。

**实现要点**:
- 只发 introspection 那一个查询;**不自动跑任何 query/mutation 抽数据**。
- introspection 关闭(403/空)→ 如实记"introspection 不可用",不猜 schema。
- mutation 字段标 `tier-hint=write`:自治不碰,列为"需人工/档 2"。
- query 字段可进 role_matrix 式越权对照(两身份查同一对象),仍 candidate。

**验收**:对开放 introspection 的靶场 GraphQL → 拿到字段清单、mutation 标写;introspection 关闭时如实降级;
全程不发 introspection 之外的查询。

## 3. JWT 配置审计 `internal/web/jwt.go`(P1,只读检查器)

**目标**:对发现的 JWT(来自登录响应/Cookie/Authorization,**由账号层会话提供,不新拉**)做**只读结构审计**,标风险,绝不破解/伪造。

**检查项(只读,判存在)**:
- `alg=none` 或可疑弱 alg → high 候选。
- 缺 `exp` / exp 过长 → medium。
- 敏感 claim 名出现(role/admin/is_admin 等,**只记 claim 名不记值**)→ 提示。
- `kid` 注入面、`jku`/`x5u` 外链 → 记风险点(不验证不利用)。

**红线**:**不爆破 HMAC 密钥、不尝试 alg 混淆伪造、不改签**。弱密钥只能"疑似、建议人工验证",不代跑。
JWT 值本身不入账本,只记解码出的非敏感元数据。

**验收**:构造 alg=none / 无 exp / 含 admin claim 的 JWT → 各出对应候选;JWT 原文与 signature 不进账本;无破解行为。

## 4. OAuth 流程配置审计 `internal/web/oauth.go`(P1)

**目标**:对 OAuth/OIDC 授权端点做**只读配置审计**(观察重定向参数与 well-known),标配置弱点,不劫持不利用。

**检查项**:
- `/.well-known/openid-configuration` 只读拉取,记端点与支持的 flow。
- 授权请求缺 `state` / 缺 PKCE(code_challenge)→ 候选。
- `redirect_uri` 校验宽松(可加子路径/可换 host)→ **只做一次只读观察**(改 redirect_uri 发一次 GET 看是否被接受),命中即 candidate,**不完成授权、不换 token、不劫持**。

**红线**:不走完授权码交换、不拿 access_token、不回放他人 code。redirect_uri 测试是单次只读观察,停在"配置疑似宽松"。

**验收**:缺 state/PKCE 命中候选;well-known 端点入账;redirect_uri 观察只发一次、不换 token。

## 5. SPA + 报告 + 文档(P2)

- 能力表单加 `api_spec`/`graphql_introspect`/`jwt_audit`/`oauth_audit`;证据面板显示来源(openapi/graphql)与端点覆盖。
- 报告/SARIF 纳入这些 candidate(仍 candidate,四样证据齐)。
- README「能力清单」+ bench ground truth 扩入:靶场加一个 OpenAPI spec、一个 GraphQL introspection、一个弱 JWT、一个缺 state 的 OAuth 端点。

**验收**:SARIF/报告含新发现且分级正确(多为 candidate);bench 对新类目算 recall/precision、越界仍 0。

## 落地顺序

1. 模块一(OpenAPI 接入)—— 放大器,先做,立刻增强 role_matrix/BOLA。
2. 模块二(GraphQL introspection)。
3. 模块三(JWT 审计)、模块四(OAuth 审计)。
4. 模块五(SPA + 报告 + bench ground truth)。

**每步验收锚点**:schema/introspection 只读、当数据不当指令、解析出的 URL 仍过 scope;JWT 不破解不伪造、原文不入账;
OAuth 不换 token;新端点进账本为 candidate、越权判定仍走 compare/role_matrix 停在影响成立;越界请求=0;`go test ./...` 全绿。

## 一句话

把 youkai 的授权越权引擎从"只能测爬到的端点"升级成"能测整份文档化 API" ——
覆盖变宽,纪律不变:仍是只读、只判存在、停在影响成立,archived 的每一发都解释得清。
