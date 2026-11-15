# DEVPLAN-v0.15:web 宽度续 — 认证/会话类漏洞(JWT 深度 / OAuth 流程 / 会话固定 / 注入变体)

> 交付对象:实现者(DeepSeek)。配 DEVPLAN-v0.9(已有 jwt_audit/oauth_audit 雏形)、v0.14(探针框架)、ADR-006 读。
> 目标:把认证/会话这条线做深(youkai 的皇冠是越权,认证弱点是它的上游),并补几类注入变体。仍只判存在、过 Guard、风险停人前。

## 0.5 不可动摇(继承)

- 只判存在/配置弱点,不劫持会话、不爆破、不伪造令牌、不完成授权流换 token(延续 v0.9 jwt/oauth 红线)。
- 全过 Guard;主动类档 2 停人前(ADR-006);candidate≠verified;凭据/令牌值不入账本。

## 1. JWT 深度(在 v0.9 jwt_audit 之上)P1

- 已有:alg=none / 缺 exp / 敏感 claim 名 / jku-x5u 外链。
- 补(只读判定,不伪造):`kid` 路径穿越/SQL 注入面标注、`exp`/`nbf`/`iat` 逻辑一致性、对称/非对称混用风险(RS256 公钥当 HS256 密钥的**配置**风险,只标不验证伪造)、刷新令牌是否轮换(观察多次登录,不爆破)。
- 弱 HMAC 密钥:**只标"疑似弱配置、建议人工验证",绝不跑字典/爆破**。

**验收**:各风险出对应 candidate;令牌值不入账;无任何伪造/爆破行为。

## 2. OAuth/OIDC 流程(在 v0.9 oauth_audit 之上)P1

- 已有:well-known、缺 state、缺 PKCE、redirect_uri 单次只读观察。
- 补(只读观察):`response_type`/`response_mode` 风险组合、隐式流残留、scope 过宽、redirect_uri 更多绕过形状**只观察一次是否被接受**(不完成换 token)、state 熵弱标注。
- 红线重申:**不走完授权码交换、不拿 access_token、不回放他人 code**。

**验收**:缺陷配置出 candidate;绝不换 token;redirect_uri 观察单次只读。

## 3. 会话管理 `internal/web/session_probe.go` P1

- **会话固定**:登录前后会话标识是否轮换(用账号层会话,观察 Set-Cookie 变化,不劫持)。
- **Cookie 安全属性**:HttpOnly/Secure/SameSite 缺失(已有部分,归并强化)。
- **会话失效**:登出后旧会话是否仍有效(单次只读复验,用自己的测试账号)。
- **可预测会话标识**:多次登录的标识是否低熵/可预测(只统计熵,不预测利用)。

**验收**:靶场命中会话固定/登出不失效各一条候选;只用测试账号;不劫持、不预测利用。

## 4. 注入变体补充 P2

- NoSQL 注入(存在性:MongoDB `$ne`/`$gt` 操作符差分,只判存在)、LDAP 注入标注、Header 注入/CRLF(只判反射到响应头的存在性)、SSTI 多引擎指纹(已有 `{{7*7}}`,补 `${}`/`#{}` 等变体)。
- 全部只判存在,接入 v0.14 探针框架与白盒假设映射。

**验收**:NoSQL/CRLF 各命中一条候选;正常参数零误报;接入假设映射。

## 5. 报告/SARIF/bench P2

- 新类纳入四样证据、SARIF、bench ground truth(lab-target.py 增认证/会话弱点端点)。

## 落地顺序:1 JWT 深度 → 2 OAuth → 3 会话管理 → 4 注入变体 → 5 报告/bench。

**验收锚点**:只判存在/配置,不劫持/爆破/伪造/换 token;令牌值不入账;档 2 停人前;candidate≠verified;越界=0;`go test ./...` 全绿。

## 一句话

认证是越权的上游:把 JWT/OAuth/会话的弱配置看清楚,youkai 的越权判定才有根 —— 仍是只看不碰,拿数据和劫持永不做。
