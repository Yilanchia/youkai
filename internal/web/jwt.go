package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// JWT configuration audit: read the token's structure, and nothing else.
//
// What this capability will never do, by construction:
//   - crack or guess an HMAC key (no signing code, no dictionaries);
//   - attempt algorithm confusion (alg=none / RS256->HS256) to forge a token;
//   - modify and re-sign anything.
//
// What it does is decode the two public segments and report what a human should
// look at: a missing exp, an "none" algorithm, a sensitive claim NAME, a rotatable
// key id. That is a configuration audit, not an attack.
//
// The token itself is never an argument and never an output: the value is taken from
// the resolved session's headers at dispatch time and only the derived metadata
// leaves this function.

// sensitiveClaimNames are claim names whose presence changes authorisation. Only the
// NAME is reported; the value never leaves this function.
var sensitiveClaimNames = map[string]bool{
	"role": true, "roles": true, "admin": true, "is_admin": true, "isadmin": true,
	"scope": true, "scopes": true, "permissions": true, "perms": true,
	"tenant": true, "tenant_id": true, "org": true, "org_id": true,
	"user_id": true, "uid": true, "sub": true, "groups": true,
}

func runJWTAudit(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	session := strings.TrimSpace(argString(args, "session"))
	if session == "" {
		return ledger.Observation{}, fmt.Errorf(`web: jwt_audit: 需要 "session"(会话名;token 从该会话的 header 里取)`)
	}
	if env.SessionName == "" || env.SessionName != session {
		return ledger.Observation{}, fmt.Errorf("web: jwt_audit: 会话 %q 未被 dispatcher 解析", session)
	}

	token, headerName := findJWT(env.SessionHeaders)
	if token == "" {
		// Say what we looked at and what we found, without echoing values.
		names := make([]string, 0, len(env.SessionHeaders))
		for k := range env.SessionHeaders {
			names = append(names, k)
		}
		sort.Strings(names)
		return ledger.Observation{}, fmt.Errorf(
			"web: jwt_audit: 会话 %q 里没有找到 JWT(检查过的 header:%s)",
			session, strings.Join(names, ","))
	}

	// The audit needs an anchor in the audit log. Either the caller already has one
	// (the login that produced the token), or it asks youkai to use the token once,
	// read-only, so the finding can be reproduced later.
	var (
		reqID  string
		anchor string
	)
	if v := strings.TrimSpace(argString(args, "request_id")); v != "" {
		reqID, anchor = v, "caller-supplied"
	} else if rawURL := strings.TrimSpace(argString(args, "url")); rawURL != "" {
		res, err := do(ctx, env, discipline.Request{
			Method: "GET", URL: rawURL, Purpose: "jwt_audit",
			Headers: env.SessionHeaders, FollowRedirects: false,
		})
		if err != nil {
			return ledger.Observation{}, fmt.Errorf("web: jwt_audit: %w", err)
		}
		reqID, anchor = res.RequestID, "session GET"
	} else {
		return ledger.Observation{}, fmt.Errorf(
			`web: jwt_audit: 需要一个请求锚点 —— 给 "url"(用该会话发一次只读 GET),或给 "request_id"(已有的审计行)`)
	}

	b := newObs()
	b.requestID(reqID)
	ev := map[string]any{"request_id": reqID, "session": session, "header": headerName, "anchor": anchor}

	meta, findings := auditJWT(token)
	b.fact(fmt.Sprintf("JWT 结构:alg=%s typ=%s claims=%d exp=%s",
		meta.Alg, meta.Typ, len(meta.ClaimNames), meta.ExpState),
		ev, "jwt", "structure")
	b.fact("JWT 敏感 claim 名:"+strings.Join(meta.SensitiveClaims, ","),
		ev, "jwt", "claims")

	for _, f := range findings {
		b.finding(ledger.FindingSeed{
			Title:    f.Title,
			Severity: f.Severity,
			Kind:     "jwt",
			Where:    "header:" + headerName,
			Detail:   f.Detail,
			Counter:  f.Counter,
			Evidence: ev,
			Tags:     []string{"jwt", "config"},
			Anchors:  []string{"surface:" + headerName},
		})
	}
	b.setSummary(fmt.Sprintf("jwt_audit: alg=%s exp=%s 风险 %d 项", meta.Alg, meta.ExpState, len(findings)))
	return b.obs, nil
}

// jwtMeta is everything we are willing to say about a token.
type jwtMeta struct {
	Alg             string
	Typ             string
	ClaimNames      []string
	SensitiveClaims []string
	ExpState        string
	Kid             bool
	ExternalKey     string
}

type jwtFinding struct {
	Title, Severity, Detail, Counter string
}

// auditJWT decodes and grades. Pure: no network, no crypto, no state.
func auditJWT(token string) (jwtMeta, []jwtFinding) {
	meta := jwtMeta{ExpState: "无 exp"}
	var out []jwtFinding
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtMeta{ExpState: "结构异常"}, []jwtFinding{{
			Title: "JWT 结构异常", Severity: "low",
			Detail:  fmt.Sprintf("token 不是三段式(%d 段),可能不是 JWT 或被截断。", len(parts)),
			Counter: "可能只是另一种 bearer token;需人工确认。",
		}}
	}
	head, err1 := decodeJWTJSON(parts[0])
	claims, err2 := decodeJWTJSON(parts[1])
	if err1 != nil || err2 != nil {
		return jwtMeta{ExpState: "无法解析"}, []jwtFinding{{
			Title: "JWT 无法解码", Severity: "low",
			Detail:  "header/payload 不是合法的 base64url JSON。",
			Counter: "可能使用了 JWE(加密)或非标准编码,本检查只处理 JWS。",
		}}
	}
	meta.Alg, _ = head["alg"].(string)
	meta.Typ, _ = head["typ"].(string)
	if meta.Alg == "" {
		meta.Alg = "(缺失)"
	}
	_, meta.Kid = head["kid"]
	if v, ok := head["jku"].(string); ok && v != "" {
		meta.ExternalKey = "jku=" + v
	}
	if v, ok := head["x5u"].(string); ok && v != "" {
		meta.ExternalKey = "x5u=" + v
	}

	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, k)
	}
	sort.Strings(names)
	meta.ClaimNames = names
	for _, n := range names {
		if sensitiveClaimNames[strings.ToLower(n)] {
			meta.SensitiveClaims = append(meta.SensitiveClaims, n)
		}
	}

	switch strings.ToLower(meta.Alg) {
	case "none":
		meta.ExpState = expStateOf(claims, &meta)
		out = append(out, jwtFinding{
			Title: "JWT 使用 alg=none", Severity: "high",
			Detail:  "令牌声明不签名(alg=none)。若服务端接受它,任何人在不改动载荷的情况下都能伪造身份。",
			Counter: "服务端通常会在库层面拒绝 none;需人工用该令牌请求一次受保护接口来确认是否被接受(本检查不做)。",
		})
	case "hs256", "hs384", "hs512":
		out = append(out, jwtFinding{
			Title: "JWT 使用对称算法(" + strings.ToUpper(meta.Alg) + ")", Severity: "low",
			Detail:  "对称签名意味着验证方与签发方共享同一密钥;密钥强度无法从令牌判断。",
			Counter: "对称算法本身不是漏洞;弱密钥只能由人工用字典验证。本检查**不爆破、不伪造**。",
		})
	}
	if meta.ExpState == "无 exp" {
		out = append(out, jwtFinding{
			Title: "JWT 缺少 exp(永不过期)", Severity: "medium",
			Detail:  "令牌没有过期时间:一旦泄露,在被吊销前长期有效。",
			Counter: "吊销可能由服务端会话状态实现;需确认是否存在服务端失效机制。",
		})
	}
	if meta.ExpState == "超长有效期" {
		out = append(out, jwtFinding{
			Title: "JWT 有效期过长", Severity: "low",
			Detail:  "exp 距今超过 30 天,泄露窗口偏长。",
			Counter: "长期令牌可能是内部服务的既定设计;需与业务确认。",
		})
	}
	if len(meta.SensitiveClaims) > 0 {
		out = append(out, jwtFinding{
			Title: "JWT 携带敏感授权 claim", Severity: "low",
			Detail: "令牌载荷里出现授权相关 claim 名:" + strings.Join(meta.SensitiveClaims, ",") +
				"(只记录名字,不记录值)。",
			Counter: "JWT 载荷是明文可读的;若这些值用于授权,任何持令牌者都能看到自己的权限结构,但不等于能提权。",
		})
	}
	if meta.Kid {
		out = append(out, jwtFinding{
			Title: "JWT 头包含 kid", Severity: "info",
			Detail:  "kid 若被用于拼接密钥路径/查询,历史上出现过注入与路径穿越;本检查只记录存在。",
			Counter: "kid 是标准字段;需人工确认服务端如何使用它。",
		})
	}
	if meta.ExternalKey != "" {
		out = append(out, jwtFinding{
			Title: "JWT 头引用外部密钥(" + strings.SplitN(meta.ExternalKey, "=", 2)[0] + ")", Severity: "medium",
			Detail:  "头里出现外部密钥地址,若服务端无条件信任,可导致密钥来源被替换。",
			Counter: "规范允许 jku/x5u;需确认服务端是否白名单校验该地址(本检查不拉取、不利用)。",
		})
	}
	return meta, out
}

func expStateOf(claims map[string]any, meta *jwtMeta) string {
	raw, ok := claims["exp"]
	if !ok {
		return "无 exp"
	}
	// JSON numbers decode as float64.
	f, ok := raw.(float64)
	if !ok {
		return "exp 非法"
	}
	exp := time.Unix(int64(f), 0).UTC()
	if exp.Before(time.Now()) {
		return "已过期"
	}
	if time.Until(exp) > 30*24*time.Hour {
		return "超长有效期"
	}
	return "有效(" + exp.Format("2006-01-02") + ")"
}

// findJWT looks for a three-segment base64url token in the session headers.
//
// It returns the token and the header name it came from. Candidate values are
// checked by shape only; nothing is logged.
func findJWT(headers map[string]string) (string, string) {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		value := headers[name]
		if strings.EqualFold(name, "Authorization") {
			if tok := jwtLike(strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))); tok != "" {
				return tok, name
			}
		}
		if strings.EqualFold(name, "Cookie") {
			for _, part := range strings.Split(value, ";") {
				_, v, ok := strings.Cut(strings.TrimSpace(part), "=")
				if !ok {
					continue
				}
				if tok := jwtLike(v); tok != "" {
					return tok, name
				}
			}
		}
		if tok := jwtLike(value); tok != "" {
			return tok, name
		}
	}
	for _, name := range names {
		for _, field := range strings.Fields(headers[name]) {
			if tok := jwtLike(strings.Trim(field, `",;`)); tok != "" {
				return tok, name
			}
		}
	}
	return "", ""
}

// jwtLike accepts only what looks like a JWS: three base64url segments, and a
// header segment that decodes to JSON with an "alg".
//
// The signature segment may be EMPTY: that is exactly what an unsigned token
// (alg=none) looks like, and it is one of the cases this audit exists to catch.
func jwtLike(v string) string {
	v = strings.TrimSpace(strings.Trim(v, `"',;`))
	parts := strings.Split(v, ".")
	if len(parts) != 3 || len(parts[0]) < 8 || parts[1] == "" {
		return ""
	}
	head, err := decodeJWTJSON(parts[0])
	if err != nil {
		return ""
	}
	if parts[2] == "" {
		alg, _ := head["alg"].(string)
		if !strings.EqualFold(alg, "none") {
			return ""
		}
	}
	return v
}

func decodeJWTJSON(seg string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

var _ = url.Parse
