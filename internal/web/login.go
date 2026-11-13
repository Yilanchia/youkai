package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Login is a single, explicit write.
//
// One attempt, one audited request, no retry and no dictionary: youkai is not a
// credential-guessing tool. The observation never contains a credential - field
// values are never copied anywhere, and the guard already redacts the cookie
// values - so the only login artefact that leaves this function is the set of
// cookie names and whether a session appeared.

func runLogin(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	session := argString(args, "session")
	if session == "" {
		return ledger.Observation{}, fmt.Errorf("web: login: 需要 session 名(如 alice / bob)")
	}
	fields := argStringMap(args, "fields")
	if len(fields) == 0 {
		return ledger.Observation{}, fmt.Errorf("web: login: fields 不能为空(至少需要一个表单字段)")
	}

	g, err := guardOf(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	scope := g.Scope()
	// A login changes server state, so it is only allowed when the passport
	// explicitly authorised a write method.
	method := strings.ToUpper(argString(args, "method"))
	if method == "" {
		method = "POST"
	}
	if method != "POST" {
		return ledger.Observation{}, fmt.Errorf("web: login: 只支持 POST(%s 不是允许的登录方法)", method)
	}
	if scope == nil || !scope.MethodAllowed(method) {
		return ledger.Observation{}, fmt.Errorf(
			"web: login: scope 未授权 %s;登录是写操作,必须在 scope.methods 里显式加入 %s", method, method)
	}

	headers := cloneHeaders(argStringMap(args, "headers"))
	var body []byte
	if argBool(args, "json", false) {
		encoded, err := json.Marshal(fields)
		if err != nil {
			return ledger.Observation{}, fmt.Errorf("web: login: encode json body: %w", err)
		}
		body = encoded
		headers["Content-Type"] = "application/json"
	} else {
		form := url.Values{}
		for k, v := range fields {
			form.Set(k, v)
		}
		body = []byte(form.Encode())
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	res, err := do(ctx, env, discipline.Request{
		Method:          method,
		URL:             rawURL,
		Headers:         headers,
		Body:            body,
		Purpose:         "login",
		FollowRedirects: false,
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: login: %w", err)
	}

	cookies := cookieNames(headerGet(res.Header, "Set-Cookie"))
	redirected := res.Status >= 300 && res.Status < 400 && headerGet(res.Header, "Location") != ""
	success := redirected || len(cookies) > 0

	b := newObs()
	b.requestID(res.RequestID)
	evidence := respEvidence(res)
	evidence["session"] = session
	evidence["redirected"] = redirected
	evidence["cookie_names"] = cookies
	evidence["field_names"] = sortedKeys(fields) // names only, never values

	if success {
		b.fact(fmt.Sprintf("登录尝试成功:%s -> HTTP %d", rawURL, res.Status), evidence, "login")
	} else {
		b.fact(fmt.Sprintf("登录尝试未获得会话:%s -> HTTP %d", rawURL, res.Status), evidence, "login")
	}

	cookieSummary := "无"
	if len(cookies) > 0 {
		cookieSummary = strings.Join(cookies, ",")
	}
	b.setSummary(fmt.Sprintf("login %s session=%s -> success=%t cookies=%s",
		discipline.HostOf(rawURL), session, success, cookieSummary))
	return b.obs, nil
}
