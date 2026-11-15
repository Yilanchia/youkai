package web

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// OAuth/OIDC configuration audit: read the discovery document, inspect one
// authorisation request, stop.
//
// The line this capability will not cross:
//   - it never completes an authorisation flow (no code exchange, no token);
//   - it never replays someone else's authorisation code;
//   - its redirect_uri observation is a single read-only GET, and the finding it can
//     raise is "validation looks loose", never "account taken over".
//
// That keeps it in tier 1: everything it does is a GET that any browser could make.

func runOAuthAudit(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	authorizeURL := strings.TrimSpace(argString(args, "authorize_url"))

	b := newObs()

	// 1) discovery document, if the caller gave an issuer base rather than a full URL
	discovery := strings.TrimSpace(argString(args, "discovery"))
	if discovery == "" {
		discovery = strings.TrimRight(rawURL, "/") + "/.well-known/openid-configuration"
	}
	res, derr := do(ctx, env, discipline.Request{
		Method: "GET", URL: discovery, Purpose: "oauth_audit", FollowRedirects: true,
	})
	var cfg struct {
		Issuer                        string   `json:"issuer"`
		AuthorizationEndpoint         string   `json:"authorization_endpoint"`
		TokenEndpoint                 string   `json:"token_endpoint"`
		JWKSURI                       string   `json:"jwks_uri"`
		ResponseTypesSupported        []string `json:"response_types_supported"`
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
		ScopesSupported               []string `json:"scopes_supported"`
	}
	haveCfg := false
	if derr != nil {
		b.fact("OIDC 发现文档不可读:"+derr.Error(), map[string]any{"request_id": "", "url": discovery}, "oauth")
	} else {
		b.requestID(res.RequestID)
		ev := map[string]any{"request_id": res.RequestID, "url": discovery, "source": "oidc"}
		if json.Unmarshal(res.Body, &cfg) == nil && (cfg.Issuer != "" || cfg.AuthorizationEndpoint != "") {
			haveCfg = true
			b.fact(fmt.Sprintf("OIDC 配置:issuer=%s flows=%s", cfg.Issuer, strings.Join(cfg.ResponseTypesSupported, ",")),
				ev, "oauth", "oidc", "source=oidc")
			if len(cfg.CodeChallengeMethodsSupported) == 0 {
				b.finding(ledger.FindingSeed{
					Title:    "OIDC 未声明 PKCE 支持",
					Severity: "low",
					Kind:     "oauth",
					Where:    discovery,
					Detail:   "发现文档没有 code_challenge_methods_supported;公开客户端(SPA/移动端)缺少 PKCE 保护。",
					Counter:  "机密客户端(有 client_secret)可以不用 PKCE;需确认该 issuer 是否服务公开客户端。",
					Evidence: ev,
					Tags:     []string{"oauth", "pkce"},
					Anchors:  []string{"surface:" + discovery},
				})
			}
			// ---- v0.15 additions: flow shape and scope width -----------------

			// Implicit flow (response_type=token) is deprecated for browser clients:
			// the access token lands in the URL fragment where scripts read it.
			for _, rt := range cfg.ResponseTypesSupported {
				if strings.Contains(strings.ToLower(rt), "token") {
					b.finding(ledger.FindingSeed{
						Title:    "OIDC 仍支持隐式流(response_type 含 token)",
						Severity: "low",
						Kind:     "oauth",
						Where:    discovery,
						Detail: "发现文档声明支持 " + rt + ":令牌会出现在跳转 URL 的 fragment 里," +
							"浏览器端脚本可读。OAuth 2.1 已不再推荐。",
						Counter:  "是否真的允许由服务端决定;需人工确认该 client 是否被公开客户端使用。",
						Evidence: ev, Tags: []string{"oauth", "flow"},
						Anchors: []string{"surface:" + discovery},
					})
					break
				}
			}

			// A very wide scope surface is a configuration smell: it means one consent
			// can hand out much more than the client needs.
			if len(cfg.ScopesSupported) > 0 {
				wide := []string{"admin", "write", "offline_access", "*"}
				var hits []string
				for _, sc := range cfg.ScopesSupported {
					for _, w := range wide {
						if strings.Contains(strings.ToLower(sc), w) {
							hits = append(hits, sc)
							break
						}
					}
				}
				if len(hits) >= 2 || len(cfg.ScopesSupported) > 20 {
					b.finding(ledger.FindingSeed{
						Title:    "OIDC scope 面过宽",
						Severity: "low",
						Kind:     "oauth",
						Where:    discovery,
						Detail: fmt.Sprintf("声明了 %d 个 scope,其中高权限/敏感的有 %s;"+
							"一次同意可能授予远超所需的范围。",
							len(cfg.ScopesSupported), strings.Join(hits, ",")),
						Counter:  "scope 多不等于被滥用;需确认实际签发时是否做最小化裁剪。",
						Evidence: ev, Tags: []string{"oauth", "scope"},
						Anchors: []string{"surface:" + discovery},
					})
				}
			}

			if cfg.TokenEndpoint != "" {
				b.asset("endpoint", cfg.TokenEndpoint)
			}
			if cfg.JWKSURI != "" {
				b.asset("endpoint", cfg.JWKSURI)
			}
		} else {
			b.fact("OIDC 发现文档不是可解析的配置(HTTP "+fmt.Sprint(res.Status)+")", ev, "oauth", "oidc")
		}
	}

	// 2) one authorisation request, read-only: inspect the parameters a client sends.
	if authorizeURL == "" && haveCfg && cfg.AuthorizationEndpoint != "" {
		b.fact("发现授权端点:"+cfg.AuthorizationEndpoint,
			map[string]any{"request_id": firstRequestID(b.obs.RequestIDs), "url": cfg.AuthorizationEndpoint},
			"oauth", "endpoint")
	}
	if authorizeURL != "" {
		if err := auditAuthorizeRequest(ctx, env, b, authorizeURL); err != nil {
			b.fact("授权请求审计跳过:"+err.Error(),
				map[string]any{"request_id": firstRequestID(b.obs.RequestIDs), "url": authorizeURL}, "oauth")
		}
	}

	b.setSummary(fmt.Sprintf("oauth_audit: 发现文档%s,发现 %d 条", map[bool]string{true: "可读", false: "不可读"}[haveCfg], len(b.obs.Findings)))
	return b.obs, nil
}

// auditAuthorizeRequest inspects one authorisation URL without completing a flow.
func auditAuthorizeRequest(ctx context.Context, env *Env, b *obsBuilder, authorizeURL string) error {
	u, err := url.Parse(authorizeURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("authorize_url 不是合法 URL")
	}
	q := u.Query()

	res, err := do(ctx, env, discipline.Request{
		Method: "GET", URL: authorizeURL, Purpose: "oauth_audit", FollowRedirects: false,
	})
	if err != nil {
		return err
	}
	b.requestID(res.RequestID)
	ev := map[string]any{"request_id": res.RequestID, "url": authorizeURL, "source": "oauth"}

	if q.Get("state") == "" {
		b.finding(ledger.FindingSeed{
			Title:    "授权请求缺少 state 参数",
			Severity: "medium",
			Kind:     "oauth",
			Where:    authorizeURL,
			Detail:   "授权请求没有 state:回调无法绑定发起方会话,存在 CSRF / 授权码注入风险。",
			Counter:  "若客户端在别处完成状态绑定(例如同站 SameSite cookie + 服务端会话),风险会降低;需人工确认。",
			Evidence: ev,
			Tags:     []string{"oauth", "csrf"},
			Anchors:  []string{"surface:" + authorizeURL},
		})
	}
	if q.Get("code_challenge") == "" && q.Get("response_type") == "code" {
		b.finding(ledger.FindingSeed{
			Title:    "授权码流程缺少 PKCE",
			Severity: "low",
			Kind:     "oauth",
			Where:    authorizeURL,
			Detail:   "response_type=code 但没有 code_challenge:公开客户端可被授权码拦截。",
			Counter:  "机密客户端可以不用 PKCE;需确认该 client_id 的类型。",
			Evidence: ev,
			Tags:     []string{"oauth", "pkce"},
			Anchors:  []string{"surface:" + authorizeURL},
		})
	}

	// 2b) state quality, still read-only: a state that is short or obviously
	// patterned cannot bind the callback to the session.
	if st := q.Get("state"); st != "" {
		if weakState(st) {
			b.finding(ledger.FindingSeed{
				Title:    "授权请求的 state 熵不足",
				Severity: "low",
				Kind:     "oauth",
				Where:    authorizeURL,
				Detail: fmt.Sprintf("state 长度 %d,字符集熵约 %.1f 位:太弱或明显有规律,"+
					"无法可靠绑定回调与发起方会话。只做统计,不解码、不重放。", len(st), stateEntropy(st)),
				Counter:  "CSRF 防护可能还依赖 SameSite cookie 或服务端会话;需人工确认。",
				Evidence: ev, Tags: []string{"oauth", "csrf", "entropy"},
				Anchors: []string{"surface:" + authorizeURL},
			})
		}
	}

	// 2c) response_mode combinations that leak material into URLs.
	if rm := q.Get("response_mode"); rm != "" {
		lower := strings.ToLower(rm)
		if lower == "query" || lower == "fragment" {
			b.fact("授权请求使用 response_mode="+rm+"(令牌或 code 可能出现在 URL 中)",
				ev, "oauth", "flow")
		}
	}

	// 3) ONE redirect_uri observation: append a path segment to the registered
	// redirect_uri and see whether the server still accepts it (no code exchange,
	// no token, nothing followed).
	if ru := q.Get("redirect_uri"); ru != "" {
		alt := strings.TrimRight(ru, "/") + "/youkai-probe"
		altURL := *u
		aq := u.Query()
		aq.Set("redirect_uri", alt)
		altURL.RawQuery = aq.Encode()
		probe, perr := do(ctx, env, discipline.Request{
			Method: "GET", URL: altURL.String(), Purpose: "oauth_audit", FollowRedirects: false,
		})
		if perr == nil {
			b.requestID(probe.RequestID)
			pev := map[string]any{"request_id": probe.RequestID, "url": altURL.String(), "source": "oauth"}
			location := probe.Header["Location"]
			accepted := probe.Status < 400
			if loc := location; loc != "" {
				// A redirect back to the modified URI means the server echoed our value.
				if strings.Contains(loc, "/youkai-probe") {
					accepted = true
				} else if strings.Contains(strings.ToLower(loc), "error=") ||
					strings.Contains(strings.ToLower(loc), "invalid_request") {
					accepted = false
				}
			}
			if accepted {
				b.finding(ledger.FindingSeed{
					Title:    "redirect_uri 校验疑似宽松",
					Severity: "medium",
					Kind:     "oauth",
					Where:    altURL.String(),
					Detail: "把 redirect_uri 追加一段路径后,服务端仍然接受(HTTP " +
						fmt.Sprint(probe.Status) + ")。若真实回调地址未白名单校验,授权码可能被导向攻击者路径。",
					Counter: "本次只发了一次只读 GET,没有完成授权、没有换 token;服务端可能在校验后仍返回同意页。" +
						"要定为可利用需要授权方配合,当前只是配置观察。",
					Evidence: pev,
					Tags:     []string{"oauth", "redirect-uri"},
					Anchors:  []string{"surface:" + u.Host},
				})
			} else {
				b.fact("redirect_uri 变体被拒绝(HTTP "+fmt.Sprint(probe.Status)+")", pev, "oauth", "redirect-uri")
			}
		}
	}
	return nil
}

func firstRequestID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// weakState flags a state value that cannot be doing CSRF binding properly.
func weakState(s string) bool {
	if len(s) < 16 {
		return true
	}
	// A single repeated character or a short cycle is not entropy.
	distinct := map[rune]bool{}
	for _, r := range s {
		distinct[r] = true
	}
	return len(distinct) < 6
}

// stateEntropy estimates the per-character entropy of the value.
func stateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h * n / 8 // rough bits of information
}
