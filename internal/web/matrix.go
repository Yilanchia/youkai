package web

import (
	"context"
	"fmt"
	"math"
	"net/url"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Multi-account permission matrix.
//
// One read-only GET per (url, identity) pair, then a summary of who could reach
// what. It is a candidate generator: a role difference may be intended design,
// and every finding says so. No object contents are read, no privilege is
// attempted, and both loops are hard-capped.

const (
	maxMatrixURLs     = 10
	maxMatrixSessions = 6
)

type matrixIdentity struct {
	name    string
	headers map[string]string
}

type matrixRow struct {
	identity matrixIdentity
	res      *discipline.Response
}

func runRoleMatrix(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	urls := argStringSlice(args, "urls")
	if len(urls) == 0 {
		return ledger.Observation{}, fmt.Errorf("web: role_matrix: missing required argument \"urls\"")
	}
	sessionArgs := argMapSlice(args, "sessions")
	if len(sessionArgs) == 0 {
		return ledger.Observation{}, fmt.Errorf("web: role_matrix: 至少需要一个 session(先在账号层完成登录)")
	}

	if len(urls) > maxMatrixURLs {
		urls = urls[:maxMatrixURLs]
	}
	if len(sessionArgs) > maxMatrixSessions {
		sessionArgs = sessionArgs[:maxMatrixSessions]
	}

	named := make([]matrixIdentity, 0, len(sessionArgs))
	for _, s := range sessionArgs {
		name := argString(s, "name")
		if name == "" {
			continue
		}
		named = append(named, matrixIdentity{name: name, headers: argStringMap(s, "headers")})
	}
	if len(named) == 0 {
		return ledger.Observation{}, fmt.Errorf("web: role_matrix: sessions 里没有带 name 的会话")
	}
	identities := make([]matrixIdentity, 0, len(named)+1)
	if argBool(args, "include_anonymous", true) {
		identities = append(identities, matrixIdentity{name: "anonymous"})
	}
	identities = append(identities, named...)

	adminName := argString(args, "admin")
	if adminName == "" {
		adminName = named[0].name
	}

	b := newObs()
	summaries := 0
	for _, rawURL := range urls {
		rows := make([]matrixRow, 0, len(identities))
		for _, identity := range identities {
			res, err := do(ctx, env, discipline.Request{
				Method: "GET", URL: rawURL, Headers: identity.headers,
				Purpose: "role_matrix", FollowRedirects: true,
			})
			if err == nil && res != nil {
				b.requestID(res.RequestID)
			}
			rows = append(rows, matrixRow{identity: identity, res: res})
		}

		first := firstSucceeded(rows)
		if first == nil {
			continue
		}
		summaries++
		verdict, statuses := summariseMatrix(rows)
		evidence := map[string]any{
			"request_id": first.RequestID,
			"url":        rawURL,
			"statuses":   statuses,
			"admin":      adminName,
			"verdict":    verdict,
		}
		b.fact(fmt.Sprintf("权限矩阵 %s -> %s", rawURL, verdict), evidence, "role_matrix", "authz")

		adminRow := findRow(rows, adminName)
		if adminRow == nil || adminRow.res == nil {
			continue
		}
		for _, row := range rows {
			if row.identity.name == "anonymous" || row.identity.name == adminName || row.res == nil {
				continue
			}
			if !sameRenderedContent(adminRow.res, row.res) {
				continue
			}
			path := rawURL
			if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
				path = u.Path
			}
			b.finding(ledger.FindingSeed{
				Title:    "非管理员会话可见与参照会话相同内容:" + path,
				Severity: "medium",
				Kind:     "authz",
				Where:    rawURL,
				Detail: fmt.Sprintf("参照会话 %s 与会话 %s 均返回 HTTP %d,正文长度 %d/%d(差 %.1f%%);"+
					"可能是 BFLA 或权限矩阵配置错误,也可能是有意共享。需人工复核。",
					adminName, row.identity.name, row.res.Status,
					adminRow.res.BodyBytes, row.res.BodyBytes, lengthDelta(adminRow.res, row.res)*100),
				Evidence: map[string]any{
					"request_id":       row.res.RequestID,
					"admin_request_id": adminRow.res.RequestID,
					"url":              rawURL,
					"status":           row.res.Status,
					"length_admin":     adminRow.res.BodyBytes,
					"length_session":   row.res.BodyBytes,
					"admin":            adminName,
					"session":          row.identity.name,
				},
				Tags: []string{"authz", "bfla"},
			})
		}
	}

	if summaries == 0 {
		return ledger.Observation{}, fmt.Errorf("web: role_matrix: 所有 url × session 请求都失败(检查 scope、方法授权与目标可达性)")
	}
	b.setSummary(fmt.Sprintf("role_matrix: %d URL × %d 身份", summaries, len(identities)))
	return b.obs, nil
}

func firstSucceeded(rows []matrixRow) *discipline.Response {
	for _, row := range rows {
		if row.res != nil {
			return row.res
		}
	}
	return nil
}

func findRow(rows []matrixRow, name string) *matrixRow {
	for i := range rows {
		if rows[i].identity.name == name {
			return &rows[i]
		}
	}
	return nil
}

func summariseMatrix(rows []matrixRow) (string, map[string]any) {
	statuses := make(map[string]any, len(rows))
	namedStatus := map[int]bool{}
	anonymousAllowed := false
	hasAnonymous := false
	for _, row := range rows {
		if row.res != nil {
			statuses[row.identity.name] = row.res.Status
		} else {
			statuses[row.identity.name] = "error"
		}
		if row.identity.name == "anonymous" {
			hasAnonymous = true
			anonymousAllowed = row.res != nil && is2xx(row.res.Status)
			continue
		}
		if row.res != nil {
			namedStatus[row.res.Status] = true
		}
	}
	switch {
	case len(namedStatus) > 1:
		return "role-diff", statuses
	case hasAnonymous && anonymousAllowed:
		return "public", statuses
	case hasAnonymous:
		return "auth-required", statuses
	default:
		return "uniform", statuses
	}
}

func is2xx(status int) bool { return status >= 200 && status < 300 }

// sameRenderedContent is the candidate test: same status and a body length within
// 5%. Length is a proxy; the finding says "candidate" and needs human review.
func sameRenderedContent(a, b *discipline.Response) bool {
	if a.Status != b.Status || !is2xx(a.Status) {
		return false
	}
	return lengthDelta(a, b) < 0.05
}

func lengthDelta(a, b *discipline.Response) float64 {
	la, lb := float64(a.BodyBytes), float64(b.BodyBytes)
	larger := math.Max(la, lb)
	if larger == 0 {
		return 0
	}
	return math.Abs(la-lb) / larger
}
