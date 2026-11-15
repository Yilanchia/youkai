package whitebox

import (
	"strings"
)

// Auth coverage: which routes look unprotected.
//
// The heuristic is intentionally blunt: a route declared without an auth-looking
// middleware/decorator nearby, on a method or path that usually mutates data, is a
// lead. It produces false positives (a global middleware registered elsewhere) and
// false negatives (auth checked inside the handler). Both are acceptable because
// the lead is verified by an actual request with a low-privilege identity, and can
// only become a candidate if that request is reachable.

var sensitiveMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

func scanAuthz(lang language, file, src string, routes []Route) []Hypothesis {
	var out []Hypothesis
	for _, r := range routes {
		if r.Auth {
			continue
		}
		sensitive := sensitiveMethods[r.Method] || reSensitivePath.MatchString(r.Path)
		if !sensitive {
			continue
		}
		// The route is worth a lead only if the file does not register a global
		// auth middleware, which would cover it invisibly.
		if hasGlobalAuth(src) {
			continue
		}
		out = append(out, Hypothesis{
			Kind: "missing-authz", Entry: r.Method + " " + r.Path, Param: "", Sink: "authz",
			Path:       file + ":" + itoa(r.Line),
			Confidence: "code-only",
			Note:       "这条路由看不出认证中间件,且方法/路径像是有状态的;用低权身份请求一次即可证伪或证实",
			File:       file, Line: r.Line,
		})
	}
	return out
}

// hasGlobalAuth spots the common "protect everything" idioms.
func hasGlobalAuth(src string) bool {
	for _, pat := range []string{
		"app.use(auth", "app.use(requireAuth", "app.use(authenticate",
		"router.use(auth", "app.use(jwt", "app.use(session",
		"@login_required", "@jwt_required", "LoginRequiredMixin", "permission_required",
		"Use(AuthMiddleware()", "Use(authMiddleware)", "middleware.JWT",
	} {
		if strings.Contains(strings.ToLower(src), strings.ToLower(pat)) {
			return true
		}
	}
	return false
}
