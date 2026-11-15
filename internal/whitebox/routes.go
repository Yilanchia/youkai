package whitebox

import (
	"regexp"
	"strings"
)

// Route discovery.
//
// Three stacks, chosen because they cover most of what an operator hands you:
// Express/Koa (JS), Flask (Python), Gin/Echo (Go). Each pattern only has to be
// good enough to produce a route table a human can check - the value of the map is
// that it costs one glance to verify, not that it is exhaustive.

var (
	// Express / Koa: app.get('/x', mw, handler)
	reJSRoute = regexp.MustCompile(`(?m)\b(?:app|router|server|api)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*['"]([^'"]+)['"]\s*(,([^)\n]*))?`)
	// Flask: @app.route('/x', methods=['POST']) or @bp.get('/x')
	rePyRoute = regexp.MustCompile(`(?m)@\s*(?:[\w.]+)\s*\.\s*(route|get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]([^)]*)\)`)
	// Gin / Echo / chi: r.GET("/x", handler)
	reGoRoute = regexp.MustCompile(`(?m)\b(?:r|router|e|g|group|api|v1)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any|Handle)\s*\(\s*"([^"]+)"`)
	// A decorator or middleware that adds authentication.
	reAuthWord = regexp.MustCompile(`(?i)auth|jwt|login|session|requireUser|isAdmin|permission|guard|token`)
	// Sensitive-looking routes are worth flagging when unprotected.
	reSensitivePath = regexp.MustCompile(`(?i)admin|delete|update|edit|create|transfer|pay|user|account|order`)
)

func scanRoutes(lang language, file, src string) []Route {
	var out []Route
	switch lang {
	case langJS:
		for _, m := range reJSRoute.FindAllStringSubmatchIndex(src, -1) {
			verb := strings.ToUpper(src[m[2]:m[3]])
			if verb == "USE" {
				continue
			}
			path := src[m[4]:m[5]]
			middle := ""
			if m[6] >= 0 {
				middle = src[m[6]:m[7]]
			}
			handler := lastIdentifier(middle)
			line := lineOf(src, m[0])
			out = append(out, Route{
				Method: verb, Path: path, Handler: handler, File: file, Line: line,
				Auth: reAuthWord.MatchString(middle), Framework: "express",
			})
		}
	case langPython:
		for _, m := range rePyRoute.FindAllStringSubmatchIndex(src, -1) {
			verbRaw := strings.ToLower(src[m[2]:m[3]])
			extra := ""
			if m[6] >= 0 {
				extra = src[m[6]:m[7]]
			}
			methods := []string{"GET"}
			if verbRaw == "route" {
				if mm := regexp.MustCompile(`methods\s*=\s*\[([^\]]*)\]`).FindStringSubmatch(extra); mm != nil {
					methods = nil
					for _, part := range strings.Split(mm[1], ",") {
						p := strings.ToUpper(strings.Trim(strings.TrimSpace(part), `'"`))
						if p != "" {
							methods = append(methods, p)
						}
					}
				}
			} else {
				methods = []string{strings.ToUpper(verbRaw)}
			}
			line := lineOf(src, m[0])
			// Auth is usually a decorator stacked above the route.
			window := decoratorWindow(src, m[0])
			for _, verb := range methods {
				out = append(out, Route{
					Method: verb, Path: src[m[4]:m[5]], Handler: pythonFuncAfter(src, m[1]),
					File: file, Line: line, Auth: reAuthWord.MatchString(window), Framework: "flask",
				})
			}
		}
	case langGo:
		for _, m := range reGoRoute.FindAllStringSubmatchIndex(src, -1) {
			verb := strings.ToUpper(src[m[2]:m[3]])
			if verb == "ANY" || verb == "HANDLE" {
				verb = "ANY"
			}
			line := lineOf(src, m[0])
			// A group that calls .Use(AuthMiddleware()) protects its routes.
			prefixWindow := src[maxInt(0, m[0]-1200):m[0]]
			out = append(out, Route{
				Method: verb, Path: src[m[4]:m[5]], File: file, Line: line,
				Auth:      strings.Contains(prefixWindow, ".Use(") && reAuthWord.MatchString(tail(prefixWindow, 200)),
				Framework: "gin",
			})
		}
	}
	return out
}

func decoratorWindow(src string, off int) string {
	start := off - 600
	if start < 0 {
		start = 0
	}
	return src[start:off]
}

func pythonFuncAfter(src string, off int) string {
	rest := src[off:]
	if i := strings.Index(rest, "def "); i >= 0 && i < 200 {
		after := rest[i+4:]
		if j := strings.IndexAny(after, "( :"); j > 0 {
			return after[:j]
		}
	}
	return ""
}

func lastIdentifier(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Strip trailing parens and take the last name in the argument list.
	if i := strings.Index(s, ")"); i >= 0 {
		s = s[:i]
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '(' || r == ' ' || r == '\n' || r == '\t'
	})
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" || p == "async" || p == "function" {
			continue
		}
		if j := strings.Index(p, "=>"); j >= 0 {
			p = strings.TrimSpace(p[:j])
		}
		if p != "" {
			return p
		}
	}
	return ""
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
