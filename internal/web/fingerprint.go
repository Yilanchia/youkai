package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// runFingerprint infers a technology stack from one guarded response.
//
// The rule is "never invent": every hit below is a regex match on a header value
// or on the response body, and the fact's evidence names the source that matched.
// If nothing matches, the capability says so instead of guessing.

type techRule struct {
	rx   *regexp.Regexp
	name string
}

// Order matters: the first matching Server-family rule wins, as in Fairy.
var headerTechRules = []techRule{
	{regexp.MustCompile(`(?i)(^|\s)openresty(?:/|$)`), "OpenResty"},
	{regexp.MustCompile(`(?i)(^|\s)nginx(?:/|$)`), "nginx"},
	{regexp.MustCompile(`(?i)(^|\s)apache(?:/|$)`), "Apache"},
	{regexp.MustCompile(`(?i)microsoft-iis`), "IIS"},
	{regexp.MustCompile(`(?i)cloudflare`), "Cloudflare"},
	{regexp.MustCompile(`(?i)envoy`), "Envoy"},
	{regexp.MustCompile(`(?i)express`), "Express"},
	{regexp.MustCompile(`(?i)caddy`), "Caddy"},
	{regexp.MustCompile(`(?i)tomcat`), "Tomcat"},
	{regexp.MustCompile(`(?i)jetty`), "Jetty"},
	{regexp.MustCompile(`(?i)kestrel`), "Kestrel"},
}

var cookieTechRules = []techRule{
	{regexp.MustCompile(`(?i)^PHPSESSID$`), "PHP"},
	{regexp.MustCompile(`(?i)^JSESSIONID$`), "Java"},
	{regexp.MustCompile(`(?i)^ASP\.NET_SessionId$`), "ASP.NET"},
	{regexp.MustCompile(`(?i)^connect\.sid$`), "Express"},
	{regexp.MustCompile(`(?i)^laravel_session$`), "Laravel"},
	{regexp.MustCompile(`(?i)^csrftoken$`), "Django"},
	{regexp.MustCompile(`(?i)^XSRF-TOKEN$`), "Laravel"},
	{regexp.MustCompile(`(?i)^(CFID|CFTOKEN)$`), "ColdFusion"},
	{regexp.MustCompile(`(?i)^wordpress_`), "WordPress"},
}

// bodyTechRules may carry one capture group, interpreted as a version when it
// looks like one (ng-version="16.1.0").
var bodyTechRules = []struct {
	rx   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`(?i)wp-content|wp-includes`), "WordPress"},
	{regexp.MustCompile(`(?i)__NEXT_DATA__|/_next/`), "Next.js"},
	{regexp.MustCompile(`(?i)__NUXT__|/_nuxt/`), "Nuxt"},
	{regexp.MustCompile(`(?i)data-reactroot|react-dom(?:\.production)?\.min\.js`), "React"},
	{regexp.MustCompile(`(?i)data-v-[0-9a-f]{6,}|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js`), "Vue"},
	{regexp.MustCompile(`(?i)ng-version=["']([\d.]+)|ng-app=`), "Angular"},
	{regexp.MustCompile(`(?i)csrfmiddlewaretoken`), "Django"},
	{regexp.MustCompile(`(?i)whitelabel error page|spring-security`), "Spring"},
	{regexp.MustCompile(`(?i)__VIEWSTATE|X-AspNet-Version`), "ASP.NET"},
	{regexp.MustCompile(`(?i)swagger-ui|SwaggerUIBundle`), "Swagger UI"},
	{regexp.MustCompile(`(?i)grafana`), "Grafana"},
	{regexp.MustCompile(`(?i)jenkins`), "Jenkins"},
}

var (
	versionRx      = regexp.MustCompile(`\d+(?:\.\d+)+`)
	metaGenRx      = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	scriptSrcRx    = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	jqueryRx       = regexp.MustCompile(`(?i)jquery[.-]?v?([\d.]+)(?:\.min)?\.js`)
	allCookiesName = regexp.MustCompile(`(?:^|;|,)\s*([^=;,\s]+)=`)
)

type techHit struct {
	name    string
	version string
	source  string
}

func runFingerprint(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	res, err := do(ctx, env, discipline.Request{
		Method:          "GET",
		URL:             rawURL,
		Headers:         argStringMap(args, "headers"),
		Purpose:         "fingerprint",
		FollowRedirects: argBool(args, "follow_redirects", true),
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: fingerprint: %w", err)
	}

	b := newObs()
	b.requestID(res.RequestID)
	hits := detectTechnologies(res)
	for _, hit := range hits {
		ev := respEvidence(res)
		ev["version"] = hit.version
		ev["source"] = hit.source
		b.fact("指纹:"+hit.name, ev, "fingerprint")
	}
	if len(hits) == 0 {
		b.fact("指纹:未识别", respEvidence(res), "fingerprint")
	}
	b.setSummary(fmt.Sprintf("fingerprint %s: %d 项", rawURL, len(hits)))
	return b.obs, nil
}

func detectTechnologies(res *discipline.Response) []techHit {
	var hits []techHit
	seen := map[string]bool{}
	add := func(name, version, source string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		version = strings.TrimSpace(version)
		key := strings.ToLower(name) + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		hits = append(hits, techHit{name: name, version: version, source: source})
	}

	server := headerGet(res.Header, "Server")
	if server != "" {
		version := versionRx.FindString(server)
		matched := false
		for _, rule := range headerTechRules {
			if rule.rx.MatchString(server) {
				add(rule.name, version, "Server: "+server)
				matched = true
				break
			}
		}
		if !matched {
			add(firstToken(server), version, "Server: "+server)
		}
	}

	if powered := headerGet(res.Header, "X-Powered-By"); powered != "" {
		name := powered
		if i := strings.IndexByte(name, '/'); i > 0 {
			name = name[:i]
		}
		add(name, versionRx.FindString(powered), "X-Powered-By: "+powered)
	}
	if via := headerGet(res.Header, "Via"); via != "" {
		add("proxy", "", "Via: "+via)
	}

	for _, cookie := range cookieNames(headerGet(res.Header, "Set-Cookie")) {
		for _, rule := range cookieTechRules {
			if rule.rx.MatchString(cookie) {
				add(rule.name, "", "Set-Cookie: "+cookie)
			}
		}
	}

	body := res.Text()
	for _, rule := range bodyTechRules {
		m := rule.rx.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		version := ""
		if len(m) > 1 && versionRx.MatchString(m[1]) {
			version = m[1]
		}
		add(rule.name, version, "body matched "+rule.name)
	}

	if m := metaGenRx.FindStringSubmatch(body); m != nil {
		content := strings.TrimSpace(m[1])
		add(firstToken(content), versionRx.FindString(content), "meta generator: "+content)
	}
	if m := jqueryRx.FindStringSubmatch(body); m != nil {
		add("jQuery", m[1], "script src")
	}
	for _, m := range scriptSrcRx.FindAllStringSubmatch(body, 40) {
		if len(m) < 2 {
			continue
		}
		src := strings.ToLower(m[1])
		switch {
		case strings.Contains(src, "jquery"):
			add("jQuery", "", "script src")
		case strings.Contains(src, "react"):
			add("React", "", "script src")
		case strings.Contains(src, "vue"):
			add("Vue", "", "script src")
		case strings.Contains(src, "angular"):
			add("Angular", "", "script src")
		case strings.Contains(src, "bootstrap"):
			add("Bootstrap", "", "script src")
		}
	}

	const maxHits = 20
	if len(hits) > maxHits {
		hits = hits[:maxHits]
	}
	return hits
}

func firstToken(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '/', '(', ')', ',', ';':
			return true
		}
		return false
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
