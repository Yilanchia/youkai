package discipline

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// Authorized is a request the guard has cleared for a sender that is NOT the Go
// HTTP client - currently the CDP browser.
//
// This is the piece that keeps the monolith honest. The browser opens its own
// sockets, so the guard cannot perform the request; what it can do - and must do -
// is decide, per request, whether the passport allows it and write the audit row
// either way. A cleared request gets a request_id before it leaves.
type Authorized struct {
	RequestID string
	Method    string
	URL       string
	// Host is the target host, for the caller's bookkeeping.
	Host string
}

// Authorize is the egress decision for another sender.
//
// Order matters: expiry, method, scope, budget, rate - the same sequence Do uses -
// and the audit row is written BEFORE the request is released. If the row cannot
// be written, the request is refused (fail closed), so an un-audited page load is
// not representable.
func (g *Guard) Authorize(ctx context.Context, method, rawURL, purpose string, detail map[string]any) (Authorized, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	scope := g.Scope()
	if scope == nil {
		return Authorized{}, ErrNoScope
	}

	refuse := func(reason string) (Authorized, error) {
		dec, _ := scope.Check(rawURL)
		_ = g.audit(ctx, AuditEvent{
			RequestID:  g.nextRequestID(),
			Engagement: g.engagement,
			TS:         g.now().UTC(),
			Method:     method,
			URL:        rawURL,
			Host:       dec.Host,
			Verdict:    VerdictBlocked,
			Reason:     reason,
			Purpose:    purpose,
			Detail:     cloneDetail(detail),
		})
		return Authorized{}, fmt.Errorf("discipline: %s", reason)
	}

	if scope.Expired(g.now()) {
		return refuse("scope passport expired")
	}
	if !scope.MethodAllowed(method) {
		return refuse("method " + method + " is not authorised")
	}
	dec, err := scope.Check(rawURL)
	if err != nil {
		return refuse(err.Error())
	}
	if g.lim.count() >= scope.MaxRequests {
		return refuse(fmt.Sprintf("request budget exhausted (%d)", scope.MaxRequests))
	}
	if _, err := g.lim.take(ctx, scope, g.now, g.sleep); err != nil {
		return refuse("rate limiter interrupted: " + err.Error())
	}

	id := g.nextRequestID()
	d := cloneDetail(detail)
	if d == nil {
		d = map[string]any{}
	}
	// The response status is unknown here: this row records the decision, and the
	// caller records what the page did with it (blocked requests get their own row).
	d["sent_by"] = "browser"
	if err := g.audit(ctx, AuditEvent{
		RequestID:  id,
		Engagement: g.engagement,
		TS:         g.now().UTC(),
		Method:     method,
		URL:        rawURL,
		Host:       dec.Host,
		Verdict:    VerdictAllowed,
		Reason:     "authorised for the browser by " + dec.Reason,
		Purpose:    purpose,
		Detail:     d,
	}); err != nil {
		return Authorized{}, fmt.Errorf("discipline: audit failed, refusing to release the request: %w", err)
	}
	return Authorized{RequestID: id, Method: method, URL: rawURL, Host: dec.Host}, nil
}

// Refuse records a blocked request that another sender tried to make (or that we
// stopped after the fact). It never sends anything.
func (g *Guard) Refuse(ctx context.Context, method, rawURL, purpose, reason string, detail map[string]any) {
	if g == nil {
		return
	}
	scope := g.Scope()
	host := ""
	if scope != nil {
		if dec, err := scope.Check(rawURL); err == nil {
			host = dec.Host
		}
	}
	if method == "" {
		method = http.MethodGet
	}
	_ = g.audit(ctx, AuditEvent{
		RequestID:  g.nextRequestID(),
		Engagement: g.engagement,
		TS:         g.now().UTC(),
		Method:     strings.ToUpper(method),
		URL:        rawURL,
		Host:       host,
		Verdict:    VerdictBlocked,
		Reason:     reason,
		Purpose:    purpose,
		Detail:     cloneDetail(detail),
	})
}

// Clone returns a guard with the same passport, auditor and budget, but its own
// cookie jar and transport.
//
// Account provisioning uses one clone per identity so sessions can never bleed
// between accounts; the browser uses its own clone for the same reason. The
// budget stays shared on purpose: N clones must not multiply the authorisation.
func (g *Guard) Clone() *Guard {
	scope := g.Scope()
	c := &Guard{
		engagement: g.engagement,
		auditor:    g.auditor,
		scope:      scope,
		lim:        g.lim,
		now:        g.now,
		sleep:      g.sleep,
	}
	c.rebuildClient()
	return c
}

// SessionCookies returns the cookies the guard's jar holds for a URL.
//
// Login flows need the real values to build a session; the sanitised response
// headers only carry names. Keeping this on the guard means the values never
// travel through a capability's Observation, and only the account layer (which is
// explicitly allowed to handle credentials) calls it.
func (g *Guard) SessionCookies(rawURL string) []*http.Cookie {
	if g.client == nil || g.client.Jar == nil {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return g.client.Jar.Cookies(u)
}

// CookieHeader renders cookies as a Cookie header value.
func CookieHeader(cookies []*http.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// NewJar is a convenience for callers that need an isolated jar (tests).
func NewJar() http.CookieJar {
	j, _ := cookiejar.New(nil)
	return j
}

func cloneDetail(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
