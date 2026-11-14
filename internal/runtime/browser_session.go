package runtime

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"youkai/internal/accounts"
	"youkai/internal/web"
)

// Browser identity resolution.
//
// The graph records the session NAME ("render /orders/1 as alice"); the credential
// itself exists only in memory for the duration of one render. The dispatcher is
// the only place that turns one into the other, so a capability can never stash a
// cookie in a fact, and a snapshot can never contain one.
//
// The host binding is the second half of the guarantee: the credential is attached
// only to the identity's own host. A render that wanders to another host inside the
// scope gets no cookie, which is what stops "A's session" from leaking to "B".

// sessionIdentity is a resolved credential plus the ownership checks that make
// sense for this identity.
type sessionIdentity struct {
	Name    string
	Headers map[string]string
	Host    string
	Watch   []web.MarkerWatch
}

// sessionIdentityFor resolves the `session` argument of a browser render.
//
// A named session that cannot be loaded is an error, not a fallback to anonymous:
// an anonymous render reported as authenticated would be a false claim.
func (d *Dispatcher) sessionIdentityFor(args map[string]any) (sessionIdentity, error) {
	name := strings.TrimSpace(argStringOf(args, "session"))
	if name == "" {
		return sessionIdentity{}, nil
	}
	store, err := accounts.NewSessionStore(d.sessionDir())
	if err != nil {
		return sessionIdentity{}, fmt.Errorf("accounts: 会话目录: %w", err)
	}
	sess, err := store.Load(name)
	if err != nil {
		return sessionIdentity{}, fmt.Errorf("accounts: 会话 %q 不可用(未登录或解密失败): %w", name, err)
	}
	if len(sess.Headers) == 0 {
		return sessionIdentity{}, fmt.Errorf("accounts: 会话 %q 没有任何 header", name)
	}
	id := sessionIdentity{Name: name, Headers: sess.Headers}

	m, err := accounts.Loaded(d.accountsPath())
	if err != nil || m == nil {
		// Without a manifest there is no host binding and no ownership to check. The
		// browser falls back to the navigation target's host; ownership checks are
		// simply absent (nothing declared, nothing to violate).
		return id, nil
	}
	if acc, ok := m.Account(name); ok {
		id.Host = hostOfURL(joinBase(m, acc.Login.URL))
		if id.Host == "" && len(acc.Owns) > 0 {
			id.Host = hostOfURL(joinBase(m, acc.Owns[0].URL))
		}
	}
	for _, p := range m.BolaPairs() {
		if p.Viewer != name {
			continue
		}
		id.Watch = append(id.Watch, web.MarkerWatch{Owner: p.Owner, Marker: p.Marker, URL: p.URL})
	}
	return id, nil
}

// joinBase resolves a possibly-relative manifest URL against the manifest base.
func joinBase(m *accounts.Manifest, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		return raw
	}
	base := m.Base(accounts.Account{})
	if base == "" {
		return raw
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(raw, "/")
}

func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

var _ = context.Background
