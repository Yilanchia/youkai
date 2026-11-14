package engine

import (
	"context"
	"errors"
	"strings"
	"time"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Mandate autonomy (ADR-005).
//
// The rule this file implements, in one sentence: a tier-2 step may run without a
// per-step approval ONLY when a human-signed mandate is in force, covers that
// step's autonomy class, covers the step's target, and still has budget left.
//
// Everything here is conservative on purpose:
//
//   - the mandate is read from the store on every run (no cached flag to flip);
//   - an unknown class, an unknown target, a missing budget or an expired mandate
//     all mean "park it", never "assume allowed";
//   - tier 3 remains refused by the gate before any of this is consulted, so a
//     mandate can never reach the wall.

// ErrNoMandate means no mandate is in force.
var ErrNoMandate = errors.New("engine: no mandate in force")

// mandateCtx is what one run knows about the mandate in force.
type mandateCtx struct {
	m       ledger.Mandate
	usage   int   // requests sent since activation
	usedUp  bool  // usage >= max_requests
	fetched bool  // whether the lookups ran
	lookErr error // store failure, kept to fail closed
}

// loadMandate reads the mandate once per run. A store error is remembered and
// treated as "no mandate": autonomy is never granted on a failed read.
func (e *Engine) loadMandate(ctx context.Context) mandateCtx {
	mc := mandateCtx{fetched: true}
	// ADR-006 retracted the mandate as a default: without RequireHighAuth the
	// engine never looks one up, so tier-2 always parks for a click.
	if !e.cfg.RequireHighAuth {
		return mc
	}
	m, err := e.cfg.Store.ActiveMandate(ctx, e.cfg.EngagementID)
	if errors.Is(err, ledger.ErrNotFound) {
		return mc
	}
	if err != nil {
		mc.lookErr = err
		return mc
	}
	mc.m = m
	usage, err := e.cfg.Store.MandateUsage(ctx, e.cfg.Engagement, m.ActivatedAt)
	if err != nil {
		mc.lookErr = err
		mc.m = ledger.Mandate{}
		return mc
	}
	mc.usage = usage
	mc.usedUp = usage >= m.MaxRequests
	return mc
}

// active reports whether a usable mandate was loaded. It re-checks the clock on
// every call: expiry is enforced here, not by whatever last wrote the row.
func (mc mandateCtx) active() bool {
	return mc.lookErr == nil && mc.m.ID != 0 && !mc.usedUp && mc.m.Active(time.Now())
}

// covers reports whether this mandate authorises running this intent.
//
// Two independent conditions, both required:
//   - the capability belongs to a class the mandate names;
//   - the intent's target is inside the mandate's assets.
func (mc mandateCtx) covers(it ledger.Intent) bool {
	if !mc.active() {
		return false
	}
	class := gate.AutonomyClass(it.Capability)
	if class == "" || !mc.m.CoversClass(class) {
		return false
	}
	for _, target := range intentTargets(it) {
		if !grantCovers(mc.m.Assets, target) {
			return false
		}
	}
	return true
}

// intentTargets lists the URLs/hosts an intent would touch.
func intentTargets(it ledger.Intent) []string {
	var out []string
	for _, key := range []string{"url", "target", "authorize_url", "login_url"} {
		if v, ok := it.Args[key].(string); ok && strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

// grantCovers matches a target against a mandate asset list using the same
// normalisation as the high-auth verifier (bare host, host:port, URL, wildcard,
// CIDR). It lives here so the engine does not import the discipline package.
func grantCovers(assets []string, target string) bool {
	host, authority := splitTargetHost(target)
	if host == "" {
		return false
	}
	for _, raw := range assets {
		pat := strings.ToLower(strings.TrimSpace(raw))
		if pat == "" {
			continue
		}
		if i := strings.Index(pat, "://"); i >= 0 {
			pat = pat[i+3:]
		}
		if i := strings.IndexAny(pat, "/?#"); i >= 0 {
			pat = pat[:i]
		}
		if strings.Contains(pat, "/") {
			continue // CIDR is not needed for mandate targets; refuse to guess
		}
		if strings.HasPrefix(pat, "*.") {
			if strings.HasSuffix(host, pat[1:]) && len(host) > len(pat)-1 {
				return true
			}
			continue
		}
		if pat == host || pat == authority {
			return true
		}
	}
	return false
}

func splitTargetHost(target string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return "", ""
	}
	if i := strings.Index(t, "://"); i >= 0 {
		rest := t[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		host := rest
		if k := strings.LastIndex(host, ":"); k > 0 && !strings.Contains(host[k:], "]") {
			host = host[:k]
		}
		return strings.TrimSuffix(host, "."), rest
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	host := t
	if k := strings.LastIndex(host, ":"); k > 0 && !strings.Contains(host[k:], "]") {
		host = host[:k]
	}
	return host, t
}
