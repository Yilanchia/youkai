// Package discipline is youkai's spine.
//
// After the monolith decision (ADR-004) there is no independent authority process
// to delegate to: youkai itself sends the target requests. So the discipline that
// used to live in Fairy - a scope passport, a per-request guard, rate limits,
// data minimisation, per-request audit, and a high-authorisation gate - has to
// live here, and it has to be the ONLY way out.
//
// Rules this package exists to make true:
//   - no scope, no request (ErrNoScope)
//   - an out-of-scope URL is refused before any bytes leave, and the refusal is
//     audited
//   - every request that does leave produces one audit row with a request_id
//   - responses are truncated to what a judgement needs; bodies never become
//     evidence
//   - redirects are re-checked hop by hop, and a hop leaving scope stops the
//     chain
//   - the dial layer re-checks the resolved address, so a hostname cannot resolve
//     its way into the private network behind the scope's back
package discipline

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
	"time"
)

// Common refusals. Callers are expected to surface these, not swallow them.
var (
	// ErrNoScope means no passport is loaded: nothing may happen.
	ErrNoScope = errors.New("discipline: no scope passport loaded")
	// ErrOutOfScope means the target is not covered by the passport.
	ErrOutOfScope = errors.New("discipline: target is outside the authorised scope")
	// ErrMethodNotAllowed means the HTTP method is not authorised.
	ErrMethodNotAllowed = errors.New("discipline: method not allowed by the scope")
	// ErrPrivateTarget means the target resolves into a private/loopback network
	// without the passport opting in.
	ErrPrivateTarget = errors.New("discipline: target resolves to a private address and the scope does not allow it")
	// ErrRateLimited means the passport's request budget is exhausted.
	ErrRateLimited = errors.New("discipline: rate limit exceeded")
	// ErrRequestBudget means the passport's total request budget is exhausted.
	ErrRequestBudget = errors.New("discipline: request budget exhausted")
	// ErrExpired means the passport is past its expiry.
	ErrExpired = errors.New("discipline: scope passport has expired")
)

// Scope is an authorisation passport. Nothing touches a target without one.
//
// It is deliberately boring data: no pointers, no defaults that "just work". A
// zero-valued Scope authorises nothing.
type Scope struct {
	// Project is the engagement directory/name this passport belongs to.
	Project string `json:"project"`
	// Include lists authorised targets: exact hosts, *.wildcard subdomains,
	// IPs, and CIDRs. Optional :port constrains the port.
	Include []string `json:"include"`
	// Exclude wins over Include.
	Exclude []string `json:"exclude"`
	// Methods is the authorised HTTP method set. Empty means read-only
	// (GET/HEAD/OPTIONS) - the safe default.
	Methods []string `json:"methods"`
	// AllowPrivate permits targets that resolve into private/loopback space.
	AllowPrivate bool `json:"allow_private"`
	// AllowActiveProbes enables tier-2 parameter probing capability.
	AllowActiveProbes bool `json:"allow_active_probes"`
	// AllowWAFProbe enables tier-2 WAF fingerprinting capability.
	AllowWAFProbe bool `json:"allow_waf_probe"`
	// AllowObjectSeeding enables tier-2 object seeding.
	AllowObjectSeeding bool `json:"allow_object_seeding"`
	// AllowAccountProvisioning enables tier-2 account provisioning.
	AllowAccountProvisioning bool `json:"allow_account_provisioning"`

	// Rate limiting and budgets.
	RPS         float64 `json:"rps"`
	MaxRequests int     `json:"max_requests"`
	// TimeoutMS bounds a single request.
	TimeoutMS int `json:"timeout_ms"`
	// MaxBytes truncates a response body; data minimisation by construction.
	MaxBytes int64 `json:"max_bytes"`
	// MaxRedirects bounds a redirect chain.
	MaxRedirects int `json:"max_redirects"`
	// MaxPages bounds crawls.
	MaxPages int `json:"max_pages"`
	// VerifyTLS refuses to connect to an invalid certificate when true.
	VerifyTLS bool `json:"verify_tls"`

	// Authority metadata: who authorised this, on what basis, until when.
	Basis     string    `json:"basis"`
	Operator  string    `json:"operator"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Defaults applied when the passport leaves a field empty.
const (
	defaultRPS          = 5
	defaultMaxRequests  = 2000
	defaultTimeoutMS    = 10000
	defaultMaxBytes     = 2 << 20
	defaultMaxRedirects = 5
	defaultMaxPages     = 40
)

// NewScope normalises a passport: fills safe defaults and uppercases methods.
func NewScope(s Scope) *Scope {
	if len(s.Methods) == 0 {
		s.Methods = []string{"GET", "HEAD", "OPTIONS"}
	}
	for i, m := range s.Methods {
		s.Methods[i] = strings.ToUpper(strings.TrimSpace(m))
	}
	if s.RPS <= 0 {
		s.RPS = defaultRPS
	}
	if s.MaxRequests <= 0 {
		s.MaxRequests = defaultMaxRequests
	}
	if s.TimeoutMS <= 0 {
		s.TimeoutMS = defaultTimeoutMS
	}
	if s.MaxBytes <= 0 {
		s.MaxBytes = defaultMaxBytes
	}
	if s.MaxRedirects <= 0 {
		s.MaxRedirects = defaultMaxRedirects
	}
	if s.MaxPages <= 0 {
		s.MaxPages = defaultMaxPages
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	return &s
}

// Validate refuses passports that would authorise everything or nothing.
func (s *Scope) Validate() error {
	if s == nil {
		return ErrNoScope
	}
	if strings.TrimSpace(s.Basis) == "" || len([]rune(s.Basis)) < 8 {
		return fmt.Errorf("scope: basis must be at least 8 characters (say what authorises this)")
	}
	if strings.TrimSpace(s.Operator) == "" {
		return fmt.Errorf("scope: operator is required")
	}
	if len(s.Include) == 0 {
		return fmt.Errorf("scope: include must name at least one target")
	}
	for _, raw := range s.Include {
		if err := validatePattern(raw); err != nil {
			return fmt.Errorf("scope: include %q: %w", raw, err)
		}
	}
	for _, raw := range s.Exclude {
		if err := validatePattern(raw); err != nil {
			return fmt.Errorf("scope: exclude %q: %w", raw, err)
		}
	}
	if !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(time.Now()) {
		return ErrExpired
	}
	return nil
}

func validatePattern(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("empty target")
	}
	if raw == "*" || raw == "*.*" {
		return fmt.Errorf("refusing a top-level wildcard")
	}
	// Reject "*.com" style wildcards: a wildcard must leave at least two labels
	// after the dot, otherwise it authorises a whole TLD.
	if strings.HasPrefix(raw, "*.") {
		rest := strings.TrimPrefix(raw, "*.")
		if strings.Count(rest, ".") < 1 {
			return fmt.Errorf("wildcard must cover a domain, not a TLD")
		}
	}
	return nil
}

// Expired reports whether the passport has run out.
func (s *Scope) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt)
}

// MethodAllowed reports whether the HTTP method is authorised.
// HEAD and OPTIONS are always allowed: they cannot change state.
func (s *Scope) MethodAllowed(method string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	if m == "HEAD" || m == "OPTIONS" {
		return true
	}
	for _, allowed := range s.Methods {
		if strings.EqualFold(allowed, m) {
			return true
		}
	}
	return false
}

// Decision is the passport's opinion about one target.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	// Matched is the include pattern that authorised the target.
	Matched string `json:"matched,omitempty"`
	// Private is true when the target is loopback/private space.
	Private bool `json:"private"`
	// Host and Port are the parsed target authority.
	Host string `json:"host"`
	Port string `json:"port"`
}

// Check decides whether a URL may be requested.
//
// It does not resolve DNS (the dial layer does that, so a rebinding hostname
// cannot slip past), but it does classify literal addresses.
func (s *Scope) Check(rawURL string) (Decision, error) {
	if s == nil {
		return Decision{}, ErrNoScope
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return Decision{}, fmt.Errorf("scope: parse %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Decision{}, fmt.Errorf("scope: scheme %q is not http(s)", u.Scheme)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return Decision{}, fmt.Errorf("scope: url has no host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	d := Decision{Host: host, Port: port}
	d.Private = isLiteralPrivate(host)

	// Exclusions first: they always win.
	for _, pat := range s.Exclude {
		if patternMatches(pat, host, port) {
			d.Reason = "excluded by pattern " + pat
			return d, fmt.Errorf("%w (excluded by %s)", ErrOutOfScope, pat)
		}
	}
	for _, pat := range s.Include {
		if patternMatches(pat, host, port) {
			d.Allowed = true
			d.Matched = pat
			d.Reason = "authorised by " + pat
			if d.Private && !s.AllowPrivate {
				d.Allowed = false
				d.Reason = "target is loopback/private but allow_private is false"
				return d, ErrPrivateTarget
			}
			return d, nil
		}
	}
	d.Reason = "no include pattern matches this target"
	return d, fmt.Errorf("%w: %s:%s", ErrOutOfScope, host, port)
}

// patternMatches applies one include/exclude pattern to a host:port.
func patternMatches(pattern, host, port string) bool {
	pat := strings.ToLower(strings.TrimSpace(pattern))
	if pat == "" {
		return false
	}
	// Strip scheme if someone wrote one.
	if i := strings.Index(pat, "://"); i >= 0 {
		pat = pat[i+3:]
	}
	// CIDR first: its slash is not a path separator.
	if strings.Contains(pat, "/") {
		if _, network, err := net.ParseCIDR(pat); err == nil {
			ip := net.ParseIP(host)
			return ip != nil && network.Contains(ip)
		}
	}
	if i := strings.IndexByte(pat, '/'); i >= 0 {
		pat = pat[:i]
	}
	wantPort := ""
	if h, p, err := net.SplitHostPort(pat); err == nil {
		pat, wantPort = h, p
	}
	if wantPort != "" && wantPort != port {
		return false
	}
	// Wildcard subdomain: *.example.com matches a.example.com, not example.com.
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return host == pat
}

// isLiteralPrivate classifies a literal address. Names are resolved later, at
// dial time.
func isLiteralPrivate(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return isPrivateIP(ip)
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// 100.64.0.0/10 (CGNAT) and 0.0.0.0/8 are also not publicly routable.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 0 {
			return true
		}
	}
	return false
}

// HostOf reduces a URL to its host, for asset keys.
func HostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// BaseOf reduces a URL to scheme://host[:port], for grouping.
func BaseOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// CapabilitiesUnlocked reports which tier-2 capabilities this passport unlocks.
// The gate still decides; the passport only says what the human allowed.
func (s *Scope) CapabilitiesUnlocked() []string {
	if s == nil {
		return nil
	}
	var out []string
	if s.AllowActiveProbes {
		out = append(out, "param", "param_adaptive")
	}
	if s.AllowWAFProbe {
		out = append(out, "waf")
	}
	if s.AllowObjectSeeding {
		out = append(out, "object_seed")
	}
	if s.AllowAccountProvisioning {
		out = append(out, "account_register")
	}
	return out
}

// CleanPath normalises a URL path for exposure checks.
func CleanPath(p string) string {
	if p == "" {
		return "/"
	}
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	return clean
}

// NamesHost reports whether any include pattern names this host, ignoring the
// port. Used by the dial layer: the port was already validated at URL level, and
// a connection has no port to compare in the same way a pattern might.
func (s *Scope) NamesHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range s.Exclude {
		if patternMatchesHostOnly(pat, host) {
			return false
		}
	}
	for _, pat := range s.Include {
		if patternMatchesHostOnly(pat, host) {
			return true
		}
	}
	return false
}

// patternMatchesHostOnly applies a pattern to a host with the port ignored.
func patternMatchesHostOnly(pattern, host string) bool {
	pat := strings.ToLower(strings.TrimSpace(pattern))
	if i := strings.Index(pat, "://"); i >= 0 {
		pat = pat[i+3:]
	}
	// CIDR first: its slash is not a path separator.
	if strings.Contains(pat, "/") {
		if _, network, err := net.ParseCIDR(pat); err == nil {
			ip := net.ParseIP(host)
			return ip != nil && network.Contains(ip)
		}
	}
	if i := strings.IndexByte(pat, '/'); i >= 0 {
		pat = pat[:i]
	}
	if h, _, err := net.SplitHostPort(pat); err == nil {
		pat = h
	}
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:]
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return host == pat
}
