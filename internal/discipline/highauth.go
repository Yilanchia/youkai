package discipline

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// HighAuthKeyEnv is the environment variable holding the high-authorisation key.
// The key never enters youkai's config, database, or logs - a human exports it.
const HighAuthKeyEnv = "FAIRY_AUTH_KEY"

// HighAuthSchema is the record format youkai verifies.
const HighAuthSchema = "FairyHighAuth/v1"

// HighAuth is a signed authorisation record.
//
// youkai VERIFIES these; it never creates one. That asymmetry is the point: the
// key lives with the human, so "youkai approved itself" is not representable.
type HighAuth struct {
	Schema    string         `json:"schema"`
	Payload   map[string]any `json:"payload"`
	Signature string         `json:"signature"`
}

// HighAuthGrant is the verified contents.
type HighAuthGrant struct {
	Tier      string    `json:"tier"`
	Basis     string    `json:"basis"`
	Approver  string    `json:"approver"`
	Assets    []string  `json:"assets"`
	Actions   []string  `json:"actions"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Nonce     string    `json:"nonce"`
	Path      string    `json:"-"`
}

// KeyFromEnv loads the verification key.
func KeyFromEnv() (string, error) {
	v := strings.TrimSpace(os.Getenv(HighAuthKeyEnv))
	if len(v) < 16 {
		return "", fmt.Errorf("high-auth: %s must be set and at least 16 characters", HighAuthKeyEnv)
	}
	return v, nil
}

// LoadHighAuth reads a record without verifying it.
func LoadHighAuth(path string) (*HighAuth, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("high-auth: read %s: %w", path, err)
	}
	var h HighAuth
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("high-auth: parse %s: %w", path, err)
	}
	return &h, nil
}

// Verify checks the signature, the schema, and the expiry, and returns the grant.
//
// Canonicalisation matches Fairy's `JSON.stringify(payload, Object.keys(payload).sort())`:
// sorted top-level keys, no HTML escaping, compact separators. Fairy-created
// records therefore verify here without conversion.
func (h *HighAuth) Verify(key string, now time.Time) (*HighAuthGrant, error) {
	if h == nil {
		return nil, fmt.Errorf("high-auth: empty record")
	}
	if h.Schema != HighAuthSchema {
		return nil, fmt.Errorf("high-auth: unexpected schema %q", h.Schema)
	}
	if len(h.Payload) == 0 {
		return nil, fmt.Errorf("high-auth: empty payload")
	}
	canonical, err := canonicalJSON(h.Payload)
	if err != nil {
		return nil, fmt.Errorf("high-auth: canonicalise payload: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))
	got := strings.ToLower(strings.TrimSpace(h.Signature))
	if !hmac.Equal([]byte(want), []byte(got)) {
		return nil, fmt.Errorf("high-auth: signature does not verify")
	}

	g := &HighAuthGrant{
		Tier:     stringField(h.Payload, "tier"),
		Basis:    stringField(h.Payload, "basis"),
		Approver: stringField(h.Payload, "approver"),
		Assets:   stringSlice(h.Payload["assets"]),
		Actions:  stringSlice(h.Payload["actions"]),
		Nonce:    stringField(h.Payload, "nonce"),
	}
	g.IssuedAt, _ = time.Parse(time.RFC3339, stringField(h.Payload, "issued_at"))
	g.ExpiresAt, _ = time.Parse(time.RFC3339, stringField(h.Payload, "expires_at"))

	if g.Basis == "" || len([]rune(g.Basis)) < 8 {
		return nil, fmt.Errorf("high-auth: basis must say what authorises this (>=8 chars)")
	}
	if g.Approver == "" {
		return nil, fmt.Errorf("high-auth: approver is required")
	}
	if len(g.Assets) == 0 {
		return nil, fmt.Errorf("high-auth: no authorised assets")
	}
	if len(g.Actions) == 0 {
		return nil, fmt.Errorf("high-auth: no authorised actions")
	}
	// High auth is read-only by construction. A record asking for more is not a
	// record this build will honour.
	for _, a := range g.Actions {
		if !strings.EqualFold(a, "read-only") {
			return nil, fmt.Errorf("high-auth: action %q is not permitted (only read-only)", a)
		}
	}
	if !g.ExpiresAt.IsZero() && now.After(g.ExpiresAt) {
		return nil, fmt.Errorf("high-auth: expired at %s", g.ExpiresAt.Format(time.RFC3339))
	}
	if g.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("high-auth: no expiry (refusing an open-ended authorisation)")
	}
	return g, nil
}

// Covers reports whether the grant names this target.
//
// A grant's `assets` are written by a human (or by Fairy's createHighAuth), so they
// arrive in whatever shape felt natural: a bare host, a host:port, a URL, a
// wildcard, a CIDR. Normalising both sides here is what makes "the operator
// authorised 127.0.0.1" cover "the action targets http://127.0.0.1:9/x".
func (g *HighAuthGrant) Covers(target string) bool {
	host, authority := splitTarget(target)
	if host == "" {
		return false
	}
	for _, raw := range g.Assets {
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
		if strings.Contains(pat, "/") { // CIDR
			if _, network, err := net.ParseCIDR(pat); err == nil {
				if ip := net.ParseIP(host); ip != nil && network.Contains(ip) {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:]
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
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

// splitTarget returns (hostname, host:port) for a URL, a host, or a path.
func splitTarget(target string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return "", ""
	}
	if i := strings.Index(t, "://"); i >= 0 {
		u, err := url.Parse(t)
		if err == nil && u.Host != "" {
			return strings.TrimSuffix(u.Hostname(), "."), u.Host
		}
	}
	// A bare authority, possibly with a port.
	if h, p, err := net.SplitHostPort(t); err == nil {
		return h, h + ":" + p
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	return t, t
}

// canonicalJSON reproduces JavaScript's JSON.stringify with sorted keys and no
// HTML escaping.
func canonicalJSON(m map[string]any) (string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshalNoEscape(k)
		if err != nil {
			return "", err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalNoEscape(m[k])
		if err != nil {
			return "", err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.String(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

func stringField(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		if ss, ok := v.([]string); ok {
			return ss
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---- mandates (ADR-005) ----------------------------------------------------
//
// A mandate is the same signed record, read with a wider (but still closed) action
// vocabulary: "read-only" plus "tier2:<class>". It is deliberately a SEPARATE
// entry point from Verify: a per-step approval must not silently become a
// standing authorisation because the parser got looser.

// MandateActionPrefix marks a pre-authorised tier-2 class inside `actions`.
const MandateActionPrefix = "tier2:"

// MandateAction builds the action string for one class.
func MandateAction(class string) string { return MandateActionPrefix + class }

// VerifyMandate verifies a mandate record and returns the classes it covers.
//
// Differences from Verify, and only these:
//   - `actions` may contain "tier2:<class>" for a class in knownClasses;
//   - at least one action is still required;
//   - the record must name the assets it applies to.
//
// Everything else - signature, basis length, approver, expiry, no open-ended
// grants - is identical, because it is the same signature over the same payload.
func (h *HighAuth) VerifyMandate(key string, now time.Time, knownClasses []string) (*HighAuthGrant, []string, error) {
	if h == nil {
		return nil, nil, fmt.Errorf("high-auth: empty record")
	}
	if h.Schema != HighAuthSchema {
		return nil, nil, fmt.Errorf("high-auth: unexpected schema %q", h.Schema)
	}
	if len(h.Payload) == 0 {
		return nil, nil, fmt.Errorf("high-auth: empty payload")
	}
	canonical, err := canonicalJSON(h.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("high-auth: canonicalise payload: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))
	got := strings.ToLower(strings.TrimSpace(h.Signature))
	if !hmac.Equal([]byte(want), []byte(got)) {
		return nil, nil, fmt.Errorf("high-auth: signature does not verify")
	}

	g := &HighAuthGrant{
		Tier:     stringField(h.Payload, "tier"),
		Basis:    stringField(h.Payload, "basis"),
		Approver: stringField(h.Payload, "approver"),
		Assets:   stringSlice(h.Payload["assets"]),
		Actions:  stringSlice(h.Payload["actions"]),
		Nonce:    stringField(h.Payload, "nonce"),
	}
	g.IssuedAt, _ = time.Parse(time.RFC3339, stringField(h.Payload, "issued_at"))
	g.ExpiresAt, _ = time.Parse(time.RFC3339, stringField(h.Payload, "expires_at"))

	if g.Basis == "" || len([]rune(g.Basis)) < 8 {
		return nil, nil, fmt.Errorf("high-auth: basis must say what authorises this (>=8 chars)")
	}
	if g.Approver == "" {
		return nil, nil, fmt.Errorf("high-auth: approver is required")
	}
	if len(g.Assets) == 0 {
		return nil, nil, fmt.Errorf("high-auth: no authorised assets")
	}
	if len(g.Actions) == 0 {
		return nil, nil, fmt.Errorf("high-auth: no authorised actions")
	}
	if g.ExpiresAt.IsZero() {
		return nil, nil, fmt.Errorf("high-auth: no expiry (refusing an open-ended authorisation)")
	}
	if now.After(g.ExpiresAt) {
		return nil, nil, fmt.Errorf("high-auth: expired at %s", g.ExpiresAt.Format(time.RFC3339))
	}

	known := map[string]bool{}
	for _, c := range knownClasses {
		known[strings.ToLower(strings.TrimSpace(c))] = true
	}
	var classes []string
	for _, a := range g.Actions {
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "read-only" {
			continue
		}
		if !strings.HasPrefix(la, MandateActionPrefix) {
			return nil, nil, fmt.Errorf("high-auth: action %q is not permitted in a mandate", a)
		}
		class := strings.TrimPrefix(la, MandateActionPrefix)
		if !known[class] {
			return nil, nil, fmt.Errorf("high-auth: unknown autonomy class %q", class)
		}
		classes = append(classes, class)
	}
	return g, classes, nil
}

// CanonicalPayload exposes the exact bytes a signature covers.
//
// Exported so tests (and anyone re-verifying a stored mandate offline) can compute
// the same digest without re-implementing the rules. It is NOT a signer: no key is
// involved, and nothing in youkaid calls it on the signing side.
func CanonicalPayload(m map[string]any) (string, error) { return canonicalJSON(m) }
