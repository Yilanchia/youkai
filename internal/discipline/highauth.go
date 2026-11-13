package discipline

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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

// Covers reports whether the grant names this target (host or host:port).
func (g *HighAuthGrant) Covers(target string) bool {
	host := HostOf(target)
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(target))
	}
	for _, a := range g.Assets {
		pat := strings.ToLower(strings.TrimSpace(a))
		if pat == "" {
			continue
		}
		if pat == host {
			return true
		}
		if strings.HasPrefix(pat, "*.") && strings.HasSuffix(host, pat[1:]) {
			return true
		}
		if strings.Contains(pat, "/") {
			if _, network, err := net.ParseCIDR(pat); err == nil {
				if ip := net.ParseIP(host); ip != nil && network.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
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
