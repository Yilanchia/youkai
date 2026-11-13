// Package accounts is youkai's identity layer: the fuel for BOLA/IDOR/BFLA.
//
// Fairy's design is preserved, minus the file-format quirks:
//
//   - The operator writes a manifest (accounts.json). Passwords come from
//     environment variables, never from the manifest if we can help it, and never
//     from the ledger.
//   - Provisioning logs each identity in ONCE, through a per-identity clone of the
//     guard (so cookie jars cannot bleed), and stores the resulting session
//     encrypted at rest. No retry, no dictionary, no guessing.
//   - Ownership is declared by the operator or seeded with a minimal object the
//     account itself creates. youkai never invents an owner.
//   - Show() returns names, roles, markers and session readiness. It never returns
//     a cookie, a token, or a password.
//   - Everything that writes to a target (login, object seeding, registration) is
//     tier 2: the autonomous engine never dispatches it, and each one needs a
//     human approval through the workbench.
package accounts

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Schema is the manifest format version.
const Schema = "YoukaiAccounts/v1"

// Manifest is the operator-authored identity list.
type Manifest struct {
	Schema   string    `json:"schema"`
	BaseURL  string    `json:"base_url,omitempty"`
	Accounts []Account `json:"accounts"`
	// Warnings are non-fatal problems found while loading (plaintext passwords,
	// loose file permissions). They are surfaced, never swallowed.
	Warnings []string `json:"-"`
	Path     string   `json:"-"`
}

// Account is one identity.
type Account struct {
	Name  string      `json:"name"`
	Role  string      `json:"role"`
	Login LoginSpec   `json:"login"`
	Owns  []Ownership `json:"owns,omitempty"`
	Seed  *SeedSpec   `json:"seed,omitempty"`
}

// LoginSpec describes the single login attempt.
type LoginSpec struct {
	URL         string            `json:"url"`
	Method      string            `json:"method,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
	PasswordEnv string            `json:"password_env,omitempty"`
	// Password is accepted only for throwaway labs; a warning is always raised.
	Password   string `json:"password,omitempty"`
	TokenField string `json:"token_field,omitempty"`
	JSON       bool   `json:"json,omitempty"`
}

// Credential returns the password and where it came from.
func (l LoginSpec) Credential() (string, string, error) {
	if strings.TrimSpace(l.PasswordEnv) != "" {
		v := os.Getenv(strings.TrimSpace(l.PasswordEnv))
		if strings.TrimSpace(v) == "" {
			return "", "", fmt.Errorf("缺少环境变量 %s", l.PasswordEnv)
		}
		return v, "env:" + l.PasswordEnv, nil
	}
	if strings.TrimSpace(l.Password) != "" {
		return l.Password, "manifest(明文,不推荐)", nil
	}
	return "", "", fmt.Errorf("缺少 password_env(或在一次性靶场里用 password)")
}

// Ownership is an object the operator declares this identity owns.
type Ownership struct {
	Marker string `json:"marker"`
	URL    string `json:"url"`
	Note   string `json:"note,omitempty"`
}

// SeedSpec describes the minimal object the identity creates for itself.
type SeedSpec struct {
	Create     SeedCreate  `json:"create"`
	Extract    SeedExtract `json:"extract,omitempty"`
	MarkerPath string      `json:"marker_path,omitempty"`
	Marker     string      `json:"marker,omitempty"`
	ItemURL    string      `json:"item_url,omitempty"`
	Note       string      `json:"note,omitempty"`
}

// SeedCreate is the single create request.
type SeedCreate struct {
	URL    string            `json:"url"`
	Method string            `json:"method,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
	JSON   bool              `json:"json,omitempty"`
}

// SeedExtract pulls the new object's identifier out of the response.
type SeedExtract struct {
	From    string `json:"from,omitempty"` // "json" (default) | "regex"
	Path    string `json:"path,omitempty"` // dotted path for json
	Pattern string `json:"pattern,omitempty"`
}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// Load reads and validates a manifest.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("accounts: 读取清单 %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("accounts: 解析 %s: %w", path, err)
	}
	m.Path = path
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil {
		if info.Mode().Perm()&0o077 != 0 {
			m.Warnings = append(m.Warnings, fmt.Sprintf(
				"%s 权限过宽(%03o);建议收紧到 600:它描述了测试账号的登录入口",
				filepath.Base(path), info.Mode().Perm()))
		}
	}
	return &m, nil
}

// Validate refuses manifests that could not be provisioned unambiguously.
func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("accounts: 空清单")
	}
	if m.Schema != Schema {
		return fmt.Errorf("accounts: schema 不匹配(%q,期望 %q)", m.Schema, Schema)
	}
	if len(m.Accounts) == 0 {
		return fmt.Errorf("accounts: 至少需要一个账号")
	}
	seen := map[string]bool{}
	for i := range m.Accounts {
		a := &m.Accounts[i]
		a.Name = strings.TrimSpace(a.Name)
		if !nameRe.MatchString(a.Name) {
			return fmt.Errorf("accounts: account.name 不合法:%q(只允许字母/数字/下划线/短横线)", a.Name)
		}
		if seen[a.Name] {
			return fmt.Errorf("accounts: account.name 重复:%s", a.Name)
		}
		seen[a.Name] = true
		if a.Role = strings.TrimSpace(a.Role); a.Role == "" {
			a.Role = "user"
		}
		if strings.TrimSpace(a.Login.URL) == "" {
			return fmt.Errorf("accounts: %s 缺少 login.url", a.Name)
		}
		if a.Login.Password == "" && a.Login.PasswordEnv == "" {
			return fmt.Errorf("accounts: %s 缺少 password_env(推荐)或 password", a.Name)
		}
		if a.Login.Password != "" && a.Login.PasswordEnv == "" {
			m.Warnings = append(m.Warnings, fmt.Sprintf("%s 使用清单里的明文 password;建议改用 password_env", a.Name))
		}
		cleaned := make([]Ownership, 0, len(a.Owns))
		for _, own := range a.Owns {
			own.Marker = strings.TrimSpace(own.Marker)
			own.URL = strings.TrimSpace(own.URL)
			if own.Marker == "" || own.URL == "" {
				m.Warnings = append(m.Warnings, fmt.Sprintf("%s 有一条 owns 缺少 marker 或 url,已忽略", a.Name))
				continue
			}
			own.Note = truncate(own.Note, 200)
			cleaned = append(cleaned, own)
		}
		a.Owns = cleaned
	}
	return nil
}

// Account looks an account up by name.
func (m *Manifest) Account(name string) (Account, bool) {
	for _, a := range m.Accounts {
		if a.Name == name {
			return a, true
		}
	}
	return Account{}, false
}

// Names lists account names in manifest order.
func (m *Manifest) Names() []string {
	out := make([]string, 0, len(m.Accounts))
	for _, a := range m.Accounts {
		out = append(out, a.Name)
	}
	return out
}

// Base returns the base URL for relative ownership URLs.
func (m *Manifest) Base(a Account) string {
	if strings.TrimSpace(m.BaseURL) != "" {
		return strings.TrimRight(m.BaseURL, "/")
	}
	u, err := parseOrigin(a.Login.URL)
	if err != nil {
		return ""
	}
	return u
}

// Pair is one BOLA comparison: the owner's object read by another identity.
type Pair struct {
	Owner  string         `json:"owner"`
	Viewer string         `json:"viewer"`
	Marker string         `json:"marker"`
	URL    string         `json:"url"`
	Action string         `json:"action"`
	Args   map[string]any `json:"args"`
	Note   string         `json:"note"`
}

// BolaPairs derives compare actions from declared ownership.
//
// It never guesses an owner: a pair exists only because the operator (or the
// seeding step) said "this identity owns this object". The comparison itself is
// tier 1 (two read-only GETs), so the engine may run it unattended.
func (m *Manifest) BolaPairs() []Pair {
	var out []Pair
	seen := map[string]bool{}
	for _, owner := range m.Accounts {
		if len(owner.Owns) == 0 {
			continue
		}
		base := m.Base(owner)
		for _, own := range owner.Owns {
			u := own.URL
			if base != "" && !strings.Contains(u, "://") {
				u = base + "/" + strings.TrimLeft(u, "/")
			}
			for _, viewer := range m.Accounts {
				if viewer.Name == owner.Name {
					continue
				}
				key := owner.Name + "|" + viewer.Name + "|" + own.Marker + "|" + u
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Pair{
					Owner: owner.Name, Viewer: viewer.Name,
					Marker: own.Marker, URL: u, Action: "compare",
					Args: map[string]any{
						"url": u, "session_a": owner.Name, "session_b": viewer.Name, "marker": own.Marker,
					},
					Note: fmt.Sprintf("BOLA: %s 的对象 %s,换 %s 读取", owner.Name, own.Marker, viewer.Name),
				})
			}
		}
	}
	return out
}

// AccountsJSON is the shape the API returns for the UI: no secrets.
type ShowAccount struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Owns         []string `json:"owns"`
	SessionReady bool     `json:"session_ready"`
}

// Show is the redacted view.
type Show struct {
	Path       string        `json:"path"`
	Schema     string        `json:"schema"`
	BaseURL    string        `json:"base_url,omitempty"`
	Accounts   []ShowAccount `json:"accounts"`
	BolaPairs  []Pair        `json:"bola_pairs"`
	Warnings   []string      `json:"warnings,omitempty"`
	SessionDir string        `json:"session_dir,omitempty"`
}

func parseOrigin(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("no host")
	}
	return u.Scheme + "://" + u.Host, nil
}

// Loaded is a convenience for callers that already have a path and tolerate a
// missing manifest (returns nil, nil) so the UI can render "no manifest yet".
func Loaded(path string) (*Manifest, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return Load(path)
}

// DefaultPath is the conventional manifest location.
const DefaultPath = ".youkai/accounts.json"

// Now is injectable for tests.
var Now = func() time.Time { return time.Now().UTC() }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
