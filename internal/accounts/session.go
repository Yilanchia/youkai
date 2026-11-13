package accounts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Sessions are the most sensitive artefact youkai holds: a live login for a test
// identity. They are therefore:
//
//   - encrypted at rest (AES-256-GCM, scrypt-derived key) whenever a session key
//     is configured, and base64 + a loud warning when it is not;
//   - written 0600 into their own directory, never inside the ledger;
//   - only ever described by name/enc/updated_at. No function here returns a
//     cookie value to a caller that is not about to send a request with it.
const (
	SessionSchema = "YoukaiSession/v1"

	EnvSessionKey = "YOUKAI_SESSION_KEY"
	// EnvSessionKeyCompat lets an operator reuse Fairy's key name.
	EnvSessionKeyCompat = "FAIRY_SESSION_KEY"
)

// Session is a decrypted login: headers to attach to a request.
type Session struct {
	Name      string            `json:"name"`
	Headers   map[string]string `json:"headers"`
	Note      string            `json:"note,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	Enc       string            `json:"enc"`
}

// SessionInfo is the redacted listing entry.
type SessionInfo struct {
	Name      string    `json:"name"`
	Enc       string    `json:"enc"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SessionStore persists sessions under one directory.
type SessionStore struct {
	Dir string
	key []byte
	// Keyed reports whether sessions are encrypted at rest.
	Keyed bool
}

// NewSessionStore opens (and creates) a session directory.
func NewSessionStore(dir string) (*SessionStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("accounts: session dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("accounts: create session dir: %w", err)
	}
	s := &SessionStore{Dir: dir}
	if pass := sessionPassphrase(); len(pass) >= 8 {
		s.key = []byte(pass)
		s.Keyed = true
	}
	return s, nil
}

// Keyed reports whether a session key was configured.
func (s *SessionStore) keyed() bool { return s != nil && s.Keyed }

func sessionPassphrase() string {
	for _, name := range []string{EnvSessionKey, EnvSessionKeyCompat} {
		if v := strings.TrimSpace(os.Getenv(name)); len(v) >= 8 {
			return v
		}
	}
	return ""
}

func (s *SessionStore) path(name string) (string, error) {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
	if safe == "" {
		return "", fmt.Errorf("accounts: session 名不能为空")
	}
	if len(safe) > 64 {
		safe = safe[:64]
	}
	return filepath.Join(s.Dir, safe+".json"), nil
}

type sessionRecord struct {
	Schema    string    `json:"schema"`
	Name      string    `json:"name"`
	Enc       string    `json:"enc"`
	Salt      string    `json:"salt,omitempty"`
	IV        string    `json:"iv,omitempty"`
	Tag       string    `json:"tag,omitempty"`
	Data      string    `json:"data"`
	UpdatedAt time.Time `json:"updated_at"`
	Warning   string    `json:"warning,omitempty"`
}

// Save stores a session. The headers map is the only thing persisted.
func (s *SessionStore) Save(name string, headers map[string]string, note string) (SessionInfo, error) {
	if len(headers) == 0 {
		return SessionInfo{}, fmt.Errorf("accounts: 不保存空会话(%s)", name)
	}
	body, err := json.Marshal(Session{
		Name: name, Headers: headers, Note: truncate(note, 300),
		CreatedAt: Now(), Enc: "",
	})
	if err != nil {
		return SessionInfo{}, err
	}

	rec := sessionRecord{Schema: SessionSchema, Name: name, UpdatedAt: Now()}
	if s.keyed() {
		salt := make([]byte, 16)
		iv := make([]byte, 12)
		if _, err := rand.Read(salt); err != nil {
			return SessionInfo{}, err
		}
		if _, err := rand.Read(iv); err != nil {
			return SessionInfo{}, err
		}
		key, err := scrypt.Key(s.key, salt, 1<<14, 8, 1, 32)
		if err != nil {
			return SessionInfo{}, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return SessionInfo{}, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return SessionInfo{}, err
		}
		sealed := gcm.Seal(nil, iv, body, []byte(name))
		rec.Enc = "aes-256-gcm"
		rec.Salt = base64.StdEncoding.EncodeToString(salt)
		rec.IV = base64.StdEncoding.EncodeToString(iv)
		rec.Tag = base64.StdEncoding.EncodeToString(sealed[len(sealed)-gcm.Overhead():])
		rec.Data = base64.StdEncoding.EncodeToString(sealed[:len(sealed)-gcm.Overhead()])
	} else {
		rec.Enc = "none"
		rec.Data = base64.StdEncoding.EncodeToString(body)
		rec.Warning = "未设置 " + EnvSessionKey + ":会话仅 base64 存放(等同明文)。真实目标请设置密钥。"
	}

	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return SessionInfo{}, err
	}
	file, err := s.path(name)
	if err != nil {
		return SessionInfo{}, err
	}
	if err := os.WriteFile(file, append(raw, '\n'), 0o600); err != nil {
		return SessionInfo{}, fmt.Errorf("accounts: write session: %w", err)
	}
	return SessionInfo{Name: name, Enc: rec.Enc, UpdatedAt: rec.UpdatedAt}, nil
}

// Load decrypts a session.
func (s *SessionStore) Load(name string) (Session, error) {
	file, err := s.path(name)
	if err != nil {
		return Session{}, err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return Session{}, fmt.Errorf("accounts: session %q 不存在(先 provision)", name)
	}
	var rec sessionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Session{}, fmt.Errorf("accounts: session %q 解析失败: %w", name, err)
	}
	if rec.Schema != SessionSchema {
		return Session{}, fmt.Errorf("accounts: session %q schema 不匹配(%q)", name, rec.Schema)
	}

	var body []byte
	switch rec.Enc {
	case "aes-256-gcm":
		if !s.keyed() {
			return Session{}, fmt.Errorf("accounts: session %q 已加密,请设置 %s(≥8 字符)", name, EnvSessionKey)
		}
		salt, err1 := base64.StdEncoding.DecodeString(rec.Salt)
		iv, err2 := base64.StdEncoding.DecodeString(rec.IV)
		tag, err3 := base64.StdEncoding.DecodeString(rec.Tag)
		data, err4 := base64.StdEncoding.DecodeString(rec.Data)
		if err := firstErr(err1, err2, err3, err4); err != nil {
			return Session{}, fmt.Errorf("accounts: session %q 已损坏: %w", name, err)
		}
		key, err := scrypt.Key(s.key, salt, 1<<14, 8, 1, 32)
		if err != nil {
			return Session{}, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return Session{}, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return Session{}, err
		}
		plain, err := gcm.Open(nil, iv, append(data, tag...), []byte(name))
		if err != nil {
			return Session{}, fmt.Errorf("accounts: session %q 解密失败:密钥不对或文件被改动", name)
		}
		body = plain
	case "none":
		plain, err := base64.StdEncoding.DecodeString(rec.Data)
		if err != nil {
			return Session{}, fmt.Errorf("accounts: session %q 已损坏: %w", name, err)
		}
		body = plain
	default:
		return Session{}, fmt.Errorf("accounts: session %q 未知加密方式 %q", name, rec.Enc)
	}

	var sess Session
	if err := json.Unmarshal(body, &sess); err != nil {
		return Session{}, fmt.Errorf("accounts: session %q 内容损坏: %w", name, err)
	}
	sess.Enc = rec.Enc
	return sess, nil
}

// List returns redacted entries, sorted by name.
func (s *SessionStore) List() ([]SessionInfo, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []SessionInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			continue
		}
		var rec sessionRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		out = append(out, SessionInfo{Name: rec.Name, Enc: rec.Enc, UpdatedAt: rec.UpdatedAt})
	}
	return out, nil
}

// Ready reports whether a session exists for the name.
func (s *SessionStore) Ready(name string) bool {
	file, err := s.path(name)
	if err != nil {
		return false
	}
	_, statErr := os.Stat(file)
	return statErr == nil
}

// Delete removes a session (used when the operator revokes an identity).
func (s *SessionStore) Delete(name string) error {
	file, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Fingerprint is a short, non-secret identifier for a header set, used in facts so
// evidence can distinguish sessions without revealing them.
func Fingerprint(headers map[string]string) string {
	h := sha256.New()
	for _, k := range sortedKeys(headers) {
		h.Write([]byte(k))
		h.Write([]byte{0x1f})
		h.Write([]byte(headers[k]))
		h.Write([]byte{0x1e})
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
