// Package config is the platform's runtime configuration layer.
//
// Before this package the only way to change how youkai talks to a model was an
// environment variable and a restart. The UI could show `enabled: true` but not
// change anything. This package adds a small persisted settings store:
//
//	key      TEXT PRIMARY KEY     -- 'llm'
//	value    JSONB                -- base_url, model, temperature, ... (not secret)
//	secret_enc BYTEA              -- AES-256-GCM blob for the API key
//
// Two rules shape every function here:
//
//   - A secret is NEVER returned by the read path. Get() reports only whether one
//     exists; the plaintext is available to the server through GetSecret, which is
//     for building a client, not for answering an HTTP request.
//   - A secret is NEVER stored unencrypted. Without a session passphrase, Put()
//     refuses instead of degrading - an LLM key is usually a paid credential, so
//     this is stricter than the session store's "base64 with a warning".
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"youkai/internal/secretbox"
)

// Keys of the settings table.
const (
	KeyLLM = "llm"
)

// ErrSecretWithoutKey is returned when a caller tries to store a secret while no
// passphrase is configured.
var ErrSecretWithoutKey = errors.New(
	"config: 没有会话密钥,拒绝保存 secret:请设置 YOUKAI_SESSION_KEY(≥8 字符),或改用 key_from_env 只存环境变量名")

// ErrNotFound means the setting has never been written.
var ErrNotFound = errors.New("config: setting not found")

// Store is the settings repository.
type Store struct {
	pool *pgxpool.Pool
	// passphrase encrypts secrets; nil means "secrets cannot be stored".
	passphrase []byte
}

// New builds a store. passphrase may be nil (secrets will be refused).
func New(pool *pgxpool.Pool, passphrase []byte) *Store {
	return &Store{pool: pool, passphrase: passphrase}
}

// NewFromLedger builds a store on the ledger's pool.
func NewFromLedger(pool *pgxpool.Pool, passphrase []byte) *Store { return New(pool, passphrase) }

// CanStoreSecrets reports whether a passphrase is configured.
func (s *Store) CanStoreSecrets() bool { return s != nil && len(s.passphrase) > 0 }

// Get returns the non-secret value and whether a secret blob exists.
//
// It never returns the secret, not even encrypted: an API response must not carry
// something an attacker could try to crack offline.
func (s *Store) Get(ctx context.Context, key string) (json.RawMessage, bool, error) {
	var raw []byte
	var hasSecret bool
	err := s.pool.QueryRow(ctx,
		`SELECT value, secret_enc IS NOT NULL FROM settings WHERE key = $1`, key).
		Scan(&raw, &hasSecret)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrNotFound
	}
	if err != nil {
		return nil, false, fmt.Errorf("config: read %s: %w", key, err)
	}
	return json.RawMessage(raw), hasSecret, nil
}

// Meta returns who changed the setting and when, for the UI.
func (s *Store) Meta(ctx context.Context, key string) (updatedAt time.Time, updatedBy string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT updated_at, updated_by FROM settings WHERE key = $1`, key).
		Scan(&updatedAt, &updatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, "", ErrNotFound
	}
	return updatedAt, updatedBy, err
}

// GetSecret decrypts the stored secret. It is for building a client, never for
// answering an HTTP request.
func (s *Store) GetSecret(ctx context.Context, key string) (string, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx, `SELECT secret_enc FROM settings WHERE key = $1`, key).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("config: read secret %s: %w", key, err)
	}
	if len(blob) == 0 {
		return "", ErrNotFound
	}
	if !s.CanStoreSecrets() {
		return "", ErrSecretWithoutKey
	}
	sealed, err := unmarshalSealed(blob)
	if err != nil {
		return "", err
	}
	plain, err := secretbox.Open(s.passphrase, sealed, aad(key))
	if err != nil {
		return "", fmt.Errorf("config: 解密 %s 失败(会话密钥换过?):%w", key, err)
	}
	return string(plain), nil
}

// Put writes a setting.
//
// secret semantics (three states, so "leave it alone" is distinguishable from
// "clear it"):
//
//	nil     keep any existing secret unchanged
//	&""     delete the stored secret
//	&"sk-…" encrypt and store it
//
// The write is one statement: a half-updated configuration cannot be observed.
func (s *Store) Put(ctx context.Context, key string, value json.RawMessage, secret *string, by string) error {
	if len(value) == 0 {
		value = json.RawMessage(`{}`)
	}
	if !json.Valid(value) {
		return fmt.Errorf("config: %s value is not valid JSON", key)
	}

	var blob []byte
	clearSecret := false
	if secret != nil {
		if *secret == "" {
			clearSecret = true
		} else {
			if !s.CanStoreSecrets() {
				return ErrSecretWithoutKey
			}
			sealed, err := secretbox.Seal(s.passphrase, []byte(*secret), aad(key))
			if err != nil {
				return fmt.Errorf("config: 加密 %s secret: %w", key, err)
			}
			blob, err = marshalSealed(sealed)
			if err != nil {
				return err
			}
		}
	}

	switch {
	case blob != nil:
		_, err := s.pool.Exec(ctx, `
			INSERT INTO settings (key, value, secret_enc, updated_by, updated_at)
			VALUES ($1,$2,$3,$4,now())
			ON CONFLICT (key) DO UPDATE
			  SET value = EXCLUDED.value, secret_enc = EXCLUDED.secret_enc,
			      updated_by = EXCLUDED.updated_by, updated_at = now()`,
			key, []byte(value), blob, by)
		return err
	case clearSecret:
		_, err := s.pool.Exec(ctx, `
			INSERT INTO settings (key, value, secret_enc, updated_by, updated_at)
			VALUES ($1,$2,NULL,$3,now())
			ON CONFLICT (key) DO UPDATE
			  SET value = EXCLUDED.value, secret_enc = NULL,
			      updated_by = EXCLUDED.updated_by, updated_at = now()`,
			key, []byte(value), by)
		return err
	default:
		// Keep whatever secret is already there.
		_, err := s.pool.Exec(ctx, `
			INSERT INTO settings (key, value, updated_by, updated_at)
			VALUES ($1,$2,$3,now())
			ON CONFLICT (key) DO UPDATE
			  SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			key, []byte(value), by)
		return err
	}
}

// ---- blob encoding ---------------------------------------------------------
//
// The stored blob is a compact JSON object so a human can see which scheme and
// sizes were used without being able to read the plaintext.

type sealedJSON struct {
	Enc   string `json:"enc"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	Data  []byte `json:"data"`
}

func marshalSealed(s secretbox.Sealed) ([]byte, error) {
	return json.Marshal(sealedJSON{Enc: "aes-256-gcm", Salt: s.Salt, Nonce: s.Nonce, Data: s.Ciphertext})
}

func unmarshalSealed(raw []byte) (secretbox.Sealed, error) {
	var sj sealedJSON
	if err := json.Unmarshal(raw, &sj); err != nil {
		return secretbox.Sealed{}, fmt.Errorf("config: 密文格式损坏: %w", err)
	}
	if sj.Enc != "aes-256-gcm" {
		return secretbox.Sealed{}, fmt.Errorf("config: 未知加密方式 %q", sj.Enc)
	}
	return secretbox.Sealed{Salt: sj.Salt, Nonce: sj.Nonce, Ciphertext: sj.Data}, nil
}

// aad binds a blob to its setting key, so one secret cannot be swapped for another.
func aad(key string) []byte { return []byte("youkai/settings/" + key) }

// PassphraseFromEnv returns the passphrase used to encrypt secrets, or nil.
//
// It reads YOUKAI_SESSION_KEY (preferred) and FAIRY_SESSION_KEY (compatible with
// the session store's variable). A passphrase shorter than 8 characters is treated
// as absent: refusing is better than a weak key that looks configured.
func PassphraseFromEnv() []byte {
	for _, name := range []string{"YOUKAI_SESSION_KEY", "FAIRY_SESSION_KEY"} {
		if v := strings.TrimSpace(os.Getenv(name)); len(v) >= 8 {
			return []byte(v)
		}
	}
	return nil
}
