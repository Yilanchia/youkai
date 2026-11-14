package config

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"youkai/internal/ledger"
)

func testDSN() string {
	if v := os.Getenv("YOUKAI_TEST_DSN"); v != "" {
		return v
	}
	return "postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai_test?sslmode=disable"
}

func openStore(t *testing.T, passphrase []byte) (*Store, *ledger.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	led, err := ledger.Open(ctx, testDSN())
	if err != nil {
		t.Skipf("no PostgreSQL (%v); skipping settings integration tests", err)
	}
	if err := led.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(led.Close)
	return New(led.Pool(), passphrase), led
}

func uniqueKey(t *testing.T) string {
	t.Helper()
	return "test-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
}

// TestPutGetNeverReturnsTheSecret is the central safety property.
func TestPutGetNeverReturnsTheSecret(t *testing.T) {
	store, led := openStore(t, []byte("a-session-passphrase"))
	ctx := context.Background()
	key := uniqueKey(t)
	t.Cleanup(func() { _, _ = led.Pool().Exec(ctx, `DELETE FROM settings WHERE key=$1`, key) })

	secret := "sk-live-DEADBEEF-should-never-leak"
	value, _ := json.Marshal(map[string]any{"model": "m1", "base_url": "https://api.example/v1", "temperature": 0.2})
	if err := store.Put(ctx, key, value, &secret, "alice"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, hasSecret, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hasSecret {
		t.Fatal("Get does not report the stored secret")
	}
	if strings.Contains(string(got), secret) || strings.Contains(string(got), "sk-live") {
		t.Fatalf("Get returned the secret: %s", got)
	}

	// The raw row must not contain the plaintext either.
	var raw []byte
	if err := led.Pool().QueryRow(ctx, `SELECT value || jsonb_build_object('blob', encode(secret_enc,'hex')) FROM settings WHERE key=$1`, key).Scan(&raw); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if strings.Contains(string(raw), "sk-live") {
		t.Fatalf("the database holds the key in the clear: %s", raw)
	}

	// The server-side path can decrypt it.
	back, err := store.GetSecret(ctx, key)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if back != secret {
		t.Fatalf("GetSecret = %q", back)
	}

	// Metadata is recorded.
	_, by, err := store.Meta(ctx, key)
	if err != nil || by != "alice" {
		t.Fatalf("Meta = %q, %v", by, err)
	}
}

// TestSecretRefusedWithoutPassphrase: no key configured means "refuse", not
// "store it in a weaker form".
func TestSecretRefusedWithoutPassphrase(t *testing.T) {
	store, led := openStore(t, nil)
	ctx := context.Background()
	key := uniqueKey(t)
	t.Cleanup(func() { _, _ = led.Pool().Exec(ctx, `DELETE FROM settings WHERE key=$1`, key) })

	if store.CanStoreSecrets() {
		t.Fatal("store claims it can store secrets with no passphrase")
	}
	secret := "sk-should-not-be-stored"
	err := store.Put(ctx, key, json.RawMessage(`{"model":"m"}`), &secret, "alice")
	if !errors.Is(err, ErrSecretWithoutKey) {
		t.Fatalf("Put secret without key = %v, want ErrSecretWithoutKey", err)
	}
	if _, _, gerr := store.Get(ctx, key); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("a refused write still created a row: %v", gerr)
	}

	// A non-secret value is still storable without a passphrase.
	if err := store.Put(ctx, key, json.RawMessage(`{"model":"m"}`), nil, "alice"); err != nil {
		t.Fatalf("Put without secret: %v", err)
	}
}

// TestSecretThreeStates pins "keep / clear / replace".
func TestSecretThreeStates(t *testing.T) {
	store, led := openStore(t, []byte("another-passphrase"))
	ctx := context.Background()
	key := uniqueKey(t)
	t.Cleanup(func() { _, _ = led.Pool().Exec(ctx, `DELETE FROM settings WHERE key=$1`, key) })

	first := "sk-first"
	if err := store.Put(ctx, key, json.RawMessage(`{"model":"a"}`), &first, "alice"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// nil secret: keep the existing one.
	if err := store.Put(ctx, key, json.RawMessage(`{"model":"b"}`), nil, "bob"); err != nil {
		t.Fatalf("Put keep: %v", err)
	}
	if s, err := store.GetSecret(ctx, key); err != nil || s != "sk-first" {
		t.Fatalf("secret was not kept: %q, %v", s, err)
	}

	// empty string: clear it.
	empty := ""
	if err := store.Put(ctx, key, json.RawMessage(`{"model":"b"}`), &empty, "bob"); err != nil {
		t.Fatalf("Put clear: %v", err)
	}
	if _, has, _ := store.Get(ctx, key); has {
		t.Fatal("secret was not cleared")
	}

	// replace works again.
	second := "sk-second"
	if err := store.Put(ctx, key, json.RawMessage(`{"model":"c"}`), &second, "carol"); err != nil {
		t.Fatalf("Put replace: %v", err)
	}
	if s, _ := store.GetSecret(ctx, key); s != "sk-second" {
		t.Fatalf("secret = %q", s)
	}
}

// TestWrongPassphraseCannotDecrypt: rotating the key must fail loudly.
func TestWrongPassphraseCannotDecrypt(t *testing.T) {
	store, led := openStore(t, []byte("original-passphrase"))
	ctx := context.Background()
	key := uniqueKey(t)
	t.Cleanup(func() { _, _ = led.Pool().Exec(ctx, `DELETE FROM settings WHERE key=$1`, key) })

	secret := "sk-original"
	if err := store.Put(ctx, key, json.RawMessage(`{}`), &secret, "alice"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	wrong := New(led.Pool(), []byte("a-different-passphrase"))
	if _, err := wrong.GetSecret(ctx, key); err == nil {
		t.Fatal("decryption succeeded with the wrong passphrase")
	}
}

func TestInvalidValueRejected(t *testing.T) {
	store, _ := openStore(t, []byte("x-passphrase"))
	if err := store.Put(context.Background(), "k", json.RawMessage(`not json`), nil, "a"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
