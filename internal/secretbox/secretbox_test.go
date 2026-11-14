package secretbox

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	pass := []byte("a-passphrase-of-decent-length")
	plain := []byte(`{"api_key":"sk-should-never-appear-in-the-clear"}`)
	aad := []byte("llm")

	sealed, err := Seal(pass, plain, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed.Ciphertext, plain) {
		t.Fatal("ciphertext contains the plaintext")
	}
	if len(sealed.Salt) != SaltLen || len(sealed.Nonce) != NonceLen {
		t.Fatalf("unexpected salt/nonce sizes: %d/%d", len(sealed.Salt), len(sealed.Nonce))
	}

	got, err := Open(pass, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestSealIsRandomised(t *testing.T) {
	pass := []byte("same-passphrase")
	plain := []byte("same-plaintext")
	a, _ := Seal(pass, plain, nil)
	b, _ := Seal(pass, plain, nil)
	if bytes.Equal(a.Salt, b.Salt) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("two seals of the same input produced identical output")
	}
}

func TestWrongKeyAndTamperFail(t *testing.T) {
	pass := []byte("right-passphrase")
	sealed, err := Seal(pass, []byte("secret"), []byte("owner-a"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open([]byte("wrong-passphrase"), sealed, []byte("owner-a")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key error = %v, want ErrDecrypt", err)
	}
	// Associated data is bound: opening as another owner must fail.
	if _, err := Open(pass, sealed, []byte("owner-b")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("aad mismatch error = %v, want ErrDecrypt", err)
	}
	tampered := Sealed{Salt: sealed.Salt, Nonce: sealed.Nonce, Ciphertext: append([]byte(nil), sealed.Ciphertext...)}
	tampered.Ciphertext[0] ^= 0xFF
	if _, err := Open(pass, tampered, []byte("owner-a")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered blob error = %v, want ErrDecrypt", err)
	}
}

func TestEmptyPassphraseRefused(t *testing.T) {
	if _, err := Seal(nil, []byte("x"), nil); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("Seal with no passphrase = %v", err)
	}
	if _, err := Open(nil, Sealed{}, nil); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("Open with no passphrase = %v", err)
	}
	// A too-short blob must be rejected rather than fed to the AEAD.
	if _, err := Open([]byte("k"), Sealed{Salt: make([]byte, SaltLen), Nonce: make([]byte, NonceLen)}, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("malformed blob error = %v", err)
	}
}
