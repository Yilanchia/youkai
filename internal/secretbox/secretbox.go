// Package secretbox is youkai's one way to put a secret on disk.
//
// Two things need it (login sessions and the platform's LLM credential), so the
// construction lives here instead of being copy-pasted:
//
//	key  = scrypt(passphrase, random 16-byte salt, N=2^14, r=8, p=1, 32 bytes)
//	blob = AES-256-GCM(key, random 12-byte nonce, plaintext, aad)
//
// The nonce and salt travel with the ciphertext, and the associated data binds a
// blob to its owner (a session blob cannot be swapped onto another account name).
//
// There is deliberately no "encrypt with a built-in key" mode: if no passphrase is
// configured the caller must refuse to store the secret, not fall back to
// obfuscation.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// Sizes and parameters are part of the on-disk format: changing them would make
// previously sealed blobs unreadable, so they are constants, not options.
const (
	// SaltLen is the scrypt salt length.
	SaltLen = 16
	// NonceLen is the GCM nonce length.
	NonceLen = 12
	// KeyLen is the derived key length.
	KeyLen = 32

	scryptN = 1 << 14
	scryptR = 8
	scryptP = 1
)

// ErrNoPassphrase is returned when a caller asks to seal without a key.
var ErrNoPassphrase = errors.New("secretbox: a passphrase is required to seal a secret")

// ErrDecrypt means the passphrase is wrong or the blob was tampered with. It is
// deliberately one error: distinguishing the two would leak information.
var ErrDecrypt = errors.New("secretbox: cannot open the sealed secret (wrong key or altered blob)")

// Sealed is the on-disk shape of an encrypted value.
type Sealed struct {
	Salt       []byte
	Nonce      []byte
	Ciphertext []byte
}

// Seal encrypts plaintext. The associated data is authenticated but not stored.
func Seal(passphrase, plaintext, aad []byte) (Sealed, error) {
	if len(passphrase) == 0 {
		return Sealed{}, ErrNoPassphrase
	}
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	key, err := derive(passphrase, salt)
	if err != nil {
		return Sealed{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Sealed{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, aad),
	}, nil
}

// Open verifies and decrypts a sealed value.
func Open(passphrase []byte, s Sealed, aad []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrNoPassphrase
	}
	if len(s.Salt) != SaltLen || len(s.Nonce) != NonceLen || len(s.Ciphertext) < 16 {
		return nil, fmt.Errorf("%w: malformed blob", ErrDecrypt)
	}
	key, err := derive(passphrase, s.Salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, s.Nonce, s.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func derive(passphrase, salt []byte) ([]byte, error) {
	return scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, KeyLen)
}
