// Package crypto provides client-side encryption helpers for vault payloads.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// KeySize is the AES-256 key size in bytes.
	KeySize = 32
	// NonceSize is the AES-GCM nonce size in bytes.
	NonceSize = 12
	// SaltSize is the Argon2id salt size in bytes.
	SaltSize = 16
)

// VaultKeyParams contains Argon2id parameters for deriving the client vault key.
type VaultKeyParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
}

// NewVaultKeyParams returns default Argon2id parameters for vault key derivation.
func NewVaultKeyParams() VaultKeyParams {
	return VaultKeyParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		KeyLength:   KeySize,
	}
}

// Cipher encrypts and decrypts vault payloads using AES-256-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// NewAESGCM returns an AES-256-GCM cipher for the provided key.
func NewAESGCM(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm cipher: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt encrypts plaintext and returns a unique nonce with ciphertext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	nonce, err := RandomBytes(NonceSize)
	if err != nil {
		return nil, nil, err
	}
	return nonce, c.aead.Seal(nil, nonce, plaintext, nil), nil
}

// Decrypt authenticates and decrypts ciphertext using nonce.
func (c *Cipher) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes", NonceSize)
	}
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

// DeriveVaultKey derives the client-side encryption key from a password and salt.
func DeriveVaultKey(password string, salt []byte, params VaultKeyParams) []byte {
	params = params.withDefaults()
	return argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
}

// RandomBytes returns cryptographically secure random bytes.
func RandomBytes(size int) ([]byte, error) {
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return out, nil
}

func (p VaultKeyParams) withDefaults() VaultKeyParams {
	defaults := NewVaultKeyParams()
	if p.Memory == 0 {
		p.Memory = defaults.Memory
	}
	if p.Iterations == 0 {
		p.Iterations = defaults.Iterations
	}
	if p.Parallelism == 0 {
		p.Parallelism = defaults.Parallelism
	}
	if p.KeyLength == 0 {
		p.KeyLength = defaults.KeyLength
	}
	return p
}
