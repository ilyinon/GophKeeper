package crypto

import (
	"bytes"
	"testing"
)

func TestCipherEncryptDecrypt(t *testing.T) {
	key := DeriveVaultKey("correct horse battery staple", bytes.Repeat([]byte{1}, SaltSize), NewVaultKeyParams())
	cipher, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	nonce, ciphertext, err := cipher.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("nonce length = %d, want %d", len(nonce), NonceSize)
	}

	plaintext, err := cipher.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plaintext) != "secret" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestCipherRejectsTamperedCiphertext(t *testing.T) {
	key := DeriveVaultKey("password", bytes.Repeat([]byte{2}, SaltSize), NewVaultKeyParams())
	cipher, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	nonce, ciphertext, err := cipher.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ciphertext[0] ^= 0xff

	if _, err := cipher.Decrypt(nonce, ciphertext); err == nil {
		t.Fatal("Decrypt succeeded for tampered ciphertext")
	}
}

func TestNewAESGCMRejectsWrongKeySize(t *testing.T) {
	if _, err := NewAESGCM([]byte("short")); err == nil {
		t.Fatal("NewAESGCM accepted short key")
	}
}

func TestDeriveVaultKeyUsesConfiguredParams(t *testing.T) {
	salt := bytes.Repeat([]byte{3}, SaltSize)
	fast := VaultKeyParams{Memory: 1024, Iterations: 1, Parallelism: 1, KeyLength: KeySize}
	stronger := VaultKeyParams{Memory: 1024, Iterations: 2, Parallelism: 1, KeyLength: KeySize}

	fastKey := DeriveVaultKey("password", salt, fast)
	strongerKey := DeriveVaultKey("password", salt, stronger)

	if len(fastKey) != KeySize {
		t.Fatalf("key length = %d, want %d", len(fastKey), KeySize)
	}
	if bytes.Equal(fastKey, strongerKey) {
		t.Fatal("different Argon2id params produced identical vault keys")
	}
}
