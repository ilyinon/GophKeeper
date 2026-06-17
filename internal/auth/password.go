// Package auth provides password hashing and token management.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const argon2Version = 19

// PasswordHasher hashes and verifies passwords using Argon2id.
type PasswordHasher struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// NewPasswordHasher returns production-oriented Argon2id parameters.
func NewPasswordHasher() PasswordHasher {
	return PasswordHasher{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Hash returns a PHC-style Argon2id password hash.
func (h PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, h.Iterations, h.Memory, h.Parallelism, h.KeyLength)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		h.Memory,
		h.Iterations,
		h.Parallelism,
		b64.EncodeToString(salt),
		b64.EncodeToString(hash),
	), nil
}

// Verify checks whether password matches an encoded PHC-style Argon2id hash.
func (h PasswordHasher) Verify(password, encodedHash string) (bool, error) {
	params, salt, expectedHash, err := parsePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}
	actualHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

func parsePasswordHash(encodedHash string) (PasswordHasher, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return PasswordHasher{}, nil, nil, fmt.Errorf("invalid argon2id hash format")
	}
	if parts[2] != "v=19" {
		return PasswordHasher{}, nil, nil, fmt.Errorf("unsupported argon2id version")
	}

	var params PasswordHasher
	for _, param := range strings.Split(parts[3], ",") {
		keyValue := strings.SplitN(param, "=", 2)
		if len(keyValue) != 2 {
			return PasswordHasher{}, nil, nil, fmt.Errorf("invalid argon2id parameter")
		}
		value, err := strconv.ParseUint(keyValue[1], 10, 32)
		if err != nil {
			return PasswordHasher{}, nil, nil, fmt.Errorf("parse argon2id parameter: %w", err)
		}
		switch keyValue[0] {
		case "m":
			params.Memory = uint32(value)
		case "t":
			params.Iterations = uint32(value)
		case "p":
			params.Parallelism = uint8(value)
		default:
			return PasswordHasher{}, nil, nil, fmt.Errorf("unknown argon2id parameter")
		}
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return PasswordHasher{}, nil, nil, fmt.Errorf("decode password salt: %w", err)
	}
	hash, err := b64.DecodeString(parts[5])
	if err != nil {
		return PasswordHasher{}, nil, nil, fmt.Errorf("decode password hash: %w", err)
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))
	return params, salt, hash, nil
}
