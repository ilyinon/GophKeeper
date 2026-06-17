package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

// TokenManager issues and verifies signed JWT access tokens.
type TokenManager struct {
	secret []byte
	ttl    time.Duration
	issuer string
}

// Claims are GophKeeper-specific JWT claims.
type Claims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}

// NewTokenManager returns a JWT manager pinned to HS256.
func NewTokenManager(secret string, ttl time.Duration, issuer string) (*TokenManager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("%w: jwt secret must be at least 32 bytes", apperrors.ErrInvalidInput)
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: jwt ttl must be positive", apperrors.ErrInvalidInput)
	}
	return &TokenManager{secret: []byte(secret), ttl: ttl, issuer: issuer}, nil
}

// Issue creates a signed access token for userID.
func (m *TokenManager) Issue(userID uuid.UUID) (string, time.Time, error) {
	expiresAt := time.Now().UTC().Add(m.ttl)
	claims := Claims{
		UserID: userID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	return token, expiresAt, nil
}

// Verify parses token and returns the authenticated user ID.
func (m *TokenManager) Verify(tokenValue string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenValue, &Claims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("%w: unexpected jwt algorithm", apperrors.ErrUnauthorized)
		}
		return m.secret, nil
	}, jwt.WithIssuer(m.issuer))
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", apperrors.ErrUnauthorized, err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid || claims.UserID == "" {
		return uuid.Nil, apperrors.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: invalid user id claim", apperrors.ErrUnauthorized)
	}
	return userID, nil
}
