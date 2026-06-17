package usecase

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	vaultcrypto "github.com/oilyin/gophkeeper/internal/crypto"
	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

const (
	minLoginLength    = 3
	minPasswordLength = 8
)

// AuthUseCase implements registration and login workflows.
type AuthUseCase struct {
	users    UserRepository
	password PasswordService
	tokens   TokenIssuer
}

// AuthResult is returned after successful registration or login.
type AuthResult struct {
	UserID      uuid.UUID
	AccessToken string
	ExpiresAt   time.Time
	KDFSalt     []byte
}

// RegisterInput contains registration data.
type RegisterInput struct {
	Login    string
	Password string
	KDFSalt  []byte
}

// LoginInput contains login data.
type LoginInput struct {
	Login    string
	Password string
}

// NewAuthUseCase creates an authentication use case.
func NewAuthUseCase(users UserRepository, password PasswordService, tokens TokenIssuer) *AuthUseCase {
	return &AuthUseCase{users: users, password: password, tokens: tokens}
}

// Register creates a new user and issues an access token.
func (u *AuthUseCase) Register(ctx context.Context, input RegisterInput) (AuthResult, error) {
	login := normalizeLogin(input.Login)
	if err := validateCredentials(login, input.Password); err != nil {
		return AuthResult{}, err
	}

	kdfSalt := input.KDFSalt
	if len(kdfSalt) == 0 {
		var err error
		kdfSalt, err = vaultcrypto.RandomBytes(vaultcrypto.SaltSize)
		if err != nil {
			return AuthResult{}, err
		}
	}
	if len(kdfSalt) < vaultcrypto.SaltSize {
		return AuthResult{}, fmt.Errorf("%w: kdf salt must be at least %d bytes", apperrors.ErrInvalidInput, vaultcrypto.SaltSize)
	}

	passwordHash, err := u.password.Hash(input.Password)
	if err != nil {
		return AuthResult{}, err
	}
	user := entity.User{
		ID:           uuid.New(),
		Login:        login,
		PasswordHash: passwordHash,
		KDFSalt:      append([]byte(nil), kdfSalt...),
		CreatedAt:    time.Now().UTC(),
	}
	if err := u.users.Create(ctx, user); err != nil {
		return AuthResult{}, err
	}
	return u.issue(user)
}

// Login authenticates an existing user and issues an access token.
func (u *AuthUseCase) Login(ctx context.Context, input LoginInput) (AuthResult, error) {
	login := normalizeLogin(input.Login)
	if login == "" || input.Password == "" {
		return AuthResult{}, fmt.Errorf("%w: login and password are required", apperrors.ErrInvalidInput)
	}
	user, err := u.users.GetByLogin(ctx, login)
	if err != nil {
		return AuthResult{}, fmt.Errorf("%w: invalid credentials", apperrors.ErrUnauthorized)
	}
	ok, err := u.password.Verify(input.Password, user.PasswordHash)
	if err != nil {
		return AuthResult{}, err
	}
	if !ok {
		return AuthResult{}, fmt.Errorf("%w: invalid credentials", apperrors.ErrUnauthorized)
	}
	return u.issue(user)
}

func (u *AuthUseCase) issue(user entity.User) (AuthResult, error) {
	token, expiresAt, err := u.tokens.Issue(user.ID)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{
		UserID:      user.ID,
		AccessToken: token,
		ExpiresAt:   expiresAt,
		KDFSalt:     append([]byte(nil), user.KDFSalt...),
	}, nil
}

func normalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func validateCredentials(login, password string) error {
	if len(login) < minLoginLength {
		return fmt.Errorf("%w: login must be at least %d characters", apperrors.ErrInvalidInput, minLoginLength)
	}
	if len(password) < minPasswordLength {
		return fmt.Errorf("%w: password must be at least %d characters", apperrors.ErrInvalidInput, minPasswordLength)
	}
	return nil
}
