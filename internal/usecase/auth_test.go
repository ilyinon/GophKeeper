package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

func TestAuthUseCaseRegisterAndLogin(t *testing.T) {
	users := newMemoryUsers()
	auth := NewAuthUseCase(users, plainPasswordService{}, staticTokenIssuer{})

	registered, err := auth.Register(context.Background(), RegisterInput{
		Login:    " Alice ",
		Password: "password-1",
		KDFSalt:  []byte("1234567890123456"),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registered.UserID == uuid.Nil || registered.AccessToken == "" {
		t.Fatalf("bad auth result: %+v", registered)
	}
	if _, ok := users.byLogin["alice"]; !ok {
		t.Fatal("login was not normalized")
	}

	loggedIn, err := auth.Login(context.Background(), LoginInput{Login: "alice", Password: "password-1"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loggedIn.UserID != registered.UserID {
		t.Fatalf("login user id = %s, want %s", loggedIn.UserID, registered.UserID)
	}
}

func TestAuthUseCaseRejectsInvalidCredentials(t *testing.T) {
	auth := NewAuthUseCase(newMemoryUsers(), plainPasswordService{}, staticTokenIssuer{})
	if _, err := auth.Register(context.Background(), RegisterInput{Login: "aa", Password: "password-1"}); !errors.Is(err, apperrors.ErrInvalidInput) {
		t.Fatalf("Register error = %v, want invalid input", err)
	}
	if _, err := auth.Login(context.Background(), LoginInput{Login: "missing", Password: "password-1"}); !errors.Is(err, apperrors.ErrUnauthorized) {
		t.Fatalf("Login error = %v, want unauthorized", err)
	}
}

func TestAuthUseCaseRegisterDuplicate(t *testing.T) {
	auth := NewAuthUseCase(newMemoryUsers(), plainPasswordService{}, staticTokenIssuer{})
	input := RegisterInput{Login: "alice", Password: "password-1", KDFSalt: []byte("1234567890123456")}
	if _, err := auth.Register(context.Background(), input); err != nil {
		t.Fatalf("Register first: %v", err)
	}
	if _, err := auth.Register(context.Background(), input); !errors.Is(err, apperrors.ErrAlreadyExists) {
		t.Fatalf("Register duplicate error = %v, want already exists", err)
	}
}

type memoryUsers struct {
	byID    map[uuid.UUID]entity.User
	byLogin map[string]entity.User
}

func newMemoryUsers() *memoryUsers {
	return &memoryUsers{byID: map[uuid.UUID]entity.User{}, byLogin: map[string]entity.User{}}
}

func (m *memoryUsers) Create(_ context.Context, user entity.User) error {
	if _, ok := m.byLogin[user.Login]; ok {
		return apperrors.ErrAlreadyExists
	}
	m.byID[user.ID] = user
	m.byLogin[user.Login] = user
	return nil
}

func (m *memoryUsers) GetByLogin(_ context.Context, login string) (entity.User, error) {
	user, ok := m.byLogin[login]
	if !ok {
		return entity.User{}, apperrors.ErrNotFound
	}
	return user, nil
}

func (m *memoryUsers) GetByID(_ context.Context, id uuid.UUID) (entity.User, error) {
	user, ok := m.byID[id]
	if !ok {
		return entity.User{}, apperrors.ErrNotFound
	}
	return user, nil
}

type plainPasswordService struct{}

func (plainPasswordService) Hash(password string) (string, error) {
	return "hash:" + password, nil
}

func (plainPasswordService) Verify(password, encodedHash string) (bool, error) {
	return encodedHash == "hash:"+password, nil
}

type staticTokenIssuer struct{}

func (staticTokenIssuer) Issue(userID uuid.UUID) (string, time.Time, error) {
	return "token:" + userID.String(), time.Now().Add(time.Hour), nil
}
