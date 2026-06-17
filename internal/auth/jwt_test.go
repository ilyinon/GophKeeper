package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTokenManagerIssueVerify(t *testing.T) {
	manager, err := NewTokenManager(strings.Repeat("a", 32), time.Hour, "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	userID := uuid.New()
	token, expiresAt, err := manager.Issue(userID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("token already expired")
	}
	actualUserID, err := manager.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if actualUserID != userID {
		t.Fatalf("user id = %s, want %s", actualUserID, userID)
	}
}

func TestTokenManagerRejectsWrongSecret(t *testing.T) {
	manager, err := NewTokenManager(strings.Repeat("a", 32), time.Hour, "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	other, err := NewTokenManager(strings.Repeat("b", 32), time.Hour, "test")
	if err != nil {
		t.Fatalf("NewTokenManager other: %v", err)
	}
	token, _, err := manager.Issue(uuid.New())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := other.Verify(token); err == nil {
		t.Fatal("Verify accepted token signed by another secret")
	}
}

func TestTokenManagerRejectsInvalidConfig(t *testing.T) {
	if _, err := NewTokenManager("short", time.Hour, "test"); err == nil {
		t.Fatal("accepted short secret")
	}
	if _, err := NewTokenManager(strings.Repeat("a", 32), 0, "test"); err == nil {
		t.Fatal("accepted zero ttl")
	}
}
