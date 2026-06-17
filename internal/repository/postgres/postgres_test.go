package postgres

import "testing"

func TestRepositoryConstructors(t *testing.T) {
	if NewUserRepository(nil) == nil {
		t.Fatal("NewUserRepository returned nil")
	}
	if NewVaultRepository(nil) == nil {
		t.Fatal("NewVaultRepository returned nil")
	}
}
