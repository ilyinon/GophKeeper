package auth

import "testing"

func TestPasswordHasherHashVerify(t *testing.T) {
	hasher := PasswordHasher{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}
	hash, err := hasher.Hash("password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := hasher.Verify("password", hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for matching password")
	}
	ok, err = hasher.Verify("wrong", hash)
	if err != nil {
		t.Fatalf("Verify wrong: %v", err)
	}
	if ok {
		t.Fatal("Verify returned true for wrong password")
	}
}

func TestPasswordHasherRejectsInvalidHash(t *testing.T) {
	hasher := NewPasswordHasher()
	if _, err := hasher.Verify("password", "bad"); err == nil {
		t.Fatal("Verify accepted invalid hash")
	}
}
