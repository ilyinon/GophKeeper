package entity

import (
	"testing"
	"time"
)

func TestVaultItemIsDeleted(t *testing.T) {
	item := VaultItem{}
	if item.IsDeleted() {
		t.Fatal("zero item reported deleted")
	}
	now := time.Now()
	item.DeletedAt = &now
	if !item.IsDeleted() {
		t.Fatal("item with deleted_at reported active")
	}
}
