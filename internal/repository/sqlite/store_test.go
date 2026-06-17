package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/oilyin/gophkeeper/internal/entity"
)

func TestStoreSessionAndItems(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	userID := uuid.New()
	session := Session{
		UserID:         userID,
		Login:          "alice",
		ServerAddr:     "127.0.0.1:3200",
		AccessToken:    "token",
		TokenExpiresAt: time.Now().Add(time.Hour).UTC(),
		KDFSalt:        []byte("1234567890123456"),
	}
	if err := store.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	loaded, err := store.LoadSession(ctx, session.ServerAddr, session.Login)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if loaded.UserID != userID || loaded.AccessToken != "token" {
		t.Fatalf("loaded session = %+v", loaded)
	}

	item := entity.VaultItem{
		ID:          uuid.New(),
		UserID:      userID,
		Revision:    1,
		SyncVersion: 10,
		Payload:     entity.EncryptedPayload{Nonce: []byte("123456789012"), Ciphertext: []byte("cipher")},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := store.UpsertItems(ctx, userID, []entity.VaultItem{item}); err != nil {
		t.Fatalf("UpsertItems: %v", err)
	}
	got, err := store.GetItem(ctx, userID, item.ID, false)
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	if got.ID != item.ID || got.Revision != 1 || string(got.Payload.Ciphertext) != "cipher" {
		t.Fatalf("got item = %+v", got)
	}
	items, err := store.ListItems(ctx, userID, false)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if err := store.SetLastSyncVersion(ctx, userID, session.ServerAddr, 10); err != nil {
		t.Fatalf("SetLastSyncVersion: %v", err)
	}
	loaded, err = store.LoadSession(ctx, session.ServerAddr, session.Login)
	if err != nil {
		t.Fatalf("LoadSession after sync: %v", err)
	}
	if loaded.LastSyncVersion != 10 {
		t.Fatalf("LastSyncVersion = %d, want 10", loaded.LastSyncVersion)
	}
}

func TestStoreHidesDeletedItemsByDefault(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	userID := uuid.New()
	deletedAt := time.Now().UTC()
	item := entity.VaultItem{
		ID:          uuid.New(),
		UserID:      userID,
		Revision:    2,
		SyncVersion: 11,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		DeletedAt:   &deletedAt,
	}
	if err := store.UpsertItems(ctx, userID, []entity.VaultItem{item}); err != nil {
		t.Fatalf("UpsertItems: %v", err)
	}
	items, err := store.ListItems(ctx, userID, false)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("len(active items) = %d, want 0", len(items))
	}
	items, err = store.ListItems(ctx, userID, true)
	if err != nil {
		t.Fatalf("ListItems include deleted: %v", err)
	}
	if len(items) != 1 || !items[0].IsDeleted() {
		t.Fatalf("deleted items = %+v", items)
	}
}
