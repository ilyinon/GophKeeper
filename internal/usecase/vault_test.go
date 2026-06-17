package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

func TestVaultUseCaseCreateUpdateDelete(t *testing.T) {
	repo := newMemoryVault()
	vault := NewVaultUseCase(repo)
	userID := uuid.New()
	payload := ItemPayloadInput{Nonce: []byte("123456789012"), Ciphertext: []byte("cipher")}

	created, err := vault.Create(context.Background(), CreateItemInput{UserID: userID, Payload: payload})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Revision != 1 || created.SyncVersion != 1 {
		t.Fatalf("bad created item: %+v", created)
	}

	updated, err := vault.Update(context.Background(), UpdateItemInput{
		ID:               created.ID,
		UserID:           userID,
		ExpectedRevision: created.Revision,
		Payload:          ItemPayloadInput{Nonce: []byte("abcdefghijkl"), Ciphertext: []byte("new")},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Revision != 2 {
		t.Fatalf("revision = %d, want 2", updated.Revision)
	}

	if _, err := vault.Delete(context.Background(), DeleteItemInput{ID: created.ID, UserID: userID, ExpectedRevision: 1}); !errors.Is(err, apperrors.ErrConflict) {
		t.Fatalf("Delete stale error = %v, want conflict", err)
	}
	deleted, err := vault.Delete(context.Background(), DeleteItemInput{ID: created.ID, UserID: userID, ExpectedRevision: updated.Revision})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !deleted.IsDeleted() {
		t.Fatal("deleted item has no tombstone")
	}
}

func TestVaultUseCaseValidatesPayload(t *testing.T) {
	vault := NewVaultUseCase(newMemoryVault())
	_, err := vault.Create(context.Background(), CreateItemInput{
		UserID:  uuid.New(),
		Payload: ItemPayloadInput{Nonce: []byte("short"), Ciphertext: []byte("cipher")},
	})
	if !errors.Is(err, apperrors.ErrInvalidInput) {
		t.Fatalf("Create error = %v, want invalid input", err)
	}
}

func TestVaultUseCaseReadMethods(t *testing.T) {
	repo := newMemoryVault()
	vault := NewVaultUseCase(repo)
	userID := uuid.New()
	created, err := vault.Create(context.Background(), CreateItemInput{
		UserID:  userID,
		Payload: ItemPayloadInput{Nonce: []byte("123456789012"), Ciphertext: []byte("cipher")},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := vault.Get(context.Background(), userID, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("got id = %s, want %s", got.ID, created.ID)
	}
	listed, err := vault.List(context.Background(), userID, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("len(listed) = %d, want 1", len(listed))
	}
	synced, cursor, err := vault.Sync(context.Background(), userID, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(synced) != 1 || cursor != created.SyncVersion {
		t.Fatalf("sync = %d items cursor %d", len(synced), cursor)
	}
	if _, err := vault.Get(context.Background(), uuid.Nil, created.ID); !errors.Is(err, apperrors.ErrInvalidInput) {
		t.Fatalf("Get nil user error = %v", err)
	}
}

type memoryVault struct {
	items map[uuid.UUID]entity.VaultItem
	sync  uint64
}

func newMemoryVault() *memoryVault {
	return &memoryVault{items: map[uuid.UUID]entity.VaultItem{}}
}

func (m *memoryVault) Create(_ context.Context, item entity.VaultItem) (entity.VaultItem, error) {
	m.sync++
	item.Revision = 1
	item.SyncVersion = m.sync
	m.items[item.ID] = item
	return item, nil
}

func (m *memoryVault) Update(_ context.Context, item entity.VaultItem, expectedRevision int64) (entity.VaultItem, error) {
	current, ok := m.items[item.ID]
	if !ok {
		return entity.VaultItem{}, apperrors.ErrNotFound
	}
	if current.Revision != expectedRevision || current.IsDeleted() {
		return entity.VaultItem{}, apperrors.ErrConflict
	}
	m.sync++
	current.Revision++
	current.SyncVersion = m.sync
	current.Payload = item.Payload
	m.items[item.ID] = current
	return current, nil
}

func (m *memoryVault) Delete(_ context.Context, userID, itemID uuid.UUID, expectedRevision int64) (entity.VaultItem, error) {
	current, ok := m.items[itemID]
	if !ok || current.UserID != userID {
		return entity.VaultItem{}, apperrors.ErrNotFound
	}
	if current.Revision != expectedRevision || current.IsDeleted() {
		return entity.VaultItem{}, apperrors.ErrConflict
	}
	m.sync++
	current.Revision++
	current.SyncVersion = m.sync
	now := current.UpdatedAt
	current.DeletedAt = &now
	m.items[itemID] = current
	return current, nil
}

func (m *memoryVault) Get(_ context.Context, userID, itemID uuid.UUID) (entity.VaultItem, error) {
	item, ok := m.items[itemID]
	if !ok || item.UserID != userID || item.IsDeleted() {
		return entity.VaultItem{}, apperrors.ErrNotFound
	}
	return item, nil
}

func (m *memoryVault) List(_ context.Context, userID uuid.UUID, includeDeleted bool) ([]entity.VaultItem, error) {
	var out []entity.VaultItem
	for _, item := range m.items {
		if item.UserID == userID && (includeDeleted || !item.IsDeleted()) {
			out = append(out, item)
		}
	}
	return out, nil
}

func (m *memoryVault) Sync(_ context.Context, userID uuid.UUID, afterSyncVersion uint64) ([]entity.VaultItem, uint64, error) {
	var out []entity.VaultItem
	for _, item := range m.items {
		if item.UserID == userID && item.SyncVersion > afterSyncVersion {
			out = append(out, item)
		}
	}
	return out, m.sync, nil
}
