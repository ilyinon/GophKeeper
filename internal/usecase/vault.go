package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	vaultcrypto "github.com/oilyin/gophkeeper/internal/crypto"
	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

// VaultUseCase implements encrypted vault item workflows.
type VaultUseCase struct {
	items VaultRepository
}

// ItemPayloadInput contains opaque encrypted bytes accepted by the server.
type ItemPayloadInput struct {
	Nonce      []byte
	Ciphertext []byte
}

// CreateItemInput contains data required to create a vault item.
type CreateItemInput struct {
	ID      uuid.UUID
	UserID  uuid.UUID
	Payload ItemPayloadInput
}

// UpdateItemInput contains data required to update a vault item.
type UpdateItemInput struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	ExpectedRevision int64
	Payload          ItemPayloadInput
}

// DeleteItemInput contains data required to delete a vault item.
type DeleteItemInput struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	ExpectedRevision int64
}

// NewVaultUseCase creates a vault use case.
func NewVaultUseCase(items VaultRepository) *VaultUseCase {
	return &VaultUseCase{items: items}
}

// Create stores a new opaque encrypted vault item.
func (u *VaultUseCase) Create(ctx context.Context, input CreateItemInput) (entity.VaultItem, error) {
	if input.UserID == uuid.Nil {
		return entity.VaultItem{}, fmt.Errorf("%w: user id is required", apperrors.ErrInvalidInput)
	}
	if err := validateEncryptedPayload(input.Payload); err != nil {
		return entity.VaultItem{}, err
	}
	itemID := input.ID
	if itemID == uuid.Nil {
		itemID = uuid.New()
	}
	now := time.Now().UTC()
	return u.items.Create(ctx, entity.VaultItem{
		ID:     itemID,
		UserID: input.UserID,
		Payload: entity.EncryptedPayload{
			Nonce:      append([]byte(nil), input.Payload.Nonce...),
			Ciphertext: append([]byte(nil), input.Payload.Ciphertext...),
		},
		CreatedAt: now,
		UpdatedAt: now,
	})
}

// Update replaces an existing opaque payload if expected revision matches.
func (u *VaultUseCase) Update(ctx context.Context, input UpdateItemInput) (entity.VaultItem, error) {
	if input.ID == uuid.Nil || input.UserID == uuid.Nil {
		return entity.VaultItem{}, fmt.Errorf("%w: item id and user id are required", apperrors.ErrInvalidInput)
	}
	if input.ExpectedRevision <= 0 {
		return entity.VaultItem{}, fmt.Errorf("%w: expected revision must be positive", apperrors.ErrInvalidInput)
	}
	if err := validateEncryptedPayload(input.Payload); err != nil {
		return entity.VaultItem{}, err
	}
	return u.items.Update(ctx, entity.VaultItem{
		ID:     input.ID,
		UserID: input.UserID,
		Payload: entity.EncryptedPayload{
			Nonce:      append([]byte(nil), input.Payload.Nonce...),
			Ciphertext: append([]byte(nil), input.Payload.Ciphertext...),
		},
		UpdatedAt: time.Now().UTC(),
	}, input.ExpectedRevision)
}

// Delete creates a tombstone if expected revision matches.
func (u *VaultUseCase) Delete(ctx context.Context, input DeleteItemInput) (entity.VaultItem, error) {
	if input.ID == uuid.Nil || input.UserID == uuid.Nil {
		return entity.VaultItem{}, fmt.Errorf("%w: item id and user id are required", apperrors.ErrInvalidInput)
	}
	if input.ExpectedRevision <= 0 {
		return entity.VaultItem{}, fmt.Errorf("%w: expected revision must be positive", apperrors.ErrInvalidInput)
	}
	return u.items.Delete(ctx, input.UserID, input.ID, input.ExpectedRevision)
}

// Get returns one non-deleted encrypted item owned by the user.
func (u *VaultUseCase) Get(ctx context.Context, userID, itemID uuid.UUID) (entity.VaultItem, error) {
	if itemID == uuid.Nil || userID == uuid.Nil {
		return entity.VaultItem{}, fmt.Errorf("%w: item id and user id are required", apperrors.ErrInvalidInput)
	}
	return u.items.Get(ctx, userID, itemID)
}

// List returns encrypted items owned by the user.
func (u *VaultUseCase) List(ctx context.Context, userID uuid.UUID, includeDeleted bool) ([]entity.VaultItem, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: user id is required", apperrors.ErrInvalidInput)
	}
	return u.items.List(ctx, userID, includeDeleted)
}

// Sync returns encrypted changes after a client sync cursor.
func (u *VaultUseCase) Sync(ctx context.Context, userID uuid.UUID, afterSyncVersion uint64) ([]entity.VaultItem, uint64, error) {
	if userID == uuid.Nil {
		return nil, 0, fmt.Errorf("%w: user id is required", apperrors.ErrInvalidInput)
	}
	return u.items.Sync(ctx, userID, afterSyncVersion)
}

func validateEncryptedPayload(payload ItemPayloadInput) error {
	if len(payload.Nonce) != vaultcrypto.NonceSize {
		return fmt.Errorf("%w: nonce must be %d bytes", apperrors.ErrInvalidInput, vaultcrypto.NonceSize)
	}
	if len(payload.Ciphertext) == 0 {
		return fmt.Errorf("%w: ciphertext is required", apperrors.ErrInvalidInput)
	}
	return nil
}
