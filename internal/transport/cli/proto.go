package cli

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/oilyin/gophkeeper/internal/entity"
	gophkeeperv1 "github.com/oilyin/gophkeeper/internal/transport/grpc/pb/gophkeeper/v1"
)

func protoItemsToEntity(items []*gophkeeperv1.EncryptedItem) ([]entity.VaultItem, error) {
	out := make([]entity.VaultItem, 0, len(items))
	for _, item := range items {
		converted, err := protoItemToEntity(item)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return out, nil
}

func protoItemToEntity(item *gophkeeperv1.EncryptedItem) (entity.VaultItem, error) {
	return itemFromParts(item.GetHeader(), item.GetNonce(), item.GetCiphertext())
}

func itemFromParts(header *gophkeeperv1.ItemHeader, nonce, ciphertext []byte) (entity.VaultItem, error) {
	if header == nil {
		return entity.VaultItem{}, fmt.Errorf("missing item header")
	}
	itemID, err := uuid.Parse(header.GetId())
	if err != nil {
		return entity.VaultItem{}, fmt.Errorf("parse item id: %w", err)
	}
	item := entity.VaultItem{
		ID:          itemID,
		Revision:    header.GetRevision(),
		SyncVersion: header.GetSyncVersion(),
		Payload: entity.EncryptedPayload{
			Nonce:      append([]byte(nil), nonce...),
			Ciphertext: append([]byte(nil), ciphertext...),
		},
		CreatedAt: header.GetCreatedAt().AsTime(),
		UpdatedAt: header.GetUpdatedAt().AsTime(),
	}
	if header.GetDeletedAt() != nil {
		deletedAt := header.GetDeletedAt().AsTime()
		item.DeletedAt = &deletedAt
	}
	return item, nil
}
