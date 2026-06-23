package entity

import (
	"time"

	"github.com/google/uuid"
)

// VaultItemType identifies the plaintext payload shape encrypted by the client.
type VaultItemType string

const (
	// VaultItemTypeLoginPassword stores a login/password pair.
	VaultItemTypeLoginPassword VaultItemType = "login_password"
	// VaultItemTypeText stores arbitrary text.
	VaultItemTypeText VaultItemType = "text"
	// VaultItemTypeBinary stores arbitrary binary data.
	VaultItemTypeBinary VaultItemType = "binary"
	// VaultItemTypeCard stores bank card details.
	VaultItemTypeCard VaultItemType = "card"
)

// EncryptedPayload is an opaque client-encrypted payload with its AEAD nonce.
type EncryptedPayload struct {
	Nonce      []byte
	Ciphertext []byte
}

// VaultItem is a server-side encrypted vault record.
type VaultItem struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Revision    int64
	SyncVersion uint64
	Payload     EncryptedPayload
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

// IsDeleted reports whether this item is a deletion tombstone.
func (i VaultItem) IsDeleted() bool {
	return i.DeletedAt != nil
}
