// Package usecase contains application business logic independent of transports.
package usecase

import (
	"context"
	"iter"
	"time"

	"github.com/google/uuid"

	"github.com/oilyin/gophkeeper/internal/entity"
)

// UserRepository persists and loads users for authentication flows.
type UserRepository interface {
	Create(ctx context.Context, user entity.User) error
	GetByLogin(ctx context.Context, login string) (entity.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (entity.User, error)
}

// VaultRepository persists opaque encrypted vault items.
type VaultRepository interface {
	Create(ctx context.Context, item entity.VaultItem) (entity.VaultItem, error)
	Update(ctx context.Context, item entity.VaultItem, expectedRevision int64) (entity.VaultItem, error)
	Delete(ctx context.Context, userID, itemID uuid.UUID, expectedRevision int64) (entity.VaultItem, error)
	Get(ctx context.Context, userID, itemID uuid.UUID) (entity.VaultItem, error)
	List(ctx context.Context, userID uuid.UUID, includeDeleted bool) (iter.Seq2[entity.VaultItem, error], error)
	Sync(ctx context.Context, userID uuid.UUID, afterSyncVersion uint64) (iter.Seq2[entity.VaultItem, error], uint64, error)
}

// PasswordService hashes and verifies user passwords.
type PasswordService interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
}

// TokenIssuer creates access tokens for authenticated users.
type TokenIssuer interface {
	Issue(userID uuid.UUID) (string, time.Time, error)
}
