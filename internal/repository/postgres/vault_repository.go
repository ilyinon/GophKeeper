package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

// VaultRepository stores opaque encrypted vault items in PostgreSQL.
type VaultRepository struct {
	pool *pgxpool.Pool
}

// NewVaultRepository creates a PostgreSQL vault repository.
func NewVaultRepository(pool *pgxpool.Pool) *VaultRepository {
	return &VaultRepository{pool: pool}
}

// Create inserts a new encrypted item.
func (r *VaultRepository) Create(ctx context.Context, item entity.VaultItem) (entity.VaultItem, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO vault_items(id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at)
		 VALUES ($1, $2, 1, nextval('vault_sync_version_seq'), $3, $4, $5, $6)
		 RETURNING id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at`,
		item.ID, item.UserID, item.Payload.Nonce, item.Payload.Ciphertext, item.CreatedAt, item.UpdatedAt,
	)
	created, err := scanVaultItem(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return entity.VaultItem{}, fmt.Errorf("%w: item already exists", apperrors.ErrAlreadyExists)
		}
		return entity.VaultItem{}, err
	}
	return created, nil
}

// Update replaces an encrypted item when expectedRevision matches.
func (r *VaultRepository) Update(ctx context.Context, item entity.VaultItem, expectedRevision int64) (entity.VaultItem, error) {
	row := r.pool.QueryRow(ctx,
		`UPDATE vault_items
		 SET revision = revision + 1,
		     sync_version = nextval('vault_sync_version_seq'),
		     nonce = $4,
		     ciphertext = $5,
		     updated_at = $6,
		     deleted_at = NULL
		 WHERE id = $1 AND user_id = $2 AND revision = $3 AND deleted_at IS NULL
		 RETURNING id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at`,
		item.ID, item.UserID, expectedRevision, item.Payload.Nonce, item.Payload.Ciphertext, item.UpdatedAt,
	)
	updated, err := scanVaultItem(row)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return entity.VaultItem{}, r.classifyWriteMiss(ctx, item.UserID, item.ID, expectedRevision)
		}
		return entity.VaultItem{}, err
	}
	return updated, nil
}

// Delete tombstones an encrypted item when expectedRevision matches.
func (r *VaultRepository) Delete(ctx context.Context, userID, itemID uuid.UUID, expectedRevision int64) (entity.VaultItem, error) {
	row := r.pool.QueryRow(ctx,
		`UPDATE vault_items
		 SET revision = revision + 1,
		     sync_version = nextval('vault_sync_version_seq'),
		     nonce = ''::bytea,
		     ciphertext = ''::bytea,
		     updated_at = now(),
		     deleted_at = now()
		 WHERE id = $1 AND user_id = $2 AND revision = $3 AND deleted_at IS NULL
		 RETURNING id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at`,
		itemID, userID, expectedRevision,
	)
	deleted, err := scanVaultItem(row)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return entity.VaultItem{}, r.classifyWriteMiss(ctx, userID, itemID, expectedRevision)
		}
		return entity.VaultItem{}, err
	}
	return deleted, nil
}

// Get returns one non-deleted item owned by userID.
func (r *VaultRepository) Get(ctx context.Context, userID, itemID uuid.UUID) (entity.VaultItem, error) {
	return scanVaultItem(r.pool.QueryRow(ctx,
		`SELECT id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at
		 FROM vault_items
		 WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
		itemID, userID,
	))
}

// List returns items owned by userID.
func (r *VaultRepository) List(ctx context.Context, userID uuid.UUID, includeDeleted bool) ([]entity.VaultItem, error) {
	query := `SELECT id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at
	          FROM vault_items WHERE user_id = $1`
	if !includeDeleted {
		query += ` AND deleted_at IS NULL`
	}
	query += ` ORDER BY updated_at DESC, id`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list vault items: %w", err)
	}
	defer rows.Close()
	return scanVaultItems(rows)
}

// Sync returns item changes after a sync cursor and the current user cursor.
func (r *VaultRepository) Sync(ctx context.Context, userID uuid.UUID, afterSyncVersion uint64) ([]entity.VaultItem, uint64, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at
		 FROM vault_items
		 WHERE user_id = $1 AND sync_version > $2
		 ORDER BY sync_version ASC`,
		userID, int64(afterSyncVersion),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("sync vault items: %w", err)
	}
	items, err := scanVaultItems(rows)
	if err != nil {
		return nil, 0, err
	}

	var current int64
	if err := r.pool.QueryRow(ctx,
		`SELECT GREATEST(COALESCE(MAX(sync_version), 0), $2)
		 FROM vault_items WHERE user_id = $1`,
		userID, int64(afterSyncVersion),
	).Scan(&current); err != nil {
		return nil, 0, fmt.Errorf("read sync cursor: %w", err)
	}
	return items, uint64(current), nil
}

func (r *VaultRepository) classifyWriteMiss(ctx context.Context, userID, itemID uuid.UUID, expectedRevision int64) error {
	var revision int64
	var deletedAt pgtype.Timestamptz
	err := r.pool.QueryRow(ctx,
		`SELECT revision, deleted_at FROM vault_items WHERE id = $1 AND user_id = $2`,
		itemID, userID,
	).Scan(&revision, &deletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return apperrors.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("classify vault write miss: %w", err)
	}
	if revision != expectedRevision || deletedAt.Valid {
		return apperrors.ErrConflict
	}
	return apperrors.ErrConflict
}

func scanVaultItems(rows pgx.Rows) ([]entity.VaultItem, error) {
	defer rows.Close()
	var items []entity.VaultItem
	for rows.Next() {
		item, err := scanVaultItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vault items: %w", err)
	}
	return items, nil
}

func scanVaultItem(row pgx.Row) (entity.VaultItem, error) {
	var item entity.VaultItem
	var syncVersion int64
	var deletedAt pgtype.Timestamptz
	if err := row.Scan(
		&item.ID,
		&item.UserID,
		&item.Revision,
		&syncVersion,
		&item.Payload.Nonce,
		&item.Payload.Ciphertext,
		&item.CreatedAt,
		&item.UpdatedAt,
		&deletedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.VaultItem{}, apperrors.ErrNotFound
		}
		return entity.VaultItem{}, fmt.Errorf("scan vault item: %w", err)
	}
	item.SyncVersion = uint64(syncVersion)
	if deletedAt.Valid {
		t := deletedAt.Time
		item.DeletedAt = &t
	}
	return item, nil
}
