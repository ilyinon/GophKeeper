// Package sqlite contains the CLI local encrypted cache.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

// Session stores local authentication and sync state.
type Session struct {
	UserID          uuid.UUID
	Login           string
	ServerAddr      string
	AccessToken     string
	TokenExpiresAt  time.Time
	KDFSalt         []byte
	LastSyncVersion uint64
}

// Store is a SQLite-backed local cache.
type Store struct {
	db *sql.DB
}

// Open opens or creates a local SQLite cache at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite cache: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the SQLite database.
func (s *Store) Close() error {
	return s.db.Close()
}

// SaveSession upserts local session and sync cursor.
func (s *Store) SaveSession(ctx context.Context, session Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(user_id, login, server_addr, access_token, token_expires_at, kdf_salt, last_sync_version, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(server_addr, login) DO UPDATE SET
		   user_id = excluded.user_id,
		   access_token = excluded.access_token,
		   token_expires_at = excluded.token_expires_at,
		   kdf_salt = excluded.kdf_salt,
		   last_sync_version = excluded.last_sync_version,
		   updated_at = excluded.updated_at`,
		session.UserID.String(),
		session.Login,
		session.ServerAddr,
		session.AccessToken,
		session.TokenExpiresAt.UTC().Format(time.RFC3339Nano),
		session.KDFSalt,
		int64(session.LastSyncVersion),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

// LoadSession returns the latest session, optionally narrowed by server and login.
func (s *Store) LoadSession(ctx context.Context, serverAddr, login string) (Session, error) {
	query := `SELECT user_id, login, server_addr, access_token, token_expires_at, kdf_salt, last_sync_version
	          FROM sessions`
	args := []any{}
	if serverAddr != "" && login != "" {
		query += ` WHERE server_addr = ? AND login = ?`
		args = append(args, serverAddr, login)
	} else if serverAddr != "" {
		query += ` WHERE server_addr = ?`
		args = append(args, serverAddr)
	}
	query += ` ORDER BY updated_at DESC LIMIT 1`
	row := s.db.QueryRowContext(ctx, query, args...)
	return scanSession(row)
}

// SetLastSyncVersion updates the local sync cursor for a session.
func (s *Store) SetLastSyncVersion(ctx context.Context, userID uuid.UUID, serverAddr string, version uint64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_sync_version = ?, updated_at = ? WHERE user_id = ? AND server_addr = ?`,
		int64(version),
		time.Now().UTC().Format(time.RFC3339Nano),
		userID.String(),
		serverAddr,
	)
	if err != nil {
		return fmt.Errorf("set sync version: %w", err)
	}
	return nil
}

// UpsertItems stores encrypted items or tombstones in the local cache.
func (s *Store) UpsertItems(ctx context.Context, userID uuid.UUID, items []entity.VaultItem) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cache transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	for _, item := range items {
		deletedAt := nullableTime(item.DeletedAt)
		nonce := nilToEmpty(item.Payload.Nonce)
		ciphertext := nilToEmpty(item.Payload.Ciphertext)
		_, err = tx.ExecContext(ctx,
			`INSERT INTO cached_items(user_id, id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(user_id, id) DO UPDATE SET
			   revision = excluded.revision,
			   sync_version = excluded.sync_version,
			   nonce = excluded.nonce,
			   ciphertext = excluded.ciphertext,
			   created_at = excluded.created_at,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at`,
			userID.String(),
			item.ID.String(),
			item.Revision,
			int64(item.SyncVersion),
			nonce,
			ciphertext,
			item.CreatedAt.UTC().Format(time.RFC3339Nano),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			deletedAt,
		)
		if err != nil {
			return fmt.Errorf("upsert cached item: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit cache transaction: %w", err)
	}
	return nil
}

// GetItem returns one encrypted cached item.
func (s *Store) GetItem(ctx context.Context, userID, itemID uuid.UUID, includeDeleted bool) (entity.VaultItem, error) {
	query := `SELECT id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at
	          FROM cached_items WHERE user_id = ? AND id = ?`
	if !includeDeleted {
		query += ` AND deleted_at IS NULL`
	}
	return scanCachedItem(s.db.QueryRowContext(ctx, query, userID.String(), itemID.String()))
}

// ListItems returns encrypted cached items for a user.
func (s *Store) ListItems(ctx context.Context, userID uuid.UUID, includeDeleted bool) ([]entity.VaultItem, error) {
	query := `SELECT id, user_id, revision, sync_version, nonce, ciphertext, created_at, updated_at, deleted_at
	          FROM cached_items WHERE user_id = ?`
	if !includeDeleted {
		query += ` AND deleted_at IS NULL`
	}
	query += ` ORDER BY updated_at DESC, id`
	rows, err := s.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, fmt.Errorf("list cached items: %w", err)
	}
	defer rows.Close()

	var items []entity.VaultItem
	for rows.Next() {
		item, err := scanCachedItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cached items: %w", err)
	}
	return items, nil
}

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode = WAL`,
		`CREATE TABLE IF NOT EXISTS sessions (
			user_id TEXT NOT NULL,
			login TEXT NOT NULL,
			server_addr TEXT NOT NULL,
			access_token TEXT NOT NULL,
			token_expires_at TEXT NOT NULL,
			kdf_salt BLOB NOT NULL,
			last_sync_version INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(server_addr, login)
		)`,
		`CREATE TABLE IF NOT EXISTS cached_items (
			user_id TEXT NOT NULL,
			id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			sync_version INTEGER NOT NULL,
			nonce BLOB NOT NULL,
			ciphertext BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			deleted_at TEXT NULL,
			PRIMARY KEY(user_id, id)
		)`,
		`CREATE INDEX IF NOT EXISTS cached_items_user_sync_idx ON cached_items(user_id, sync_version)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite cache: %w", err)
		}
	}
	return nil
}

func scanSession(row scanner) (Session, error) {
	var session Session
	var userID string
	var expiresAt string
	var syncVersion int64
	if err := row.Scan(
		&userID,
		&session.Login,
		&session.ServerAddr,
		&session.AccessToken,
		&expiresAt,
		&session.KDFSalt,
		&syncVersion,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, apperrors.ErrNotFound
		}
		return Session{}, fmt.Errorf("scan session: %w", err)
	}
	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return Session{}, fmt.Errorf("parse cached user id: %w", err)
	}
	parsedExpiresAt, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse token expiry: %w", err)
	}
	session.UserID = parsedUserID
	session.TokenExpiresAt = parsedExpiresAt
	session.LastSyncVersion = uint64(syncVersion)
	return session, nil
}

func scanCachedItem(row scanner) (entity.VaultItem, error) {
	var item entity.VaultItem
	var itemID string
	var userID string
	var syncVersion int64
	var createdAt string
	var updatedAt string
	var deletedAt sql.NullString
	if err := row.Scan(
		&itemID,
		&userID,
		&item.Revision,
		&syncVersion,
		&item.Payload.Nonce,
		&item.Payload.Ciphertext,
		&createdAt,
		&updatedAt,
		&deletedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.VaultItem{}, apperrors.ErrNotFound
		}
		return entity.VaultItem{}, fmt.Errorf("scan cached item: %w", err)
	}

	parsedItemID, err := uuid.Parse(itemID)
	if err != nil {
		return entity.VaultItem{}, fmt.Errorf("parse cached item id: %w", err)
	}
	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return entity.VaultItem{}, fmt.Errorf("parse cached item user id: %w", err)
	}
	item.ID = parsedItemID
	item.UserID = parsedUserID
	item.SyncVersion = uint64(syncVersion)
	item.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return entity.VaultItem{}, fmt.Errorf("parse cached item created_at: %w", err)
	}
	item.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return entity.VaultItem{}, fmt.Errorf("parse cached item updated_at: %w", err)
	}
	if deletedAt.Valid {
		t, err := time.Parse(time.RFC3339Nano, deletedAt.String)
		if err != nil {
			return entity.VaultItem{}, fmt.Errorf("parse cached item deleted_at: %w", err)
		}
		item.DeletedAt = &t
	}
	return item, nil
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func nilToEmpty(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

type scanner interface {
	Scan(dest ...any) error
}
