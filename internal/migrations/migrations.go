// Package migrations applies PostgreSQL schema migrations for GophKeeper.
package migrations

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

var statements = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`,
	`CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		login TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		kdf_salt BYTEA NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`,
	`CREATE SEQUENCE IF NOT EXISTS vault_sync_version_seq`,
	`CREATE TABLE IF NOT EXISTS vault_items (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		revision BIGINT NOT NULL DEFAULT 1,
		sync_version BIGINT NOT NULL,
		nonce BYTEA NOT NULL,
		ciphertext BYTEA NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		deleted_at TIMESTAMPTZ NULL
	)`,
	`CREATE INDEX IF NOT EXISTS vault_items_user_sync_idx ON vault_items(user_id, sync_version)`,
	`CREATE INDEX IF NOT EXISTS vault_items_user_deleted_idx ON vault_items(user_id, deleted_at)`,
	`INSERT INTO schema_migrations(version) VALUES (1) ON CONFLICT DO NOTHING`,
}

// Up applies all built-in schema migrations.
func Up(ctx context.Context, pool *pgxpool.Pool) error {
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply migration: %w", err)
		}
	}
	return nil
}
