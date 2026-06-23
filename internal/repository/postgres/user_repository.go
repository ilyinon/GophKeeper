package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/oilyin/gophkeeper/internal/entity"
	apperrors "github.com/oilyin/gophkeeper/internal/errors"
)

// UserRepository stores users in PostgreSQL.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository creates a PostgreSQL user repository.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// Create inserts a new user.
func (r *UserRepository) Create(ctx context.Context, user entity.User) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO users(id, login, password_hash, kdf_salt, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		user.ID, user.Login, user.PasswordHash, user.KDFSalt, user.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: login already exists", apperrors.ErrAlreadyExists)
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// GetByLogin returns a user by normalized login.
func (r *UserRepository) GetByLogin(ctx context.Context, login string) (entity.User, error) {
	return r.scanUser(r.pool.QueryRow(ctx,
		`SELECT id, login, password_hash, kdf_salt, created_at
		 FROM users WHERE login = $1`,
		login,
	))
}

// GetByID returns a user by ID.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (entity.User, error) {
	return r.scanUser(r.pool.QueryRow(ctx,
		`SELECT id, login, password_hash, kdf_salt, created_at
		 FROM users WHERE id = $1`,
		id,
	))
}

func (r *UserRepository) scanUser(row pgx.Row) (entity.User, error) {
	var user entity.User
	if err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.KDFSalt, &user.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.User{}, apperrors.ErrNotFound
		}
		return entity.User{}, fmt.Errorf("scan user: %w", err)
	}
	return user, nil
}
