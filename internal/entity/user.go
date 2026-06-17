// Package entity contains framework-free GophKeeper business entities.
package entity

import (
	"time"

	"github.com/google/uuid"
)

// User is an account allowed to own encrypted vault items.
type User struct {
	ID           uuid.UUID
	Login        string
	PasswordHash string
	KDFSalt      []byte
	CreatedAt    time.Time
}
