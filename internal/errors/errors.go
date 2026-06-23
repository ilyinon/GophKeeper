// Package apperrors contains typed application-level errors shared by layers.
package apperrors

import "errors"

var (
	// ErrInvalidInput reports malformed or incomplete user input.
	ErrInvalidInput = errors.New("invalid input")
	// ErrAlreadyExists reports a duplicate resource.
	ErrAlreadyExists = errors.New("already exists")
	// ErrNotFound reports a missing resource.
	ErrNotFound = errors.New("not found")
	// ErrUnauthorized reports missing or invalid authentication.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrForbidden reports an authenticated user without required access.
	ErrForbidden = errors.New("forbidden")
	// ErrConflict reports an optimistic concurrency conflict.
	ErrConflict = errors.New("conflict")
)
