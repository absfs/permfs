package permfs

import (
	"errors"
	"fmt"
)

var (
	// ErrPermissionDenied is returned when a permission check fails
	ErrPermissionDenied = errors.New("permission denied")

	// ErrNoIdentity is returned when no identity is found in context
	ErrNoIdentity = errors.New("no identity in context")

	// ErrInvalidPattern is returned when a path pattern is invalid
	ErrInvalidPattern = errors.New("invalid path pattern")

	// ErrInvalidConfig is returned when configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")
)

// PermissionError represents a permission denial with additional context
type PermissionError struct {
	// Path is the filesystem path that was denied
	Path string
	// Operation is the operation that was denied
	Operation Operation
	// UserID is the user who was denied
	UserID string
	// Reason provides additional context for the denial
	Reason string
}

// Error implements the error interface
func (e *PermissionError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("permission denied: user %s cannot perform %s on %s: %s",
			e.UserID, e.Operation, e.Path, e.Reason)
	}
	return fmt.Sprintf("permission denied: user %s cannot perform %s on %s",
		e.UserID, e.Operation, e.Path)
}

// Unwrap returns the underlying error
func (e *PermissionError) Unwrap() error {
	return ErrPermissionDenied
}

// IsPermissionDenied checks if an error is a permission denial
func IsPermissionDenied(err error) bool {
	return errors.Is(err, ErrPermissionDenied)
}

// NewPermissionError creates a new permission error
func NewPermissionError(path string, op Operation, userID string, reason string) error {
	return &PermissionError{
		Path:      path,
		Operation: op,
		UserID:    userID,
		Reason:    reason,
	}
}
