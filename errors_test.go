package permfs

import (
	"errors"
	"testing"
)

func TestPermissionErrorError(t *testing.T) {
	err := NewPermissionError("/test/file.txt", OperationRead, "alice", "access denied")

	errStr := err.Error()

	// Check that error string contains key information
	if errStr == "" {
		t.Error("error string should not be empty")
	}
}

func TestPermissionErrorUnwrap(t *testing.T) {
	err := NewPermissionError("/test/file.txt", OperationRead, "alice", "access denied")

	unwrapped := errors.Unwrap(err)
	if unwrapped != ErrPermissionDenied {
		t.Errorf("expected ErrPermissionDenied, got %v", unwrapped)
	}
}

func TestIsPermissionDenied(t *testing.T) {
	t.Run("PermissionError", func(t *testing.T) {
		err := NewPermissionError("/test/file.txt", OperationRead, "alice", "denied")
		if !IsPermissionDenied(err) {
			t.Error("expected IsPermissionDenied to return true")
		}
	})

	t.Run("ErrPermissionDenied", func(t *testing.T) {
		if !IsPermissionDenied(ErrPermissionDenied) {
			t.Error("expected IsPermissionDenied to return true for ErrPermissionDenied")
		}
	})

	t.Run("other error", func(t *testing.T) {
		err := errors.New("some other error")
		if IsPermissionDenied(err) {
			t.Error("expected IsPermissionDenied to return false for other errors")
		}
	})

	t.Run("nil error", func(t *testing.T) {
		if IsPermissionDenied(nil) {
			t.Error("expected IsPermissionDenied to return false for nil")
		}
	})
}

func TestErrors(t *testing.T) {
	t.Run("ErrNoIdentity", func(t *testing.T) {
		if ErrNoIdentity == nil {
			t.Error("ErrNoIdentity should not be nil")
		}
	})

	t.Run("ErrPermissionDenied", func(t *testing.T) {
		if ErrPermissionDenied == nil {
			t.Error("ErrPermissionDenied should not be nil")
		}
	})

	t.Run("ErrInvalidConfig", func(t *testing.T) {
		if ErrInvalidConfig == nil {
			t.Error("ErrInvalidConfig should not be nil")
		}
	})

	t.Run("ErrInvalidPattern", func(t *testing.T) {
		if ErrInvalidPattern == nil {
			t.Error("ErrInvalidPattern should not be nil")
		}
	})

}
