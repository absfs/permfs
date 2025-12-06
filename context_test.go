package permfs

import (
	"context"
	"testing"
)

func TestWithUserAndGroups(t *testing.T) {
	ctx := WithUserAndGroups(context.Background(), "alice", []string{"admins", "users"})

	identity, err := GetIdentity(ctx)
	if err != nil {
		t.Fatalf("GetIdentity error: %v", err)
	}

	if identity.UserID != "alice" {
		t.Errorf("expected userID 'alice', got %q", identity.UserID)
	}
	if len(identity.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(identity.Groups))
	}
	if identity.Groups[0] != "admins" || identity.Groups[1] != "users" {
		t.Errorf("unexpected groups: %v", identity.Groups)
	}
}

func TestWithUserGroupsAndRoles(t *testing.T) {
	ctx := WithUserGroupsAndRoles(context.Background(), "bob", []string{"developers"}, []string{"admin", "viewer"})

	identity, err := GetIdentity(ctx)
	if err != nil {
		t.Fatalf("GetIdentity error: %v", err)
	}

	if identity.UserID != "bob" {
		t.Errorf("expected userID 'bob', got %q", identity.UserID)
	}
	if len(identity.Groups) != 1 || identity.Groups[0] != "developers" {
		t.Errorf("unexpected groups: %v", identity.Groups)
	}
	if len(identity.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(identity.Roles))
	}
	if identity.Roles[0] != "admin" || identity.Roles[1] != "viewer" {
		t.Errorf("unexpected roles: %v", identity.Roles)
	}
}

func TestAddMetadata(t *testing.T) {
	ctx := context.Background()

	// Add first key
	ctx = AddMetadata(ctx, "key1", "value1")

	metadata := GetMetadata(ctx)
	if metadata["key1"] != "value1" {
		t.Errorf("expected 'value1', got %v", metadata["key1"])
	}

	// Add second key - should preserve first
	ctx = AddMetadata(ctx, "key2", "value2")

	metadata = GetMetadata(ctx)
	if metadata["key1"] != "value1" {
		t.Errorf("key1 should still be 'value1', got %v", metadata["key1"])
	}
	if metadata["key2"] != "value2" {
		t.Errorf("expected 'value2', got %v", metadata["key2"])
	}
}

func TestAddMetadataToEmptyContext(t *testing.T) {
	ctx := context.Background()

	ctx = AddMetadata(ctx, "test", 123)

	metadata := GetMetadata(ctx)
	if metadata["test"] != 123 {
		t.Errorf("expected 123, got %v", metadata["test"])
	}
}

func TestGetMetadataNoMetadata(t *testing.T) {
	ctx := context.Background()

	metadata := GetMetadata(ctx)
	if metadata == nil {
		t.Error("GetMetadata should return non-nil map")
	}
	if len(metadata) != 0 {
		t.Error("metadata should be empty")
	}
}

func TestGetTokenNotSet(t *testing.T) {
	ctx := context.Background()

	token, ok := GetToken(ctx)
	if ok {
		t.Error("expected ok to be false when no token set")
	}
	if token != "" {
		t.Error("expected empty token")
	}
}

func TestWithIdentityNil(t *testing.T) {
	ctx := WithIdentity(context.Background(), nil)

	_, err := GetIdentity(ctx)
	if err == nil {
		t.Error("expected error when identity is nil")
	}
}
