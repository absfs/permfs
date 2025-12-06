package permfs

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestStaticAuthenticator(t *testing.T) {
	t.Run("NewStaticAuthenticator", func(t *testing.T) {
		auth := NewStaticAuthenticator()
		if auth == nil {
			t.Fatal("expected non-nil authenticator")
		}
		if auth.users == nil {
			t.Error("users map should be initialized")
		}
	})

	t.Run("AddUser and AuthenticateToken", func(t *testing.T) {
		auth := NewStaticAuthenticator()
		auth.AddUser("alice", []string{"admins"}, []string{"admin"})

		identity, err := auth.AuthenticateToken("alice")
		if err != nil {
			t.Fatalf("AuthenticateToken error: %v", err)
		}
		if identity.UserID != "alice" {
			t.Errorf("expected userID 'alice', got %q", identity.UserID)
		}
		if len(identity.Groups) != 1 || identity.Groups[0] != "admins" {
			t.Errorf("expected groups [admins], got %v", identity.Groups)
		}
		if len(identity.Roles) != 1 || identity.Roles[0] != "admin" {
			t.Errorf("expected roles [admin], got %v", identity.Roles)
		}
	})

	t.Run("AuthenticateToken invalid token", func(t *testing.T) {
		auth := NewStaticAuthenticator()
		_, err := auth.AuthenticateToken("invalid")
		if err == nil {
			t.Error("expected error for invalid token")
		}
	})

	t.Run("Authenticate with identity in context", func(t *testing.T) {
		auth := NewStaticAuthenticator()
		ctx := WithUser(context.Background(), "alice")

		identity, err := auth.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "alice" {
			t.Errorf("expected userID 'alice', got %q", identity.UserID)
		}
	})

	t.Run("Authenticate with token in context", func(t *testing.T) {
		auth := NewStaticAuthenticator()
		auth.AddUser("bob", nil, nil)

		ctx := WithToken(context.Background(), "bob")
		identity, err := auth.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "bob" {
			t.Errorf("expected userID 'bob', got %q", identity.UserID)
		}
	})

	t.Run("Authenticate with no identity", func(t *testing.T) {
		auth := NewStaticAuthenticator()
		ctx := context.Background()

		_, err := auth.Authenticate(ctx)
		if err == nil {
			t.Error("expected error when no identity")
		}
	})
}

func TestAPIKeyAuthenticator(t *testing.T) {
	t.Run("NewAPIKeyAuthenticator", func(t *testing.T) {
		auth := NewAPIKeyAuthenticator()
		if auth == nil {
			t.Fatal("expected non-nil authenticator")
		}
		if auth.keys == nil {
			t.Error("keys map should be initialized")
		}
	})

	t.Run("AddAPIKey and AuthenticateToken", func(t *testing.T) {
		auth := NewAPIKeyAuthenticator()
		identity := &Identity{UserID: "service", Groups: []string{"services"}}
		auth.AddAPIKey("api-key-123", identity)

		result, err := auth.AuthenticateToken("api-key-123")
		if err != nil {
			t.Fatalf("AuthenticateToken error: %v", err)
		}
		if result.UserID != "service" {
			t.Errorf("expected userID 'service', got %q", result.UserID)
		}
	})

	t.Run("AuthenticateToken invalid key", func(t *testing.T) {
		auth := NewAPIKeyAuthenticator()
		_, err := auth.AuthenticateToken("invalid")
		if err == nil {
			t.Error("expected error for invalid API key")
		}
	})

	t.Run("Authenticate with API key in metadata", func(t *testing.T) {
		auth := NewAPIKeyAuthenticator()
		auth.AddAPIKey("my-api-key", &Identity{UserID: "apiuser"})

		ctx := WithMetadata(context.Background(), map[string]interface{}{
			"api_key": "my-api-key",
		})

		identity, err := auth.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "apiuser" {
			t.Errorf("expected userID 'apiuser', got %q", identity.UserID)
		}
	})

	t.Run("Authenticate with token fallback", func(t *testing.T) {
		auth := NewAPIKeyAuthenticator()
		auth.AddAPIKey("token-key", &Identity{UserID: "tokenuser"})

		ctx := WithToken(context.Background(), "token-key")

		identity, err := auth.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "tokenuser" {
			t.Errorf("expected userID 'tokenuser', got %q", identity.UserID)
		}
	})

	t.Run("Authenticate with no credentials", func(t *testing.T) {
		auth := NewAPIKeyAuthenticator()
		ctx := context.Background()

		_, err := auth.Authenticate(ctx)
		if err == nil {
			t.Error("expected error when no credentials")
		}
	})
}

func TestChainAuthenticator(t *testing.T) {
	t.Run("NewChainAuthenticator", func(t *testing.T) {
		auth1 := NewStaticAuthenticator()
		auth2 := NewAPIKeyAuthenticator()
		chain := NewChainAuthenticator(auth1, auth2)

		if chain == nil {
			t.Fatal("expected non-nil chain authenticator")
		}
		if len(chain.authenticators) != 2 {
			t.Errorf("expected 2 authenticators, got %d", len(chain.authenticators))
		}
	})

	t.Run("Authenticate uses first successful", func(t *testing.T) {
		auth1 := NewStaticAuthenticator()
		auth1.AddUser("alice", nil, nil)

		auth2 := NewAPIKeyAuthenticator()
		auth2.AddAPIKey("api-key", &Identity{UserID: "api-user"})

		chain := NewChainAuthenticator(auth1, auth2)

		// First authenticator succeeds
		ctx := WithToken(context.Background(), "alice")
		identity, err := chain.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "alice" {
			t.Errorf("expected 'alice', got %q", identity.UserID)
		}
	})

	t.Run("Authenticate falls through to second", func(t *testing.T) {
		auth1 := NewStaticAuthenticator()
		// auth1 has no users

		auth2 := NewAPIKeyAuthenticator()
		auth2.AddAPIKey("api-key", &Identity{UserID: "api-user"})

		chain := NewChainAuthenticator(auth1, auth2)

		ctx := WithToken(context.Background(), "api-key")
		identity, err := chain.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "api-user" {
			t.Errorf("expected 'api-user', got %q", identity.UserID)
		}
	})

	t.Run("Authenticate all fail", func(t *testing.T) {
		auth1 := NewStaticAuthenticator()
		auth2 := NewAPIKeyAuthenticator()
		chain := NewChainAuthenticator(auth1, auth2)

		ctx := context.Background()
		_, err := chain.Authenticate(ctx)
		if err == nil {
			t.Error("expected error when all authenticators fail")
		}
	})

	t.Run("Authenticate empty chain", func(t *testing.T) {
		chain := NewChainAuthenticator()
		ctx := context.Background()

		_, err := chain.Authenticate(ctx)
		if err == nil {
			t.Error("expected error for empty chain")
		}
	})
}

func TestFuncAuthenticator(t *testing.T) {
	t.Run("Authenticate calls function", func(t *testing.T) {
		called := false
		auth := FuncAuthenticator(func(ctx context.Context) (*Identity, error) {
			called = true
			return &Identity{UserID: "funcuser"}, nil
		})

		identity, err := auth.Authenticate(context.Background())
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if !called {
			t.Error("function should be called")
		}
		if identity.UserID != "funcuser" {
			t.Errorf("expected 'funcuser', got %q", identity.UserID)
		}
	})
}

func TestHeaderAuthenticator(t *testing.T) {
	t.Run("NewHeaderAuthenticator", func(t *testing.T) {
		auth := NewHeaderAuthenticator("X-User", "X-Groups", "X-Roles")
		if auth == nil {
			t.Fatal("expected non-nil authenticator")
		}
		if auth.userHeader != "X-User" {
			t.Errorf("expected userHeader 'X-User', got %q", auth.userHeader)
		}
		if auth.separator != "," {
			t.Errorf("expected separator ',', got %q", auth.separator)
		}
	})

	t.Run("Authenticate with all headers", func(t *testing.T) {
		auth := NewHeaderAuthenticator("X-User", "X-Groups", "X-Roles")

		ctx := WithMetadata(context.Background(), map[string]interface{}{
			"X-User":   "alice",
			"X-Groups": "admins,users",
			"X-Roles":  "admin,viewer",
		})

		identity, err := auth.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "alice" {
			t.Errorf("expected userID 'alice', got %q", identity.UserID)
		}
		if len(identity.Groups) != 2 {
			t.Errorf("expected 2 groups, got %d", len(identity.Groups))
		}
		if len(identity.Roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(identity.Roles))
		}
	})

	t.Run("Authenticate with only user header", func(t *testing.T) {
		auth := NewHeaderAuthenticator("X-User", "X-Groups", "X-Roles")

		ctx := WithMetadata(context.Background(), map[string]interface{}{
			"X-User": "bob",
		})

		identity, err := auth.Authenticate(ctx)
		if err != nil {
			t.Fatalf("Authenticate error: %v", err)
		}
		if identity.UserID != "bob" {
			t.Errorf("expected userID 'bob', got %q", identity.UserID)
		}
		if identity.Groups != nil && len(identity.Groups) > 0 {
			t.Error("groups should be empty")
		}
	})

	t.Run("Authenticate missing user header", func(t *testing.T) {
		auth := NewHeaderAuthenticator("X-User", "X-Groups", "X-Roles")
		ctx := context.Background()

		_, err := auth.Authenticate(ctx)
		if err == nil {
			t.Error("expected error when user header is missing")
		}
	})

	t.Run("Authenticate empty user header", func(t *testing.T) {
		auth := NewHeaderAuthenticator("X-User", "X-Groups", "X-Roles")

		ctx := WithMetadata(context.Background(), map[string]interface{}{
			"X-User": "",
		})

		_, err := auth.Authenticate(ctx)
		if err == nil {
			t.Error("expected error when user header is empty")
		}
	})
}

func TestNewPermFSWithAuthenticator(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	config := Config{
		ACL: ACL{
			Entries: []ACLEntry{
				{
					Subject:     User("testuser"),
					PathPattern: "/**",
					Permissions: All,
					Effect:      Allow,
					Priority:    100,
				},
			},
			Default: Deny,
		},
	}

	auth := NewStaticAuthenticator()
	auth.AddUser("testuser", nil, nil)

	pfs, err := NewPermFSWithAuthenticator(mock, config, auth)
	if err != nil {
		t.Fatalf("NewPermFSWithAuthenticator error: %v", err)
	}
	if pfs == nil {
		t.Fatal("expected non-nil PermFS")
	}
}

func TestAuthFSDirectly(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("testuser"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	// Create a PermFS as the base
	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	auth := NewStaticAuthenticator()
	auth.AddUser("testuser", nil, nil)

	// Create authFS wrapper directly
	afs := &authFS{base: pfs, auth: auth}

	// Test with token that will authenticate to testuser
	ctx := WithToken(context.Background(), "testuser")

	t.Run("OpenFile", func(t *testing.T) {
		f, err := afs.OpenFile(ctx, "/test/file.txt", os.O_RDONLY, 0644)
		if err != nil {
			t.Errorf("OpenFile error: %v", err)
		}
		if f != nil {
			f.Close()
		}
	})

	t.Run("Mkdir", func(t *testing.T) {
		err := afs.Mkdir(ctx, "/test/dir", 0755)
		if err != nil {
			t.Errorf("Mkdir error: %v", err)
		}
	})

	t.Run("MkdirAll", func(t *testing.T) {
		err := afs.MkdirAll(ctx, "/test/a/b/c", 0755)
		if err != nil {
			t.Errorf("MkdirAll error: %v", err)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		err := afs.Remove(ctx, "/test/file.txt")
		if err != nil {
			t.Errorf("Remove error: %v", err)
		}
	})

	t.Run("RemoveAll", func(t *testing.T) {
		err := afs.RemoveAll(ctx, "/test/dir")
		if err != nil {
			t.Errorf("RemoveAll error: %v", err)
		}
	})

	t.Run("Rename", func(t *testing.T) {
		err := afs.Rename(ctx, "/test/old.txt", "/test/new.txt")
		if err != nil {
			t.Errorf("Rename error: %v", err)
		}
	})

	t.Run("Stat", func(t *testing.T) {
		_, err := afs.Stat(ctx, "/test/file.txt")
		if err != nil {
			t.Errorf("Stat error: %v", err)
		}
	})

	t.Run("Lstat", func(t *testing.T) {
		_, err := afs.Lstat(ctx, "/test/file.txt")
		if err != nil {
			t.Errorf("Lstat error: %v", err)
		}
	})

	t.Run("ReadDir", func(t *testing.T) {
		_, err := afs.ReadDir(ctx, "/test")
		if err != nil {
			t.Errorf("ReadDir error: %v", err)
		}
	})

	t.Run("Chmod", func(t *testing.T) {
		err := afs.Chmod(ctx, "/test/file.txt", 0600)
		if err != nil {
			t.Errorf("Chmod error: %v", err)
		}
	})

	t.Run("Chown", func(t *testing.T) {
		err := afs.Chown(ctx, "/test/file.txt", 1000, 1000)
		if err != nil {
			t.Errorf("Chown error: %v", err)
		}
	})

	t.Run("Chtimes", func(t *testing.T) {
		now := time.Now()
		err := afs.Chtimes(ctx, "/test/file.txt", now, now)
		if err != nil {
			t.Errorf("Chtimes error: %v", err)
		}
	})
}

func TestAuthFSWithExistingIdentity(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("testuser"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	auth := NewStaticAuthenticator()
	// Don't add the user - should still work if identity is in context
	afs := &authFS{base: pfs, auth: auth}

	// Use identity directly in context (bypasses authenticator)
	ctx := WithUser(context.Background(), "testuser")

	_, err = afs.Stat(ctx, "/test/file.txt")
	if err != nil {
		t.Errorf("Stat error with existing identity: %v", err)
	}
}

func TestAuthFSAuthenticationFailure(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{Default: Allow}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	auth := NewStaticAuthenticator()
	// No users added - authentication will fail
	afs := &authFS{base: pfs, auth: auth}

	// No identity in context, no token - should fail
	ctx := context.Background()

	_, err = afs.Stat(ctx, "/test/file.txt")
	if err == nil {
		t.Error("expected authentication error")
	}
}
