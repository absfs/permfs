package permfs

import (
	"testing"
	"time"
)

func TestEvaluatorBasicPermissions(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     User("bob"),
				PathPattern: "/home/bob/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)

	tests := []struct {
		name      string
		identity  *Identity
		path      string
		operation Operation
		expected  bool
	}{
		{
			name:      "alice can read her files",
			identity:  &Identity{UserID: "alice"},
			path:      "/home/alice/file.txt",
			operation: OperationRead,
			expected:  true,
		},
		{
			name:      "alice can write her files",
			identity:  &Identity{UserID: "alice"},
			path:      "/home/alice/file.txt",
			operation: OperationWrite,
			expected:  true,
		},
		{
			name:      "alice cannot delete her files (not granted)",
			identity:  &Identity{UserID: "alice"},
			path:      "/home/alice/file.txt",
			operation: OperationDelete,
			expected:  false,
		},
		{
			name:      "bob can read his files",
			identity:  &Identity{UserID: "bob"},
			path:      "/home/bob/file.txt",
			operation: OperationRead,
			expected:  true,
		},
		{
			name:      "bob cannot write his files (only read granted)",
			identity:  &Identity{UserID: "bob"},
			path:      "/home/bob/file.txt",
			operation: OperationWrite,
			expected:  false,
		},
		{
			name:      "alice cannot access bob's files",
			identity:  &Identity{UserID: "alice"},
			path:      "/home/bob/file.txt",
			operation: OperationRead,
			expected:  false,
		},
		{
			name:      "bob cannot access alice's files",
			identity:  &Identity{UserID: "bob"},
			path:      "/home/alice/file.txt",
			operation: OperationRead,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &EvaluationContext{
				Identity:  tt.identity,
				Path:      tt.path,
				Operation: tt.operation,
			}

			got, err := evaluator.Evaluate(ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("Evaluate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEvaluatorPriorityConflictResolution(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			// High priority deny overrides lower priority allow
			{
				Subject:     User("alice"),
				PathPattern: "/secrets/**",
				Permissions: All,
				Effect:      Deny,
				Priority:    1000,
			},
			{
				Subject:     User("alice"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)

	tests := []struct {
		name      string
		path      string
		operation Operation
		expected  bool
	}{
		{
			name:      "high priority deny blocks access to secrets",
			path:      "/secrets/key.txt",
			operation: OperationRead,
			expected:  false,
		},
		{
			name:      "lower priority allow grants access to other files",
			path:      "/data/file.txt",
			operation: OperationRead,
			expected:  true,
		},
	}

	identity := &Identity{UserID: "alice"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &EvaluationContext{
				Identity:  identity,
				Path:      tt.path,
				Operation: tt.operation,
			}

			got, err := evaluator.Evaluate(ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("Evaluate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEvaluatorGroupPermissions(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     Group("engineering"),
				PathPattern: "/projects/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     Group("managers"),
				PathPattern: "/**",
				Permissions: Read | Metadata,
				Effect:      Allow,
				Priority:    50,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)

	tests := []struct {
		name      string
		identity  *Identity
		path      string
		operation Operation
		expected  bool
	}{
		{
			name: "engineering group member can read projects",
			identity: &Identity{
				UserID: "alice",
				Groups: []string{"engineering"},
			},
			path:      "/projects/app/code.go",
			operation: OperationRead,
			expected:  true,
		},
		{
			name: "engineering group member can write projects",
			identity: &Identity{
				UserID: "alice",
				Groups: []string{"engineering"},
			},
			path:      "/projects/app/code.go",
			operation: OperationWrite,
			expected:  true,
		},
		{
			name: "manager can read projects",
			identity: &Identity{
				UserID: "bob",
				Groups: []string{"managers"},
			},
			path:      "/projects/app/code.go",
			operation: OperationRead,
			expected:  true,
		},
		{
			name: "manager cannot write projects",
			identity: &Identity{
				UserID: "bob",
				Groups: []string{"managers"},
			},
			path:      "/projects/app/code.go",
			operation: OperationWrite,
			expected:  false,
		},
		{
			name: "manager can read metadata anywhere",
			identity: &Identity{
				UserID: "bob",
				Groups: []string{"managers"},
			},
			path:      "/home/alice/file.txt",
			operation: OperationMetadata,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &EvaluationContext{
				Identity:  tt.identity,
				Path:      tt.path,
				Operation: tt.operation,
			}

			got, err := evaluator.Evaluate(ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("Evaluate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEvaluatorRolePermissions(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     Role("admin"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    1000,
			},
			{
				Subject:     Role("intern"),
				PathPattern: "/public/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    10,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)

	tests := []struct {
		name      string
		identity  *Identity
		path      string
		operation Operation
		expected  bool
	}{
		{
			name: "admin can do anything",
			identity: &Identity{
				UserID: "alice",
				Roles:  []string{"admin"},
			},
			path:      "/secrets/key.txt",
			operation: OperationDelete,
			expected:  true,
		},
		{
			name: "intern can read public files",
			identity: &Identity{
				UserID: "bob",
				Roles:  []string{"intern"},
			},
			path:      "/public/readme.txt",
			operation: OperationRead,
			expected:  true,
		},
		{
			name: "intern cannot write public files",
			identity: &Identity{
				UserID: "bob",
				Roles:  []string{"intern"},
			},
			path:      "/public/readme.txt",
			operation: OperationWrite,
			expected:  false,
		},
		{
			name: "intern cannot read private files",
			identity: &Identity{
				UserID: "bob",
				Roles:  []string{"intern"},
			},
			path:      "/secrets/key.txt",
			operation: OperationRead,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &EvaluationContext{
				Identity:  tt.identity,
				Path:      tt.path,
				Operation: tt.operation,
			}

			got, err := evaluator.Evaluate(ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("Evaluate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEvaluatorEveryonePermissions(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     Everyone(),
				PathPattern: "/public/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    1,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)

	tests := []struct {
		name      string
		userID    string
		path      string
		operation Operation
		expected  bool
	}{
		{
			name:      "anyone can read public files",
			userID:    "alice",
			path:      "/public/file.txt",
			operation: OperationRead,
			expected:  true,
		},
		{
			name:      "anyone cannot write public files",
			userID:    "bob",
			path:      "/public/file.txt",
			operation: OperationWrite,
			expected:  false,
		},
		{
			name:      "anyone cannot read private files",
			userID:    "charlie",
			path:      "/private/file.txt",
			operation: OperationRead,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &EvaluationContext{
				Identity: &Identity{
					UserID: tt.userID,
				},
				Path:      tt.path,
				Operation: tt.operation,
			}

			got, err := evaluator.Evaluate(ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("Evaluate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetEffectivePermissions(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite | Delete,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)
	identity := &Identity{UserID: "alice"}

	perms := evaluator.GetEffectivePermissions(identity, "/home/alice/file.txt")

	if !perms.Has(OperationRead) {
		t.Error("Expected Read permission")
	}
	if !perms.Has(OperationWrite) {
		t.Error("Expected Write permission")
	}
	if !perms.Has(OperationDelete) {
		t.Error("Expected Delete permission")
	}
	if perms.Has(OperationExecute) {
		t.Error("Did not expect Execute permission")
	}
	if perms.Has(OperationAdmin) {
		t.Error("Did not expect Admin permission")
	}
}

func TestConvenienceMethods(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)
	identity := &Identity{UserID: "alice"}

	if !evaluator.CanRead(identity, "/data/file.txt") {
		t.Error("Expected alice to be able to read")
	}
	if !evaluator.CanWrite(identity, "/data/file.txt") {
		t.Error("Expected alice to be able to write")
	}
	if evaluator.CanDelete(identity, "/data/file.txt") {
		t.Error("Expected alice not to be able to delete")
	}
	if evaluator.IsAdmin(identity, "/data/file.txt") {
		t.Error("Expected alice not to be admin")
	}
}

func TestNewEvaluatorWithCache(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	permCache := NewPermissionCache(100, 5*time.Minute)
	patternCache := NewPatternCache()

	evaluator := NewEvaluatorWithCache(acl, permCache, patternCache)

	// Test that evaluation works with cache
	ctx := &EvaluationContext{
		Identity:  &Identity{UserID: "alice"},
		Path:      "/home/alice/file.txt",
		Operation: OperationRead,
	}

	allowed, err := evaluator.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected access to be allowed")
	}

	// Second call should use cache
	allowed2, err2 := evaluator.Evaluate(ctx)
	if err2 != nil {
		t.Fatalf("Unexpected error on second call: %v", err2)
	}
	if !allowed2 {
		t.Error("Expected access to be allowed on cache hit")
	}

	// Check cache stats
	stats := permCache.Stats()
	if stats.Hits == 0 {
		t.Error("Expected cache hits > 0")
	}
}

func TestGetMatchingEntries(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     Everyone(),
				PathPattern: "/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    1,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)

	ctx := &EvaluationContext{
		Identity:  &Identity{UserID: "alice"},
		Path:      "/home/alice/file.txt",
		Operation: OperationRead,
	}

	entries := evaluator.GetMatchingEntries(ctx)
	if len(entries) != 2 {
		t.Errorf("Expected 2 matching entries, got %d", len(entries))
	}
}

func TestCanExecute(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/bin/**",
				Permissions: Execute,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)
	identity := &Identity{UserID: "alice"}

	if !evaluator.CanExecute(identity, "/bin/script.sh") {
		t.Error("Expected alice to be able to execute")
	}

	if evaluator.CanExecute(identity, "/home/file.txt") {
		t.Error("Expected alice not to be able to execute outside /bin")
	}
}

func TestCanAccessMetadata(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Metadata,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)
	identity := &Identity{UserID: "alice"}

	if !evaluator.CanAccessMetadata(identity, "/data/file.txt") {
		t.Error("Expected alice to be able to access metadata")
	}

	if evaluator.CanAccessMetadata(identity, "/home/file.txt") {
		t.Error("Expected alice not to be able to access metadata outside /data")
	}
}

func TestEvaluatorInvalidateCache(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	permCache := NewPermissionCache(100, 5*time.Minute)
	evaluator := NewEvaluatorWithCache(acl, permCache, nil)

	ctx := &EvaluationContext{
		Identity:  &Identity{UserID: "alice"},
		Path:      "/file.txt",
		Operation: OperationRead,
	}

	// Populate cache
	evaluator.Evaluate(ctx)

	// Invalidate
	evaluator.InvalidateCache("alice", "/file")

	// Should get a miss after invalidation
	stats := permCache.Stats()
	initialMisses := stats.Misses

	evaluator.Evaluate(ctx)

	stats = permCache.Stats()
	if stats.Misses <= initialMisses {
		t.Error("Expected cache miss after invalidation")
	}
}

func TestEvaluatorInvalidateCacheNoCache(t *testing.T) {
	acl := ACL{Default: Deny}
	evaluator := NewEvaluator(acl)

	// Should not panic when no cache
	evaluator.InvalidateCache("alice", "/path")
}

func TestEvaluatorGetCacheStats(t *testing.T) {
	acl := ACL{Default: Deny}

	// Without cache
	evaluator := NewEvaluator(acl)
	stats := evaluator.GetCacheStats()
	if stats != nil {
		t.Error("Expected nil stats when no cache")
	}

	// With cache
	permCache := NewPermissionCache(100, 5*time.Minute)
	evaluatorWithCache := NewEvaluatorWithCache(acl, permCache, nil)
	stats = evaluatorWithCache.GetCacheStats()
	if stats == nil {
		t.Error("Expected non-nil stats when cache exists")
	}
}

func TestEvaluatorClearCacheNoCache(t *testing.T) {
	acl := ACL{Default: Deny}
	evaluator := NewEvaluator(acl)

	// Should not panic when no cache
	evaluator.ClearCache()
}

func TestEvaluatorDefaultAllow(t *testing.T) {
	acl := ACL{
		Entries: []ACLEntry{},
		Default: Allow, // Default allow when no rules match
	}

	evaluator := NewEvaluator(acl)

	ctx := &EvaluationContext{
		Identity:  &Identity{UserID: "anyone"},
		Path:      "/anything",
		Operation: OperationRead,
	}

	allowed, err := evaluator.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected access to be allowed with default allow policy")
	}
}

func BenchmarkEvaluate(b *testing.B) {
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     Group("engineering"),
				PathPattern: "/projects/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     Everyone(),
				PathPattern: "/public/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    1,
			},
		},
		Default: Deny,
	}

	evaluator := NewEvaluator(acl)
	ctx := &EvaluationContext{
		Identity: &Identity{
			UserID: "alice",
			Groups: []string{"engineering"},
		},
		Path:      "/home/alice/file.txt",
		Operation: OperationRead,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = evaluator.Evaluate(ctx)
	}
}
