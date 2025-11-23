package permfs

import (
	"testing"
)

func TestValidateACL(t *testing.T) {
	tests := []struct {
		name        string
		acl         ACL
		expectValid bool
		errorCount  int
	}{
		{
			name: "valid ACL",
			acl: ACL{
				Default: Deny,
				Entries: []ACLEntry{
					{
						Subject:     User("alice"),
						PathPattern: "/home/alice/**",
						Permissions: ReadWrite,
						Effect:      Allow,
						Priority:    100,
					},
				},
			},
			expectValid: true,
			errorCount:  0,
		},
		{
			name: "empty subject ID",
			acl: ACL{
				Default: Deny,
				Entries: []ACLEntry{
					{
						Subject:     User(""),
						PathPattern: "/test/**",
						Permissions: Read,
						Effect:      Allow,
						Priority:    100,
					},
				},
			},
			expectValid: false,
			errorCount:  1,
		},
		{
			name: "empty path pattern",
			acl: ACL{
				Default: Deny,
				Entries: []ACLEntry{
					{
						Subject:     User("alice"),
						PathPattern: "",
						Permissions: Read,
						Effect:      Allow,
						Priority:    100,
					},
				},
			},
			expectValid: false,
			errorCount:  1,
		},
		{
			name: "no permissions",
			acl: ACL{
				Default: Deny,
				Entries: []ACLEntry{
					{
						Subject:     User("alice"),
						PathPattern: "/test/**",
						Permissions: 0,
						Effect:      Allow,
						Priority:    100,
					},
				},
			},
			expectValid: false,
			errorCount:  1,
		},
		{
			name: "negative priority",
			acl: ACL{
				Default: Deny,
				Entries: []ACLEntry{
					{
						Subject:     User("alice"),
						PathPattern: "/test/**",
						Permissions: Read,
						Effect:      Allow,
						Priority:    -1,
					},
				},
			},
			expectValid: false,
			errorCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateACL(tt.acl)

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v", tt.expectValid, result.Valid)
			}

			if len(result.Errors) != tt.errorCount {
				t.Errorf("Expected %d errors, got %d: %v",
					tt.errorCount, len(result.Errors), result.Errors)
			}
		})
	}
}

func TestValidatePathPattern(t *testing.T) {
	tests := []struct {
		pattern     string
		expectError bool
	}{
		{"/home/**", false},
		{"/data/*", false},
		{"/test", false},
		{"", true},
		{"/invalid/***", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			err := validatePathPattern(tt.pattern)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestTestPermission(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Default: Deny,
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     User("alice"),
				PathPattern: "/secrets/**",
				Permissions: All,
				Effect:      Deny,
				Priority:    1000,
			},
		},
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("Failed to create PermFS: %v", err)
	}

	tests := []struct {
		name      string
		userID    string
		path      string
		operation Operation
		expected  bool
	}{
		{
			name:      "allowed access",
			userID:    "alice",
			path:      "/home/alice/file.txt",
			operation: OperationRead,
			expected:  true,
		},
		{
			name:      "denied by explicit deny",
			userID:    "alice",
			path:      "/secrets/key.txt",
			operation: OperationRead,
			expected:  false,
		},
		{
			name:      "denied by default",
			userID:    "bob",
			path:      "/home/alice/file.txt",
			operation: OperationRead,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{UserID: tt.userID}
			allowed, result := pfs.TestPermission(identity, tt.path, tt.operation)

			if allowed != tt.expected {
				t.Errorf("Expected %v, got %v\nExplanation:\n%s",
					tt.expected, allowed, result.Explain())
			}

			if result.Path != tt.path {
				t.Errorf("Result path mismatch")
			}

			if result.Identity.UserID != tt.userID {
				t.Errorf("Result identity mismatch")
			}
		})
	}
}

func TestFindConflictingRules(t *testing.T) {
	acl := ACL{
		Default: Deny,
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: ReadWrite,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: ReadWrite,
				Effect:      Deny,
				Priority:    100,
			},
		},
	}

	conflicts := FindConflictingRules(acl)

	if len(conflicts) == 0 {
		t.Error("Expected to find conflicts")
	}

	if len(conflicts) > 0 {
		conflict := conflicts[0]
		if conflict.Rule1.Effect == conflict.Rule2.Effect {
			t.Error("Conflicting rules should have different effects")
		}
	}
}

func TestOptimizeACL(t *testing.T) {
	// Create ACL with duplicate entries
	acl := ACL{
		Default: Deny,
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     User("bob"),
				PathPattern: "/other/**",
				Permissions: Write,
				Effect:      Allow,
				Priority:    50,
			},
		},
	}

	optimized := OptimizeACL(acl)

	if len(optimized.Entries) != 2 {
		t.Errorf("Expected 2 entries after optimization, got %d", len(optimized.Entries))
	}
}

func TestPermissionTestResultExplain(t *testing.T) {
	identity := &Identity{UserID: "alice"}
	result := &PermissionTestResult{
		Allowed:   false,
		Path:      "/test/file.txt",
		Operation: OperationRead,
		Identity:  identity,
		MatchingEntries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/test/**",
				Permissions: Read,
				Effect:      Deny,
				Priority:    100,
			},
		},
	}

	explanation := result.Explain()

	if explanation == "" {
		t.Error("Explanation should not be empty")
	}

	// Check that explanation contains key information
	if !containsString(explanation, "alice") {
		t.Error("Explanation should mention user")
	}
	if !containsString(explanation, "DENIED") {
		t.Error("Explanation should show result")
	}
}

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && indexString(s, substr) >= 0)
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
