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

func TestValidationError(t *testing.T) {
	err := ValidationError{
		Field:   "PathPattern",
		Message: "pattern is empty",
	}

	errStr := err.Error()
	if errStr != "PathPattern: pattern is empty" {
		t.Errorf("unexpected error string: %q", errStr)
	}
}

func TestValidationResultAddError(t *testing.T) {
	result := ValidationResult{Valid: true}

	result.AddError("field1", "error1")
	if result.Valid {
		t.Error("result should be invalid after AddError")
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}

	result.AddError("field2", "error2")
	if len(result.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(result.Errors))
	}
}

func TestValidateACLEntry(t *testing.T) {
	tests := []struct {
		name        string
		entry       ACLEntry
		expectValid bool
	}{
		{
			name: "valid entry",
			entry: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/home/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			expectValid: true,
		},
		{
			name: "empty subject ID",
			entry: ACLEntry{
				Subject:     User(""),
				PathPattern: "/test/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			expectValid: false,
		},
		{
			name: "everyone subject with any ID is valid",
			entry: ACLEntry{
				Subject:     Everyone(),
				PathPattern: "/test/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			expectValid: true,
		},
		{
			name: "empty path pattern",
			entry: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			expectValid: false,
		},
		{
			name: "invalid path pattern with ***",
			entry: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/test/***",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			expectValid: false,
		},
		{
			name: "zero permissions",
			entry: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/test/**",
				Permissions: 0,
				Effect:      Allow,
				Priority:    100,
			},
			expectValid: false,
		},
		{
			name: "negative priority",
			entry: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/test/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    -5,
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateACLEntry(tt.entry)
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got %v; errors: %v", tt.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

func TestRulesCanConflict(t *testing.T) {
	tests := []struct {
		name           string
		rule1          ACLEntry
		rule2          ACLEntry
		expectConflict bool
	}{
		{
			name: "different priorities - no conflict",
			rule1: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			rule2: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Deny,
				Priority:    200,
			},
			expectConflict: false,
		},
		{
			name: "same effect - no conflict",
			rule1: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			rule2: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			expectConflict: false,
		},
		{
			name: "different subjects - no conflict",
			rule1: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			rule2: ACLEntry{
				Subject:     User("bob"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Deny,
				Priority:    100,
			},
			expectConflict: false,
		},
		{
			name: "same priority, different effects, same subject, same pattern - conflict",
			rule1: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			rule2: ACLEntry{
				Subject:     User("alice"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Deny,
				Priority:    100,
			},
			expectConflict: true,
		},
		{
			name: "everyone subjects overlap - conflict",
			rule1: ACLEntry{
				Subject:     Everyone(),
				PathPattern: "/public/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
			rule2: ACLEntry{
				Subject:     Everyone(),
				PathPattern: "/public/**",
				Permissions: Read,
				Effect:      Deny,
				Priority:    100,
			},
			expectConflict: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflict := rulesCanConflict(tt.rule1, tt.rule2)
			if conflict != tt.expectConflict {
				t.Errorf("expected conflict=%v, got %v", tt.expectConflict, conflict)
			}
		})
	}
}

func TestSubjectsOverlap(t *testing.T) {
	tests := []struct {
		name    string
		s1      Subject
		s2      Subject
		overlap bool
	}{
		{
			name:    "same user",
			s1:      User("alice"),
			s2:      User("alice"),
			overlap: true,
		},
		{
			name:    "different users",
			s1:      User("alice"),
			s2:      User("bob"),
			overlap: false,
		},
		{
			name:    "same group",
			s1:      Group("admins"),
			s2:      Group("admins"),
			overlap: true,
		},
		{
			name:    "different groups",
			s1:      Group("admins"),
			s2:      Group("users"),
			overlap: false,
		},
		{
			name:    "both everyone",
			s1:      Everyone(),
			s2:      Everyone(),
			overlap: true,
		},
		{
			name:    "user and group - different types",
			s1:      User("alice"),
			s2:      Group("alice"),
			overlap: false,
		},
		{
			name:    "user and everyone",
			s1:      User("alice"),
			s2:      Everyone(),
			overlap: true, // everyone overlaps with all subjects
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := subjectsOverlap(tt.s1, tt.s2)
			if result != tt.overlap {
				t.Errorf("expected overlap=%v, got %v", tt.overlap, result)
			}
		})
	}
}

func TestPatternsOverlap(t *testing.T) {
	tests := []struct {
		name    string
		p1      string
		p2      string
		overlap bool
	}{
		{
			name:    "identical patterns",
			p1:      "/data/**",
			p2:      "/data/**",
			overlap: true,
		},
		{
			name:    "parent and child patterns",
			p1:      "/data/**",
			p2:      "/data/sub/**",
			overlap: true,
		},
		{
			name:    "child and parent patterns",
			p1:      "/data/sub/**",
			p2:      "/data/**",
			overlap: true,
		},
		{
			name:    "completely different paths with wildcards",
			p1:      "/data/**",
			p2:      "/other/**",
			overlap: true, // patternsOverlap returns true if either has **
		},
		{
			name:    "completely different paths without wildcards",
			p1:      "/data/file.txt",
			p2:      "/other/file.txt",
			overlap: false,
		},
		{
			name:    "wildcard in first pattern",
			p1:      "/**",
			p2:      "/anything/**",
			overlap: true,
		},
		{
			name:    "wildcard in second pattern",
			p1:      "/anything/**",
			p2:      "/**",
			overlap: true,
		},
		{
			name:    "single star wildcards",
			p1:      "/data/*",
			p2:      "/data/*",
			overlap: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := patternsOverlap(tt.p1, tt.p2)
			if result != tt.overlap {
				t.Errorf("expected overlap=%v, got %v for %q and %q", tt.overlap, result, tt.p1, tt.p2)
			}
		})
	}
}

func TestDescribeConflict(t *testing.T) {
	rule1 := ACLEntry{
		Subject:     User("alice"),
		PathPattern: "/data/**",
		Permissions: Read,
		Effect:      Allow,
		Priority:    100,
	}
	rule2 := ACLEntry{
		Subject:     User("alice"),
		PathPattern: "/data/**",
		Permissions: Read,
		Effect:      Deny,
		Priority:    100,
	}

	description := describeConflict(rule1, rule2)

	if description == "" {
		t.Error("description should not be empty")
	}
	if !containsString(description, "Allow") {
		t.Error("description should mention Allow")
	}
	if !containsString(description, "Deny") {
		t.Error("description should mention Deny")
	}
}

func TestEntryKey(t *testing.T) {
	entry1 := ACLEntry{
		Subject:     User("alice"),
		PathPattern: "/data/**",
		Permissions: Read,
		Effect:      Allow,
		Priority:    100,
	}
	entry2 := ACLEntry{
		Subject:     User("alice"),
		PathPattern: "/data/**",
		Permissions: Read,
		Effect:      Allow,
		Priority:    100,
	}
	entry3 := ACLEntry{
		Subject:     User("bob"),
		PathPattern: "/data/**",
		Permissions: Read,
		Effect:      Allow,
		Priority:    100,
	}

	key1 := entryKey(entry1)
	key2 := entryKey(entry2)
	key3 := entryKey(entry3)

	if key1 != key2 {
		t.Error("identical entries should have same key")
	}
	if key1 == key3 {
		t.Error("different entries should have different keys")
	}
}

func TestPermissionTestResultExplainAllowed(t *testing.T) {
	identity := &Identity{UserID: "alice"}
	result := &PermissionTestResult{
		Allowed:   true,
		Path:      "/test/file.txt",
		Operation: OperationRead,
		Identity:  identity,
		MatchingEntries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/test/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    100,
			},
		},
	}

	explanation := result.Explain()

	if !containsString(explanation, "ALLOWED") {
		t.Error("Explanation should show ALLOWED for allowed result")
	}
}

func TestPermissionTestResultExplainNoMatchingEntries(t *testing.T) {
	identity := &Identity{UserID: "bob"}
	result := &PermissionTestResult{
		Allowed:         false,
		Path:            "/test/file.txt",
		Operation:       OperationRead,
		Identity:        identity,
		MatchingEntries: []ACLEntry{},
	}

	explanation := result.Explain()

	if !containsString(explanation, "No matching") || !containsString(explanation, "default") {
		t.Error("Explanation should mention no matching entries and default policy")
	}
}
