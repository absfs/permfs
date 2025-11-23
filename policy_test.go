package permfs

import (
	"bytes"
	"strings"
	"testing"
)

func TestPolicyExportImport(t *testing.T) {
	// Create a test ACL
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
				Subject:     Group("admins"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    1000,
			},
		},
	}

	// Export to policy
	policy := ExportPolicy(acl, "Test Policy")

	if policy.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", policy.Version)
	}

	if policy.Description != "Test Policy" {
		t.Errorf("Expected description 'Test Policy', got %s", policy.Description)
	}

	if len(policy.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(policy.Entries))
	}

	// Import back
	imported, err := ImportPolicy(policy)
	if err != nil {
		t.Fatalf("Failed to import policy: %v", err)
	}

	if imported.Default != acl.Default {
		t.Errorf("Default mismatch")
	}

	if len(imported.Entries) != len(acl.Entries) {
		t.Errorf("Entry count mismatch")
	}
}

func TestPolicyJSONSerialization(t *testing.T) {
	acl := ACL{
		Default: Allow,
		Entries: []ACLEntry{
			{
				Subject:     User("bob"),
				PathPattern: "/data/**",
				Permissions: Read,
				Effect:      Allow,
				Priority:    50,
			},
		},
	}

	policy := ExportPolicy(acl, "JSON Test")

	// Save to JSON
	var buf bytes.Buffer
	err := SavePolicy(policy, &buf, PolicyFormatJSON)
	if err != nil {
		t.Fatalf("Failed to save policy: %v", err)
	}

	json := buf.String()
	if !strings.Contains(json, "\"version\"") {
		t.Error("JSON should contain version field")
	}

	if !strings.Contains(json, "bob") {
		t.Error("JSON should contain user bob")
	}

	// Load from JSON
	loaded, err := LoadPolicy(&buf, PolicyFormatJSON)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if loaded.Version != "1.0" {
		t.Errorf("Loaded policy version mismatch")
	}
}

func TestPolicyYAMLSerialization(t *testing.T) {
	acl := ACL{
		Default: Deny,
		Entries: []ACLEntry{
			{
				Subject:     Role("admin"),
				PathPattern: "/admin/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
	}

	policy := ExportPolicy(acl, "YAML Test")

	// Save to YAML
	var buf bytes.Buffer
	err := SavePolicy(policy, &buf, PolicyFormatYAML)
	if err != nil {
		t.Fatalf("Failed to save policy: %v", err)
	}

	yaml := buf.String()
	if !strings.Contains(yaml, "version:") {
		t.Error("YAML should contain version field")
	}

	// Load from YAML
	loaded, err := LoadPolicy(&buf, PolicyFormatYAML)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if loaded.Description != "YAML Test" {
		t.Errorf("Loaded policy description mismatch")
	}
}

func TestOperationConversion(t *testing.T) {
	tests := []struct {
		name  string
		ops   Operation
		strs  []string
	}{
		{
			name: "single operation",
			ops:  Read,
			strs: []string{"read"},
		},
		{
			name: "multiple operations",
			ops:  ReadWrite,
			strs: []string{"read", "write"},
		},
		{
			name: "all operations",
			ops:  All,
			strs: []string{"read", "write", "execute", "delete", "metadata", "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to strings
			strs := operationsToStrings(tt.ops)

			if len(strs) != len(tt.strs) {
				t.Errorf("Expected %d strings, got %d", len(tt.strs), len(strs))
			}

			// Convert back
			ops, err := stringsToOperations(strs)
			if err != nil {
				t.Fatalf("Failed to convert strings to operations: %v", err)
			}

			if ops != tt.ops {
				t.Errorf("Operations mismatch: expected %v, got %v", tt.ops, ops)
			}
		})
	}
}

func TestInvalidPolicyImport(t *testing.T) {
	tests := []struct {
		name        string
		policy      PolicyFile
		expectError bool
	}{
		{
			name: "invalid effect",
			policy: PolicyFile{
				Version: "1.0",
				Default: "invalid",
			},
			expectError: true,
		},
		{
			name: "invalid subject type",
			policy: PolicyFile{
				Version: "1.0",
				Default: "deny",
				Entries: []PolicyEntryExport{
					{
						Subject:     SubjectExport{Type: "invalid", ID: "test"},
						PathPattern: "/test",
						Permissions: []string{"read"},
						Effect:      "allow",
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid permission",
			policy: PolicyFile{
				Version: "1.0",
				Default: "deny",
				Entries: []PolicyEntryExport{
					{
						Subject:     SubjectExport{Type: "user", ID: "test"},
						PathPattern: "/test",
						Permissions: []string{"invalid_permission"},
						Effect:      "allow",
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ImportPolicy(&tt.policy)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
