package permfs

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// PolicyFormat represents the format of a policy file
type PolicyFormat int

const (
	// PolicyFormatJSON represents JSON format
	PolicyFormatJSON PolicyFormat = iota
	// PolicyFormatYAML represents YAML format
	PolicyFormatYAML
)

// PolicyFile represents a serializable policy
type PolicyFile struct {
	Version     string              `json:"version" yaml:"version"`
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	Default     string              `json:"default" yaml:"default"`
	Entries     []PolicyEntryExport `json:"entries" yaml:"entries"`
}

// PolicyEntryExport represents a serializable ACL entry
type PolicyEntryExport struct {
	Subject     SubjectExport `json:"subject" yaml:"subject"`
	PathPattern string        `json:"path_pattern" yaml:"path_pattern"`
	Permissions []string      `json:"permissions" yaml:"permissions"`
	Effect      string        `json:"effect" yaml:"effect"`
	Priority    int           `json:"priority" yaml:"priority"`
}

// SubjectExport represents a serializable subject
type SubjectExport struct {
	Type string `json:"type" yaml:"type"`
	ID   string `json:"id" yaml:"id"`
}

// ExportPolicy exports an ACL to a policy file format
func ExportPolicy(acl ACL, description string) *PolicyFile {
	policy := &PolicyFile{
		Version:     "1.0",
		Description: description,
		Default:     effectToString(acl.Default),
		Entries:     make([]PolicyEntryExport, len(acl.Entries)),
	}

	for i, entry := range acl.Entries {
		policy.Entries[i] = PolicyEntryExport{
			Subject: SubjectExport{
				Type: subjectTypeToString(entry.Subject.Type),
				ID:   entry.Subject.ID,
			},
			PathPattern: entry.PathPattern,
			Permissions: operationsToStrings(entry.Permissions),
			Effect:      effectToString(entry.Effect),
			Priority:    entry.Priority,
		}
	}

	return policy
}

// ImportPolicy imports a policy file into an ACL
func ImportPolicy(policy *PolicyFile) (ACL, error) {
	acl := ACL{
		Entries: make([]ACLEntry, len(policy.Entries)),
	}

	// Parse default effect
	defaultEffect, err := stringToEffect(policy.Default)
	if err != nil {
		return acl, fmt.Errorf("invalid default effect: %w", err)
	}
	acl.Default = defaultEffect

	// Parse entries
	for i, entry := range policy.Entries {
		subjectType, err := stringToSubjectType(entry.Subject.Type)
		if err != nil {
			return acl, fmt.Errorf("entry %d: invalid subject type: %w", i, err)
		}

		permissions, err := stringsToOperations(entry.Permissions)
		if err != nil {
			return acl, fmt.Errorf("entry %d: invalid permissions: %w", i, err)
		}

		effect, err := stringToEffect(entry.Effect)
		if err != nil {
			return acl, fmt.Errorf("entry %d: invalid effect: %w", i, err)
		}

		acl.Entries[i] = ACLEntry{
			Subject: Subject{
				Type: subjectType,
				ID:   entry.Subject.ID,
			},
			PathPattern: entry.PathPattern,
			Permissions: permissions,
			Effect:      effect,
			Priority:    entry.Priority,
		}
	}

	return acl, nil
}

// SavePolicyToFile saves a policy to a file
func SavePolicyToFile(policy *PolicyFile, filename string, format PolicyFormat) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return SavePolicy(policy, file, format)
}

// SavePolicy saves a policy to a writer
func SavePolicy(policy *PolicyFile, w io.Writer, format PolicyFormat) error {
	switch format {
	case PolicyFormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(policy)
	case PolicyFormatYAML:
		encoder := yaml.NewEncoder(w)
		defer encoder.Close()
		return encoder.Encode(policy)
	default:
		return fmt.Errorf("unsupported format: %d", format)
	}
}

// LoadPolicyFromFile loads a policy from a file
func LoadPolicyFromFile(filename string, format PolicyFormat) (*PolicyFile, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return LoadPolicy(file, format)
}

// LoadPolicy loads a policy from a reader
func LoadPolicy(r io.Reader, format PolicyFormat) (*PolicyFile, error) {
	policy := &PolicyFile{}

	switch format {
	case PolicyFormatJSON:
		decoder := json.NewDecoder(r)
		if err := decoder.Decode(policy); err != nil {
			return nil, err
		}
	case PolicyFormatYAML:
		decoder := yaml.NewDecoder(r)
		if err := decoder.Decode(policy); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported format: %d", format)
	}

	return policy, nil
}

// Helper conversion functions

func effectToString(effect Effect) string {
	if effect == EffectAllow {
		return "allow"
	}
	return "deny"
}

func stringToEffect(s string) (Effect, error) {
	switch s {
	case "allow":
		return EffectAllow, nil
	case "deny":
		return EffectDeny, nil
	default:
		return EffectDeny, fmt.Errorf("invalid effect: %s", s)
	}
}

func subjectTypeToString(st SubjectType) string {
	switch st {
	case SubjectTypeUser:
		return "user"
	case SubjectTypeGroup:
		return "group"
	case SubjectTypeRole:
		return "role"
	case SubjectTypeEveryone:
		return "everyone"
	default:
		return "unknown"
	}
}

func stringToSubjectType(s string) (SubjectType, error) {
	switch s {
	case "user":
		return SubjectTypeUser, nil
	case "group":
		return SubjectTypeGroup, nil
	case "role":
		return SubjectTypeRole, nil
	case "everyone":
		return SubjectTypeEveryone, nil
	default:
		return SubjectTypeUser, fmt.Errorf("invalid subject type: %s", s)
	}
}

func operationsToStrings(ops Operation) []string {
	var result []string
	if ops&OperationRead != 0 {
		result = append(result, "read")
	}
	if ops&OperationWrite != 0 {
		result = append(result, "write")
	}
	if ops&OperationExecute != 0 {
		result = append(result, "execute")
	}
	if ops&OperationDelete != 0 {
		result = append(result, "delete")
	}
	if ops&OperationMetadata != 0 {
		result = append(result, "metadata")
	}
	if ops&OperationAdmin != 0 {
		result = append(result, "admin")
	}
	return result
}

func stringsToOperations(strs []string) (Operation, error) {
	var result Operation
	for _, s := range strs {
		switch s {
		case "read":
			result |= OperationRead
		case "write":
			result |= OperationWrite
		case "execute":
			result |= OperationExecute
		case "delete":
			result |= OperationDelete
		case "metadata":
			result |= OperationMetadata
		case "admin":
			result |= OperationAdmin
		case "all":
			result |= OperationAll
		default:
			return 0, fmt.Errorf("invalid operation: %s", s)
		}
	}
	return result, nil
}
