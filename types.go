package permfs

import (
	"fmt"
	"strings"
)

// Operation represents a filesystem operation type
type Operation uint32

const (
	// OperationRead allows opening files for reading and listing directories
	OperationRead Operation = 1 << iota
	// OperationWrite allows creating, modifying, or appending to files
	OperationWrite
	// OperationExecute allows executing files
	OperationExecute
	// OperationDelete allows removing files or directories
	OperationDelete
	// OperationMetadata allows reading/modifying file attributes, permissions, timestamps
	OperationMetadata
	// OperationAdmin allows full control including permission changes
	OperationAdmin

	// OperationAll grants all permissions
	OperationAll Operation = OperationRead | OperationWrite | OperationExecute | OperationDelete | OperationMetadata | OperationAdmin
)

// Common permission combinations
var (
	Read      = OperationRead
	Write     = OperationWrite
	Execute   = OperationExecute
	Delete    = OperationDelete
	Metadata  = OperationMetadata
	Admin     = OperationAdmin
	ReadWrite = OperationRead | OperationWrite
	All       = OperationAll
)

// String returns a string representation of the operation
func (o Operation) String() string {
	if o == OperationAll {
		return "All"
	}

	var ops []string
	if o&OperationRead != 0 {
		ops = append(ops, "Read")
	}
	if o&OperationWrite != 0 {
		ops = append(ops, "Write")
	}
	if o&OperationExecute != 0 {
		ops = append(ops, "Execute")
	}
	if o&OperationDelete != 0 {
		ops = append(ops, "Delete")
	}
	if o&OperationMetadata != 0 {
		ops = append(ops, "Metadata")
	}
	if o&OperationAdmin != 0 {
		ops = append(ops, "Admin")
	}

	if len(ops) == 0 {
		return "None"
	}
	return strings.Join(ops, "|")
}

// Has checks if the operation set includes the given operation
func (o Operation) Has(op Operation) bool {
	return o&op == op
}

// OperationSet is an alias for Operation (for backwards compatibility with API examples)
type OperationSet = Operation

// Effect represents whether an ACL entry allows or denies access
type Effect int

const (
	// EffectDeny denies access (takes precedence)
	EffectDeny Effect = iota
	// EffectAllow allows access
	EffectAllow
)

// String returns a string representation of the effect
func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "Allow"
	case EffectDeny:
		return "Deny"
	default:
		return "Unknown"
	}
}

var (
	Allow = EffectAllow
	Deny  = EffectDeny
)

// SubjectType represents the type of subject in an ACL entry
type SubjectType int

const (
	// SubjectTypeUser represents a specific user
	SubjectTypeUser SubjectType = iota
	// SubjectTypeGroup represents a group of users
	SubjectTypeGroup
	// SubjectTypeRole represents a role
	SubjectTypeRole
	// SubjectTypeEveryone represents all users (wildcard)
	SubjectTypeEveryone
)

// String returns a string representation of the subject type
func (st SubjectType) String() string {
	switch st {
	case SubjectTypeUser:
		return "User"
	case SubjectTypeGroup:
		return "Group"
	case SubjectTypeRole:
		return "Role"
	case SubjectTypeEveryone:
		return "Everyone"
	default:
		return "Unknown"
	}
}

// Subject represents who an ACL entry applies to
type Subject struct {
	Type SubjectType
	ID   string
}

// String returns a string representation of the subject
func (s Subject) String() string {
	if s.Type == SubjectTypeEveryone {
		return "Everyone"
	}
	return fmt.Sprintf("%s:%s", s.Type, s.ID)
}

// User creates a Subject representing a specific user
func User(id string) Subject {
	return Subject{Type: SubjectTypeUser, ID: id}
}

// Group creates a Subject representing a group
func Group(id string) Subject {
	return Subject{Type: SubjectTypeGroup, ID: id}
}

// Role creates a Subject representing a role
func Role(id string) Subject {
	return Subject{Type: SubjectTypeRole, ID: id}
}

// Everyone creates a Subject representing all users
func Everyone() Subject {
	return Subject{Type: SubjectTypeEveryone, ID: "*"}
}

// Condition represents a conditional check that must pass for an ACL entry to apply
type Condition interface {
	// Evaluate checks if the condition is satisfied
	Evaluate(ctx *EvaluationContext) bool
	// String returns a string representation of the condition
	String() string
}

// EvaluationContext contains information needed to evaluate permissions
type EvaluationContext struct {
	// Identity contains user, group, and role information
	Identity *Identity
	// Path is the filesystem path being accessed
	Path string
	// Operation is the operation being attempted
	Operation Operation
	// Metadata contains additional context information
	Metadata map[string]interface{}
}

// Identity represents a user's identity and group memberships
type Identity struct {
	// UserID is the unique identifier for the user
	UserID string
	// Groups is a list of groups the user belongs to
	Groups []string
	// Roles is a list of roles assigned to the user
	Roles []string
	// Metadata contains additional identity information
	Metadata map[string]string
}

// HasGroup checks if the identity belongs to the given group
func (i *Identity) HasGroup(group string) bool {
	for _, g := range i.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// HasRole checks if the identity has the given role
func (i *Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Matches checks if the identity matches the given subject
func (i *Identity) Matches(subject Subject) bool {
	switch subject.Type {
	case SubjectTypeUser:
		return i.UserID == subject.ID
	case SubjectTypeGroup:
		return i.HasGroup(subject.ID)
	case SubjectTypeRole:
		return i.HasRole(subject.ID)
	case SubjectTypeEveryone:
		return true
	default:
		return false
	}
}

// ACLEntry represents a single access control rule
type ACLEntry struct {
	// Subject specifies who this rule applies to
	Subject Subject
	// PathPattern is a glob pattern matching filesystem paths
	PathPattern string
	// Permissions specifies which operations are allowed/denied
	Permissions Operation
	// Effect specifies whether to allow or deny access
	Effect Effect
	// Priority is used for conflict resolution (higher priority wins)
	Priority int
	// Conditions are optional conditions that must be satisfied
	Conditions []Condition
}

// String returns a string representation of the ACL entry
func (e ACLEntry) String() string {
	return fmt.Sprintf("%s: %s %s on %s (priority: %d)",
		e.Subject, e.Effect, e.Permissions, e.PathPattern, e.Priority)
}

// Matches checks if this entry applies to the given context
func (e ACLEntry) Matches(ctx *EvaluationContext) bool {
	// Check if subject matches
	if !ctx.Identity.Matches(e.Subject) {
		return false
	}

	// Check if path matches pattern (to be implemented in pattern.go)
	matched, err := matchPattern(e.PathPattern, ctx.Path)
	if err != nil || !matched {
		return false
	}

	// Check all conditions
	for _, cond := range e.Conditions {
		if !cond.Evaluate(ctx) {
			return false
		}
	}

	return true
}

// Applies checks if this entry's permissions apply to the requested operation
func (e ACLEntry) Applies(op Operation) bool {
	return e.Permissions.Has(op)
}

// ACL represents a complete access control list
type ACL struct {
	// Entries is the list of ACL rules
	Entries []ACLEntry
	// Default is the default effect when no rules match
	Default Effect
}

// Config contains configuration for a permission filesystem
type Config struct {
	// ACL is the access control list
	ACL ACL
	// Audit configuration (placeholder for Phase 3)
	Audit AuditConfig
	// Performance configuration (placeholder for Phase 2)
	Performance PerformanceConfig
}

// AuditConfig contains audit logging configuration (Phase 3)
type AuditConfig struct {
	Enabled bool
	// Additional fields to be implemented in Phase 3
}

// PerformanceConfig contains performance optimization settings (Phase 2)
type PerformanceConfig struct {
	CacheEnabled bool
	// Additional fields to be implemented in Phase 2
}
