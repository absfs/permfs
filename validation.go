package permfs

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

// Error implements the error interface
func (ve *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", ve.Field, ve.Message)
}

// ValidationResult contains the result of validation
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// AddError adds an error to the validation result
func (vr *ValidationResult) AddError(field, message string) {
	vr.Valid = false
	vr.Errors = append(vr.Errors, ValidationError{
		Field:   field,
		Message: message,
	})
}

// ValidateACL validates an ACL configuration
func ValidateACL(acl ACL) ValidationResult {
	result := ValidationResult{Valid: true}

	// Validate entries
	for i, entry := range acl.Entries {
		prefix := fmt.Sprintf("entries[%d]", i)
		validateEntry(entry, prefix, &result)
	}

	return result
}

// ValidateACLEntry validates a single ACL entry
func ValidateACLEntry(entry ACLEntry) ValidationResult {
	result := ValidationResult{Valid: true}
	validateEntry(entry, "entry", &result)
	return result
}

func validateEntry(entry ACLEntry, prefix string, result *ValidationResult) {
	// Validate subject
	if entry.Subject.Type == SubjectTypeUser ||
		entry.Subject.Type == SubjectTypeGroup ||
		entry.Subject.Type == SubjectTypeRole {
		if entry.Subject.ID == "" {
			result.AddError(prefix+".subject.id", "subject ID cannot be empty")
		}
	}

	// Validate path pattern
	if entry.PathPattern == "" {
		result.AddError(prefix+".path_pattern", "path pattern cannot be empty")
	} else {
		if err := validatePathPattern(entry.PathPattern); err != nil {
			result.AddError(prefix+".path_pattern", err.Error())
		}
	}

	// Validate permissions
	if entry.Permissions == 0 {
		result.AddError(prefix+".permissions", "at least one permission must be specified")
	}

	// Validate priority
	if entry.Priority < 0 {
		result.AddError(prefix+".priority", "priority cannot be negative")
	}
}

// validatePathPattern validates a path pattern
func validatePathPattern(pattern string) error {
	// Check for empty pattern
	if pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	// Try to compile the pattern
	_, err := NewPatternMatcher(pattern)
	if err != nil {
		return err
	}

	// Check for common mistakes
	if strings.Contains(pattern, "***") {
		return fmt.Errorf("invalid pattern: *** is not supported, use **")
	}

	return nil
}

// TestPermission simulates a permission check without actually performing it
func (pfs *PermFS) TestPermission(identity *Identity, path string, op Operation) (bool, *PermissionTestResult) {
	evalCtx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: op,
		Metadata:  make(map[string]interface{}),
	}

	allowed, _ := pfs.evaluator.Evaluate(evalCtx)

	// Find matching entries for the test result
	var matchingEntries []ACLEntry
	for _, entry := range pfs.evaluator.acl.Entries {
		if entry.Matches(evalCtx) && entry.Applies(op) {
			matchingEntries = append(matchingEntries, entry)
		}
	}

	result := &PermissionTestResult{
		Allowed:         allowed,
		MatchingEntries: matchingEntries,
		Path:            path,
		Operation:       op,
		Identity:        identity,
	}

	return allowed, result
}

// PermissionTestResult contains the result of a permission test
type PermissionTestResult struct {
	Allowed         bool
	MatchingEntries []ACLEntry
	Path            string
	Operation       Operation
	Identity        *Identity
}

// Explain returns a human-readable explanation of the permission decision
func (ptr *PermissionTestResult) Explain() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Permission Test: %s attempting %s on %s\n",
		ptr.Identity.UserID, ptr.Operation, ptr.Path))
	sb.WriteString(fmt.Sprintf("Result: %s\n\n", allowedString(ptr.Allowed)))

	if len(ptr.MatchingEntries) == 0 {
		sb.WriteString("No matching rules found (using default policy)\n")
	} else {
		sb.WriteString(fmt.Sprintf("Matching rules (%d):\n", len(ptr.MatchingEntries)))
		for i, entry := range ptr.MatchingEntries {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, entry.String()))
		}
	}

	return sb.String()
}

func allowedString(allowed bool) string {
	if allowed {
		return "ALLOWED"
	}
	return "DENIED"
}

// FindConflictingRules finds rules that might conflict with each other
func FindConflictingRules(acl ACL) []RuleConflict {
	var conflicts []RuleConflict

	for i := 0; i < len(acl.Entries); i++ {
		for j := i + 1; j < len(acl.Entries); j++ {
			entry1 := acl.Entries[i]
			entry2 := acl.Entries[j]

			// Check if rules might conflict
			if rulesCanConflict(entry1, entry2) {
				conflicts = append(conflicts, RuleConflict{
					Rule1:       entry1,
					Rule2:       entry2,
					Description: describeConflict(entry1, entry2),
				})
			}
		}
	}

	return conflicts
}

// RuleConflict represents a potential conflict between two rules
type RuleConflict struct {
	Rule1       ACLEntry
	Rule2       ACLEntry
	Description string
}

func rulesCanConflict(rule1, rule2 ACLEntry) bool {
	// Rules can conflict if:
	// 1. They have the same priority
	// 2. They apply to the same subject
	// 3. They have overlapping path patterns
	// 4. They have opposite effects

	if rule1.Priority != rule2.Priority {
		return false
	}

	if !subjectsOverlap(rule1.Subject, rule2.Subject) {
		return false
	}

	if rule1.Effect == rule2.Effect {
		return false
	}

	// Simplified pattern overlap check
	return patternsOverlap(rule1.PathPattern, rule2.PathPattern)
}

func subjectsOverlap(s1, s2 Subject) bool {
	if s1.Type == SubjectTypeEveryone || s2.Type == SubjectTypeEveryone {
		return true
	}
	return s1.Type == s2.Type && s1.ID == s2.ID
}

func patternsOverlap(p1, p2 string) bool {
	// Simplified check - just see if patterns are related
	if p1 == p2 {
		return true
	}

	// Check if one is a prefix of the other
	p1Clean := filepath.Clean(p1)
	p2Clean := filepath.Clean(p2)

	if strings.HasPrefix(p1Clean, p2Clean) || strings.HasPrefix(p2Clean, p1Clean) {
		return true
	}

	// Check for wildcard overlap
	if strings.Contains(p1, "**") || strings.Contains(p2, "**") {
		return true
	}

	return false
}

func describeConflict(rule1, rule2 ACLEntry) string {
	return fmt.Sprintf("Rules have same priority (%d) but opposite effects (%s vs %s) for overlapping patterns",
		rule1.Priority, rule1.Effect, rule2.Effect)
}

// OptimizeACL optimizes an ACL by removing redundant rules
func OptimizeACL(acl ACL) ACL {
	optimized := ACL{
		Default: acl.Default,
		Entries: make([]ACLEntry, 0, len(acl.Entries)),
	}

	// Remove duplicate entries
	seen := make(map[string]bool)
	for _, entry := range acl.Entries {
		key := entryKey(entry)
		if !seen[key] {
			seen[key] = true
			optimized.Entries = append(optimized.Entries, entry)
		}
	}

	return optimized
}

func entryKey(entry ACLEntry) string {
	return fmt.Sprintf("%s:%s:%s:%d:%d",
		entry.Subject.Type, entry.Subject.ID,
		entry.PathPattern, entry.Permissions, entry.Effect)
}
