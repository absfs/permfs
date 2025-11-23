package permfs

import (
	"sort"
)

// Evaluator evaluates permissions based on ACL rules
type Evaluator struct {
	acl          ACL
	cache        *PermissionCache
	patternCache *PatternCache
}

// NewEvaluator creates a new permission evaluator
func NewEvaluator(acl ACL) *Evaluator {
	return &Evaluator{
		acl:          acl,
		cache:        nil, // Cache is optional
		patternCache: nil, // Pattern cache is optional
	}
}

// NewEvaluatorWithCache creates a new evaluator with caching enabled
func NewEvaluatorWithCache(acl ACL, cache *PermissionCache, patternCache *PatternCache) *Evaluator {
	return &Evaluator{
		acl:          acl,
		cache:        cache,
		patternCache: patternCache,
	}
}

// Evaluate checks if the given operation is allowed for the context
func (e *Evaluator) Evaluate(ctx *EvaluationContext) (bool, error) {
	// Check cache first if enabled
	if e.cache != nil && ctx.Identity != nil {
		cacheKey := CacheKey{
			UserID:    ctx.Identity.UserID,
			Path:      ctx.Path,
			Operation: ctx.Operation,
		}
		if allowed, found := e.cache.Get(cacheKey); found {
			return allowed, nil
		}

		// Evaluate and cache the result
		allowed, err := e.evaluateUncached(ctx)
		if err == nil {
			e.cache.Set(cacheKey, allowed)
		}
		return allowed, err
	}

	// No cache, evaluate directly
	return e.evaluateUncached(ctx)
}

// evaluateUncached performs the actual permission evaluation without caching
func (e *Evaluator) evaluateUncached(ctx *EvaluationContext) (bool, error) {
	// Find all matching entries
	var matchingEntries []ACLEntry
	for _, entry := range e.acl.Entries {
		if entry.Matches(ctx) && entry.Applies(ctx.Operation) {
			matchingEntries = append(matchingEntries, entry)
		}
	}

	// If no entries match, use default policy
	if len(matchingEntries) == 0 {
		return e.acl.Default == EffectAllow, nil
	}

	// Sort by priority (higher priority first)
	sort.Slice(matchingEntries, func(i, j int) bool {
		return matchingEntries[i].Priority > matchingEntries[j].Priority
	})

	// Evaluation order:
	// 1. Explicit deny rules (highest priority)
	// 2. Explicit allow rules
	// 3. Default deny

	// First pass: check for explicit deny at highest priority level
	highestPriority := matchingEntries[0].Priority
	for _, entry := range matchingEntries {
		// Only consider entries at the highest priority level
		if entry.Priority < highestPriority {
			break
		}
		if entry.Effect == EffectDeny {
			return false, nil
		}
	}

	// Second pass: check for explicit allow at highest priority level
	for _, entry := range matchingEntries {
		// Only consider entries at the highest priority level
		if entry.Priority < highestPriority {
			break
		}
		if entry.Effect == EffectAllow {
			return true, nil
		}
	}

	// If we get here, check next priority level
	// This handles the case where multiple priority levels exist
	for _, entry := range matchingEntries {
		if entry.Effect == EffectDeny {
			return false, nil
		}
		if entry.Effect == EffectAllow {
			return true, nil
		}
	}

	// Default to deny if no explicit allow
	return false, nil
}

// GetMatchingEntries returns all ACL entries that match the given context
func (e *Evaluator) GetMatchingEntries(ctx *EvaluationContext) []ACLEntry {
	var matching []ACLEntry
	for _, entry := range e.acl.Entries {
		if entry.Matches(ctx) {
			matching = append(matching, entry)
		}
	}
	return matching
}

// GetEffectivePermissions returns the effective permissions for a path and identity
func (e *Evaluator) GetEffectivePermissions(identity *Identity, path string) Operation {
	var allowed Operation

	// Check each operation type
	operations := []Operation{
		OperationRead,
		OperationWrite,
		OperationExecute,
		OperationDelete,
		OperationMetadata,
		OperationAdmin,
	}

	for _, op := range operations {
		ctx := &EvaluationContext{
			Identity:  identity,
			Path:      path,
			Operation: op,
		}

		if ok, _ := e.Evaluate(ctx); ok {
			allowed |= op
		}
	}

	return allowed
}

// CanRead checks if the identity can read the path
func (e *Evaluator) CanRead(identity *Identity, path string) bool {
	ctx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: OperationRead,
	}
	allowed, _ := e.Evaluate(ctx)
	return allowed
}

// CanWrite checks if the identity can write to the path
func (e *Evaluator) CanWrite(identity *Identity, path string) bool {
	ctx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: OperationWrite,
	}
	allowed, _ := e.Evaluate(ctx)
	return allowed
}

// CanDelete checks if the identity can delete the path
func (e *Evaluator) CanDelete(identity *Identity, path string) bool {
	ctx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: OperationDelete,
	}
	allowed, _ := e.Evaluate(ctx)
	return allowed
}

// CanExecute checks if the identity can execute the path
func (e *Evaluator) CanExecute(identity *Identity, path string) bool {
	ctx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: OperationExecute,
	}
	allowed, _ := e.Evaluate(ctx)
	return allowed
}

// CanAccessMetadata checks if the identity can access metadata for the path
func (e *Evaluator) CanAccessMetadata(identity *Identity, path string) bool {
	ctx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: OperationMetadata,
	}
	allowed, _ := e.Evaluate(ctx)
	return allowed
}

// IsAdmin checks if the identity has admin permissions for the path
func (e *Evaluator) IsAdmin(identity *Identity, path string) bool {
	ctx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: OperationAdmin,
	}
	allowed, _ := e.Evaluate(ctx)
	return allowed
}

// ClearCache clears the permission cache
func (e *Evaluator) ClearCache() {
	if e.cache != nil {
		e.cache.Clear()
	}
}

// InvalidateCache invalidates cache entries for a user and/or path prefix
func (e *Evaluator) InvalidateCache(userID string, pathPrefix string) {
	if e.cache != nil {
		e.cache.Invalidate(userID, pathPrefix)
	}
}

// GetCacheStats returns cache statistics
func (e *Evaluator) GetCacheStats() *CacheStats {
	if e.cache != nil {
		stats := e.cache.Stats()
		return &stats
	}
	return nil
}
