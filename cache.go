package permfs

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// CacheKey represents a cache key for permission evaluation
type CacheKey struct {
	UserID    string
	Path      string
	Operation Operation
}

// String returns a string representation of the cache key
func (ck CacheKey) String() string {
	return fmt.Sprintf("%s:%s:%d", ck.UserID, ck.Path, ck.Operation)
}

// CacheEntry represents a cached permission evaluation result
type CacheEntry struct {
	Key       CacheKey
	Allowed   bool
	ExpiresAt time.Time
	element   *list.Element // For LRU tracking
}

// IsExpired checks if the cache entry has expired
func (ce *CacheEntry) IsExpired() bool {
	return time.Now().After(ce.ExpiresAt)
}

// PermissionCache provides LRU caching for permission evaluations
type PermissionCache struct {
	mu         sync.RWMutex
	maxSize    int
	ttl        time.Duration
	entries    map[string]*CacheEntry
	lruList    *list.List
	hits       uint64
	misses     uint64
	evictions  uint64
	enabled    bool
}

// NewPermissionCache creates a new permission cache
func NewPermissionCache(maxSize int, ttl time.Duration) *PermissionCache {
	return &PermissionCache{
		maxSize: maxSize,
		ttl:     ttl,
		entries: make(map[string]*CacheEntry, maxSize),
		lruList: list.New(),
		enabled: true,
	}
}

// Get retrieves a cached permission result
func (pc *PermissionCache) Get(key CacheKey) (allowed bool, found bool) {
	if !pc.enabled {
		return false, false
	}

	pc.mu.RLock()
	entry, exists := pc.entries[key.String()]
	pc.mu.RUnlock()

	if !exists {
		pc.mu.Lock()
		pc.misses++
		pc.mu.Unlock()
		return false, false
	}

	// Check expiration
	if entry.IsExpired() {
		pc.mu.Lock()
		delete(pc.entries, key.String())
		pc.lruList.Remove(entry.element)
		pc.misses++
		pc.mu.Unlock()
		return false, false
	}

	// Move to front (most recently used)
	pc.mu.Lock()
	pc.lruList.MoveToFront(entry.element)
	pc.hits++
	pc.mu.Unlock()

	return entry.Allowed, true
}

// Set stores a permission result in the cache
func (pc *PermissionCache) Set(key CacheKey, allowed bool) {
	if !pc.enabled {
		return
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	keyStr := key.String()

	// Check if entry already exists
	if entry, exists := pc.entries[keyStr]; exists {
		// Update existing entry
		entry.Allowed = allowed
		entry.ExpiresAt = time.Now().Add(pc.ttl)
		pc.lruList.MoveToFront(entry.element)
		return
	}

	// Evict if at capacity
	if pc.lruList.Len() >= pc.maxSize {
		pc.evictOldest()
	}

	// Add new entry
	entry := &CacheEntry{
		Key:       key,
		Allowed:   allowed,
		ExpiresAt: time.Now().Add(pc.ttl),
	}

	entry.element = pc.lruList.PushFront(entry)
	pc.entries[keyStr] = entry
}

// evictOldest removes the least recently used entry
func (pc *PermissionCache) evictOldest() {
	if pc.lruList.Len() == 0 {
		return
	}

	oldest := pc.lruList.Back()
	if oldest == nil {
		return
	}

	entry := oldest.Value.(*CacheEntry)
	delete(pc.entries, entry.Key.String())
	pc.lruList.Remove(oldest)
	pc.evictions++
}

// Clear removes all entries from the cache
func (pc *PermissionCache) Clear() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.entries = make(map[string]*CacheEntry, pc.maxSize)
	pc.lruList.Init()
}

// Invalidate removes entries matching a pattern
func (pc *PermissionCache) Invalidate(userID string, pathPrefix string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	toRemove := []string{}

	for keyStr, entry := range pc.entries {
		if (userID == "" || entry.Key.UserID == userID) &&
			(pathPrefix == "" || matchesPrefix(entry.Key.Path, pathPrefix)) {
			toRemove = append(toRemove, keyStr)
		}
	}

	for _, keyStr := range toRemove {
		if entry, exists := pc.entries[keyStr]; exists {
			delete(pc.entries, keyStr)
			pc.lruList.Remove(entry.element)
		}
	}
}

// matchesPrefix checks if a path matches a prefix
func matchesPrefix(path, prefix string) bool {
	if prefix == "" {
		return true
	}
	if len(path) < len(prefix) {
		return false
	}
	return path[:len(prefix)] == prefix
}

// Stats returns cache statistics
func (pc *PermissionCache) Stats() CacheStats {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	return CacheStats{
		Size:      pc.lruList.Len(),
		MaxSize:   pc.maxSize,
		Hits:      pc.hits,
		Misses:    pc.misses,
		Evictions: pc.evictions,
		HitRate:   pc.hitRate(),
	}
}

// hitRate calculates the cache hit rate
func (pc *PermissionCache) hitRate() float64 {
	total := pc.hits + pc.misses
	if total == 0 {
		return 0
	}
	return float64(pc.hits) / float64(total)
}

// Enable enables the cache
func (pc *PermissionCache) Enable() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.enabled = true
}

// Disable disables the cache
func (pc *PermissionCache) Disable() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.enabled = false
}

// IsEnabled returns whether the cache is enabled
func (pc *PermissionCache) IsEnabled() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.enabled
}

// CacheStats contains cache statistics
type CacheStats struct {
	Size      int
	MaxSize   int
	Hits      uint64
	Misses    uint64
	Evictions uint64
	HitRate   float64
}

// PatternCache caches compiled path patterns
type PatternCache struct {
	mu      sync.RWMutex
	cache   map[string]*PatternMatcher
	enabled bool
}

// NewPatternCache creates a new pattern cache
func NewPatternCache() *PatternCache {
	return &PatternCache{
		cache:   make(map[string]*PatternMatcher),
		enabled: true,
	}
}

// Get retrieves a cached pattern matcher
func (pc *PatternCache) Get(pattern string) (*PatternMatcher, bool) {
	if !pc.enabled {
		return nil, false
	}

	pc.mu.RLock()
	defer pc.mu.RUnlock()

	matcher, exists := pc.cache[pattern]
	return matcher, exists
}

// Set stores a pattern matcher in the cache
func (pc *PatternCache) Set(pattern string, matcher *PatternMatcher) {
	if !pc.enabled {
		return
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.cache[pattern] = matcher
}

// GetOrCreate gets a cached pattern or creates a new one
func (pc *PatternCache) GetOrCreate(pattern string) (*PatternMatcher, error) {
	// Try to get from cache first
	if matcher, exists := pc.Get(pattern); exists {
		return matcher, nil
	}

	// Create new matcher
	matcher, err := NewPatternMatcher(pattern)
	if err != nil {
		return nil, err
	}

	// Store in cache
	pc.Set(pattern, matcher)

	return matcher, nil
}

// Clear removes all cached patterns
func (pc *PatternCache) Clear() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.cache = make(map[string]*PatternMatcher)
}

// Size returns the number of cached patterns
func (pc *PatternCache) Size() int {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	return len(pc.cache)
}
