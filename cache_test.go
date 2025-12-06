package permfs

import (
	"testing"
	"time"
)

func TestPermissionCache(t *testing.T) {
	cache := NewPermissionCache(5, 1*time.Second)

	t.Run("set and get", func(t *testing.T) {
		key := CacheKey{
			UserID:    "alice",
			Path:      "/home/alice/file.txt",
			Operation: OperationRead,
		}

		// Should not exist initially
		_, found := cache.Get(key)
		if found {
			t.Error("Expected cache miss")
		}

		// Set value
		cache.Set(key, true)

		// Should exist now
		allowed, found := cache.Get(key)
		if !found {
			t.Error("Expected cache hit")
		}
		if !allowed {
			t.Error("Expected allowed=true")
		}
	})

	t.Run("cache expiration", func(t *testing.T) {
		shortCache := NewPermissionCache(5, 100*time.Millisecond)
		key := CacheKey{
			UserID:    "bob",
			Path:      "/data/file.txt",
			Operation: OperationWrite,
		}

		shortCache.Set(key, true)

		// Should exist immediately
		_, found := shortCache.Get(key)
		if !found {
			t.Error("Expected cache hit")
		}

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should be expired now
		_, found = shortCache.Get(key)
		if found {
			t.Error("Expected cache miss after expiration")
		}
	})

	t.Run("LRU eviction", func(t *testing.T) {
		lruCache := NewPermissionCache(3, 1*time.Minute)

		// Fill cache to capacity
		for i := 1; i <= 3; i++ {
			key := CacheKey{
				UserID:    "user",
				Path:      "/file" + string(rune(i)),
				Operation: OperationRead,
			}
			lruCache.Set(key, true)
		}

		// Add one more - should evict the oldest
		newKey := CacheKey{
			UserID:    "user",
			Path:      "/file4",
			Operation: OperationRead,
		}
		lruCache.Set(newKey, true)

		// First key should be evicted
		firstKey := CacheKey{
			UserID:    "user",
			Path:      "/file" + string(rune(1)),
			Operation: OperationRead,
		}
		_, found := lruCache.Get(firstKey)
		if found {
			t.Error("Expected oldest entry to be evicted")
		}

		// New key should exist
		_, found = lruCache.Get(newKey)
		if !found {
			t.Error("Expected new entry to exist")
		}
	})

	t.Run("clear cache", func(t *testing.T) {
		cache := NewPermissionCache(5, 1*time.Minute)
		key := CacheKey{
			UserID:    "alice",
			Path:      "/file.txt",
			Operation: OperationRead,
		}

		cache.Set(key, true)
		cache.Clear()

		_, found := cache.Get(key)
		if found {
			t.Error("Expected cache to be empty after clear")
		}
	})

	t.Run("invalidate by user", func(t *testing.T) {
		cache := NewPermissionCache(10, 1*time.Minute)

		// Add entries for different users
		aliceKey := CacheKey{UserID: "alice", Path: "/data/file.txt", Operation: OperationRead}
		bobKey := CacheKey{UserID: "bob", Path: "/data/file.txt", Operation: OperationRead}

		cache.Set(aliceKey, true)
		cache.Set(bobKey, true)

		// Invalidate alice's entries
		cache.Invalidate("alice", "")

		// Alice's entry should be gone
		_, found := cache.Get(aliceKey)
		if found {
			t.Error("Expected alice's entry to be invalidated")
		}

		// Bob's entry should still exist
		_, found = cache.Get(bobKey)
		if !found {
			t.Error("Expected bob's entry to remain")
		}
	})

	t.Run("invalidate by path prefix", func(t *testing.T) {
		cache := NewPermissionCache(10, 1*time.Minute)

		dataKey := CacheKey{UserID: "alice", Path: "/data/file.txt", Operation: OperationRead}
		homeKey := CacheKey{UserID: "alice", Path: "/home/file.txt", Operation: OperationRead}

		cache.Set(dataKey, true)
		cache.Set(homeKey, true)

		// Invalidate /data entries
		cache.Invalidate("", "/data")

		// Data entry should be gone
		_, found := cache.Get(dataKey)
		if found {
			t.Error("Expected /data entry to be invalidated")
		}

		// Home entry should still exist
		_, found = cache.Get(homeKey)
		if !found {
			t.Error("Expected /home entry to remain")
		}
	})

	t.Run("cache stats", func(t *testing.T) {
		cache := NewPermissionCache(5, 1*time.Minute)
		key := CacheKey{UserID: "alice", Path: "/file.txt", Operation: OperationRead}

		// Initial stats
		stats := cache.Stats()
		if stats.Hits != 0 || stats.Misses != 0 {
			t.Error("Expected zero stats initially")
		}

		// Miss
		cache.Get(key)
		stats = cache.Stats()
		if stats.Misses != 1 {
			t.Errorf("Expected 1 miss, got %d", stats.Misses)
		}

		// Set and hit
		cache.Set(key, true)
		cache.Get(key)
		stats = cache.Stats()
		if stats.Hits != 1 {
			t.Errorf("Expected 1 hit, got %d", stats.Hits)
		}

		// Check hit rate
		if stats.HitRate != 0.5 {
			t.Errorf("Expected hit rate 0.5, got %f", stats.HitRate)
		}
	})

	t.Run("disabled cache", func(t *testing.T) {
		cache := NewPermissionCache(5, 1*time.Minute)
		cache.Disable()

		key := CacheKey{UserID: "alice", Path: "/file.txt", Operation: OperationRead}

		cache.Set(key, true)
		_, found := cache.Get(key)
		if found {
			t.Error("Expected cache to be disabled")
		}

		cache.Enable()
		cache.Set(key, true)
		_, found = cache.Get(key)
		if !found {
			t.Error("Expected cache to be enabled")
		}
	})
}

func TestPatternCache(t *testing.T) {
	t.Run("set and get", func(t *testing.T) {
		cache := NewPatternCache()
		pattern := "/home/**"

		matcher, err := NewPatternMatcher(pattern)
		if err != nil {
			t.Fatalf("Failed to create pattern matcher: %v", err)
		}

		cache.Set(pattern, matcher)

		retrieved, found := cache.Get(pattern)
		if !found {
			t.Error("Expected to find cached pattern")
		}
		if retrieved.Pattern() != pattern {
			t.Errorf("Expected pattern %s, got %s", pattern, retrieved.Pattern())
		}
	})

	t.Run("get or create", func(t *testing.T) {
		cache := NewPatternCache()
		pattern := "/data/**"

		// Should create and cache
		matcher1, err := cache.GetOrCreate(pattern)
		if err != nil {
			t.Fatalf("Failed to create pattern: %v", err)
		}

		// Should retrieve from cache
		matcher2, err := cache.GetOrCreate(pattern)
		if err != nil {
			t.Fatalf("Failed to get pattern: %v", err)
		}

		if matcher1 != matcher2 {
			t.Error("Expected same matcher instance from cache")
		}
	})

	t.Run("clear", func(t *testing.T) {
		cache := NewPatternCache()
		pattern := "/test/**"

		matcher, _ := NewPatternMatcher(pattern)
		cache.Set(pattern, matcher)

		cache.Clear()

		_, found := cache.Get(pattern)
		if found {
			t.Error("Expected cache to be empty after clear")
		}
	})

	t.Run("size", func(t *testing.T) {
		cache := NewPatternCache()

		if cache.Size() != 0 {
			t.Error("Expected empty cache")
		}

		for i := 0; i < 5; i++ {
			matcher, _ := NewPatternMatcher("/pattern" + string(rune(i)) + "/**")
			cache.Set("/pattern"+string(rune(i))+"/**", matcher)
		}

		if cache.Size() != 5 {
			t.Errorf("Expected size 5, got %d", cache.Size())
		}
	})
}

func TestCacheKeyString(t *testing.T) {
	key := CacheKey{
		UserID:    "alice",
		Path:      "/data/file.txt",
		Operation: OperationRead,
	}

	expected := "alice:/data/file.txt:1"
	if key.String() != expected {
		t.Errorf("Expected %s, got %s", expected, key.String())
	}
}

func TestPermissionCacheIsEnabled(t *testing.T) {
	cache := NewPermissionCache(5, 1*time.Minute)

	if !cache.IsEnabled() {
		t.Error("Expected cache to be enabled by default")
	}

	cache.Disable()
	if cache.IsEnabled() {
		t.Error("Expected cache to be disabled")
	}

	cache.Enable()
	if !cache.IsEnabled() {
		t.Error("Expected cache to be enabled after Enable()")
	}
}

func TestMatchesPrefix(t *testing.T) {
	tests := []struct {
		path     string
		prefix   string
		expected bool
	}{
		{"/data/file.txt", "/data", true},
		{"/data/file.txt", "", true},
		{"/data/file.txt", "/home", false},
		{"/d", "/data", false}, // path shorter than prefix
	}

	for _, tt := range tests {
		got := matchesPrefix(tt.path, tt.prefix)
		if got != tt.expected {
			t.Errorf("matchesPrefix(%q, %q) = %v, want %v", tt.path, tt.prefix, got, tt.expected)
		}
	}
}

func TestCacheEntryIsExpired(t *testing.T) {
	entry := &CacheEntry{
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}

	if !entry.IsExpired() {
		t.Error("Expected entry to be expired")
	}

	entry.ExpiresAt = time.Now().Add(1 * time.Hour)
	if entry.IsExpired() {
		t.Error("Expected entry to not be expired")
	}
}

func TestPermissionCacheUpdateExisting(t *testing.T) {
	cache := NewPermissionCache(5, 1*time.Minute)
	key := CacheKey{UserID: "alice", Path: "/file.txt", Operation: OperationRead}

	// Set initial value
	cache.Set(key, true)

	// Update to different value
	cache.Set(key, false)

	// Get should return updated value
	allowed, found := cache.Get(key)
	if !found {
		t.Error("Expected to find entry")
	}
	if allowed {
		t.Error("Expected allowed=false after update")
	}
}

func BenchmarkCacheGet(b *testing.B) {
	cache := NewPermissionCache(10000, 5*time.Minute)
	key := CacheKey{
		UserID:    "alice",
		Path:      "/data/file.txt",
		Operation: OperationRead,
	}
	cache.Set(key, true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(key)
	}
}

func BenchmarkCacheSet(b *testing.B) {
	cache := NewPermissionCache(10000, 5*time.Minute)
	key := CacheKey{
		UserID:    "alice",
		Path:      "/data/file.txt",
		Operation: OperationRead,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(key, true)
	}
}
