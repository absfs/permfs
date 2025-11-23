package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/absfs/permfs"
)

// This example demonstrates all Phase 1-4 features:
// - ACL-based permissions
// - Conditions (time-based, IP-based, custom)
// - Permission caching
// - Audit logging with metrics

func main() {
	fmt.Println("=== Comprehensive PermFS Example ===")

	// Create a mock base filesystem
	base := &mockFS{}

	// Create an audit log buffer (in production, use a file or log service)
	auditLog := &bytes.Buffer{}

	// Configure comprehensive permission filesystem
	config := permfs.Config{
		ACL: permfs.ACL{
			Entries: []permfs.ACLEntry{
				// Example 1: Basic user permissions
				{
					Subject:     permfs.User("alice"),
					PathPattern: "/home/alice/**",
					Permissions: permfs.ReadWrite | permfs.Delete,
					Effect:      permfs.Allow,
					Priority:    100,
				},

				// Example 2: Group permissions
				{
					Subject:     permfs.Group("engineering"),
					PathPattern: "/projects/**",
					Permissions: permfs.ReadWrite,
					Effect:      permfs.Allow,
					Priority:    100,
				},

				// Example 3: Time-based access (business hours only)
				{
					Subject:     permfs.User("contractor"),
					PathPattern: "/company/**",
					Permissions: permfs.Read,
					Effect:      permfs.Allow,
					Priority:    90,
					Conditions: []permfs.Condition{
						permfs.NewBusinessHoursCondition(),
					},
				},

				// Example 4: IP-based access control
				{
					Subject:     permfs.User("remote_worker"),
					PathPattern: "/secure/**",
					Permissions: permfs.Read,
					Effect:      permfs.Allow,
					Priority:    80,
					Conditions: []permfs.Condition{
						mustCreateIPCondition([]string{"10.0.0.0/8", "192.168.0.0/16"}, nil),
					},
				},

				// Example 5: Custom condition (metadata-based)
				{
					Subject:     permfs.Everyone(),
					PathPattern: "/public/**",
					Permissions: permfs.Read,
					Effect:      permfs.Allow,
					Priority:    10,
				},

				// Example 6: Explicit deny (highest priority)
				{
					Subject:     permfs.Everyone(),
					PathPattern: "/secrets/**",
					Permissions: permfs.All,
					Effect:      permfs.Deny,
					Priority:    1000,
				},

				// Example 7: Admin with full access
				{
					Subject:     permfs.Role("admin"),
					PathPattern: "/**",
					Permissions: permfs.All,
					Effect:      permfs.Allow,
					Priority:    500,
				},
			},
			Default: permfs.Deny, // Secure by default
		},

		// Enable performance caching
		Performance: permfs.PerformanceConfig{
			CacheEnabled:        true,
			CacheTTL:            5 * time.Minute,
			CacheMaxSize:        10000,
			PatternCacheEnabled: true,
		},

		// Enable audit logging
		Audit: permfs.AuditConfig{
			Enabled:    true,
			Writer:     auditLog,
			Level:      ptr(permfs.AuditLevelAll),
			Async:      true,
			BufferSize: 100,
		},
	}

	// Create the permission filesystem
	pfs, err := permfs.New(base, config)
	if err != nil {
		log.Fatal(err)
	}
	defer pfs.Close()

	fmt.Println("✓ Permission filesystem created with caching and audit logging")

	// Example 1: Basic access control
	fmt.Println("--- Example 1: Basic Access Control ---")
	testAccess(pfs, "alice", nil, nil, "/home/alice/document.txt", os.O_RDWR)
	testAccess(pfs, "bob", nil, nil, "/home/alice/document.txt", os.O_RDONLY)

	// Example 2: Group-based access
	fmt.Println("\n--- Example 2: Group-Based Access ---")
	testAccess(pfs, "alice", []string{"engineering"}, nil, "/projects/app/code.go", os.O_RDWR)
	testAccess(pfs, "bob", []string{"marketing"}, nil, "/projects/app/code.go", os.O_RDONLY)

	// Example 3: Role-based access
	fmt.Println("\n--- Example 3: Role-Based Access (Admin) ---")
	testAccess(pfs, "admin_user", nil, []string{"admin"}, "/secrets/key.txt", os.O_RDONLY)
	testAccess(pfs, "regular_user", nil, nil, "/secrets/key.txt", os.O_RDONLY)

	// Example 4: IP-based access
	fmt.Println("\n--- Example 4: IP-Based Access Control ---")
	testAccessWithIP(pfs, "remote_worker", "/secure/data.txt", "192.168.1.100", os.O_RDONLY)
	testAccessWithIP(pfs, "remote_worker", "/secure/data.txt", "203.0.113.50", os.O_RDONLY)

	// Example 5: Public access
	fmt.Println("\n--- Example 5: Public Read Access ---")
	testAccess(pfs, "anyone", nil, nil, "/public/readme.txt", os.O_RDONLY)

	// Example 6: Cache performance
	fmt.Println("\n--- Example 6: Cache Performance ---")
	fmt.Println("Performing repeated access to demonstrate caching...")
	start := time.Now()
	for i := 0; i < 100; i++ {
		testAccess(pfs, "alice", nil, nil, "/home/alice/file.txt", os.O_RDONLY)
	}
	elapsed := time.Since(start)
	fmt.Printf("100 permission checks completed in %v (avg: %v per check)\n",
		elapsed, elapsed/100)

	if stats := pfs.GetCacheStats(); stats != nil {
		fmt.Printf("Cache stats: %d hits, %d misses, %.2f%% hit rate\n",
			stats.Hits, stats.Misses, stats.HitRate*100)
	}

	// Example 7: Dynamic rule management
	fmt.Println("\n--- Example 7: Dynamic Rule Management ---")
	newRule := permfs.ACLEntry{
		Subject:     permfs.User("charlie"),
		PathPattern: "/shared/**",
		Permissions: permfs.Read,
		Effect:      permfs.Allow,
		Priority:    100,
	}

	fmt.Println("Adding new rule for charlie...")
	pfs.AddRule(newRule)
	testAccess(pfs, "charlie", nil, nil, "/shared/data.txt", os.O_RDONLY)

	fmt.Println("Removing rule for charlie...")
	pfs.RemoveRule(newRule)
	testAccess(pfs, "charlie", nil, nil, "/shared/data.txt", os.O_RDONLY)

	// Example 8: Audit metrics
	fmt.Println("\n--- Example 8: Audit Metrics ---")
	auditStats := pfs.GetAuditStats()
	fmt.Printf("Total audit events: %d\n", auditStats.TotalEvents)
	fmt.Printf("  Allowed: %d\n", auditStats.AllowedEvents)
	fmt.Printf("  Denied: %d\n", auditStats.DeniedEvents)
	fmt.Printf("  Average duration: %v\n", auditStats.AverageDuration)

	if metrics := pfs.GetAuditMetrics(); metrics != nil {
		fmt.Println("\nTop denied users:")
		for i, stat := range metrics.GetTopDeniedUsers(3) {
			fmt.Printf("  %d. %s: %d denials\n", i+1, stat.UserID, stat.Count)
		}

		fmt.Println("\nTop accessed paths:")
		for i, stat := range metrics.GetTopAccessedPaths(3) {
			fmt.Printf("  %d. %s: %d accesses\n", i+1, stat.Path, stat.Count)
		}
	}

	// Example 9: Sample audit log
	fmt.Println("\n--- Example 9: Sample Audit Log Entries ---")
	auditLines := bytes.Split(auditLog.Bytes(), []byte("\n"))
	fmt.Printf("Total audit log entries: %d\n", len(auditLines)-1)
	fmt.Println("Sample entries:")
	for i := 0; i < 3 && i < len(auditLines)-1; i++ {
		if len(auditLines[i]) > 0 {
			fmt.Printf("  %s\n", truncate(string(auditLines[i]), 100))
		}
	}

	fmt.Println("\n✓ All examples completed successfully")
}

// Helper functions

func testAccess(pfs *permfs.PermFS, userID string, groups, roles []string, path string, flag int) {
	ctx := context.Background()
	if len(groups) > 0 || len(roles) > 0 {
		ctx = permfs.WithUserGroupsAndRoles(ctx, userID, groups, roles)
	} else {
		ctx = permfs.WithUser(ctx, userID)
	}

	_, err := pfs.OpenFile(ctx, path, flag, 0644)
	if err != nil {
		if permfs.IsPermissionDenied(err) {
			fmt.Printf("  ✗ %s: Access DENIED to %s\n", userID, path)
		} else {
			fmt.Printf("  ⚠ %s: Error accessing %s: %v\n", userID, path, err)
		}
	} else {
		fmt.Printf("  ✓ %s: Access ALLOWED to %s\n", userID, path)
	}
}

func testAccessWithIP(pfs *permfs.PermFS, userID, path, sourceIP string, flag int) {
	ctx := permfs.WithUser(context.Background(), userID)
	ctx = permfs.AddMetadata(ctx, "source_ip", sourceIP)

	_, err := pfs.OpenFile(ctx, path, flag, 0644)
	if err != nil {
		if permfs.IsPermissionDenied(err) {
			fmt.Printf("  ✗ %s from %s: Access DENIED to %s\n", userID, sourceIP, path)
		} else {
			fmt.Printf("  ⚠ %s from %s: Error accessing %s: %v\n", userID, sourceIP, path, err)
		}
	} else {
		fmt.Printf("  ✓ %s from %s: Access ALLOWED to %s\n", userID, sourceIP, path)
	}
}

func mustCreateIPCondition(allowed, denied []string) *permfs.IPCondition {
	cond, err := permfs.NewIPCondition(allowed, denied)
	if err != nil {
		panic(err)
	}
	return cond
}

func ptr[T any](v T) *T {
	return &v
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Mock filesystem (same as other examples)
type mockFS struct{}

func (m *mockFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (permfs.File, error) {
	return &mockFile{}, nil
}
func (m *mockFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return nil
}
func (m *mockFS) MkdirAll(ctx context.Context, name string, perm os.FileMode) error {
	return nil
}
func (m *mockFS) Remove(ctx context.Context, name string) error {
	return nil
}
func (m *mockFS) RemoveAll(ctx context.Context, name string) error {
	return nil
}
func (m *mockFS) Rename(ctx context.Context, oldname, newname string) error {
	return nil
}
func (m *mockFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	return nil, nil
}
func (m *mockFS) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	return nil, nil
}
func (m *mockFS) ReadDir(ctx context.Context, name string) ([]os.FileInfo, error) {
	return nil, nil
}
func (m *mockFS) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	return nil
}
func (m *mockFS) Chown(ctx context.Context, name string, uid, gid int) error {
	return nil
}
func (m *mockFS) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	return nil
}

type mockFile struct{}

func (f *mockFile) Close() error                                           { return nil }
func (f *mockFile) Read(p []byte) (n int, err error)                       { return 0, nil }
func (f *mockFile) Stat() (os.FileInfo, error)                             { return nil, nil }
func (f *mockFile) Write(p []byte) (n int, err error)                      { return len(p), nil }
func (f *mockFile) WriteAt(p []byte, off int64) (n int, err error)         { return len(p), nil }
func (f *mockFile) ReadAt(p []byte, off int64) (n int, err error)          { return 0, nil }
func (f *mockFile) Seek(offset int64, whence int) (int64, error)           { return 0, nil }
func (f *mockFile) Sync() error                                            { return nil }
func (f *mockFile) Truncate(size int64) error                              { return nil }
