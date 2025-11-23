package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/absfs/permfs"
)

// This example demonstrates multi-tenant usage of permfs
// Each tenant has isolated access to their own directory

type TenantFS struct {
	base  permfs.FileSystem
	perms map[string]*permfs.PermFS
}

func NewTenantFS(base permfs.FileSystem) *TenantFS {
	return &TenantFS{
		base:  base,
		perms: make(map[string]*permfs.PermFS),
	}
}

// GetFS returns a filesystem with tenant-specific permissions
func (t *TenantFS) GetFS(tenantID string) (*permfs.PermFS, error) {
	if fs, ok := t.perms[tenantID]; ok {
		return fs, nil
	}

	// Create tenant-specific ACL
	acl := permfs.ACL{
		Entries: []permfs.ACLEntry{
			// Tenant users can read/write their own directory
			{
				Subject:     permfs.Group(tenantID + ":users"),
				PathPattern: fmt.Sprintf("/tenants/%s/**", tenantID),
				Permissions: permfs.ReadWrite,
				Effect:      permfs.Allow,
				Priority:    100,
			},
			// Tenant admins have full control of their directory
			{
				Subject:     permfs.Group(tenantID + ":admins"),
				PathPattern: fmt.Sprintf("/tenants/%s/**", tenantID),
				Permissions: permfs.All,
				Effect:      permfs.Allow,
				Priority:    200,
			},
			// Explicitly deny access to other tenants' directories
			{
				Subject:     permfs.Group(tenantID + ":users"),
				PathPattern: "/tenants/**",
				Permissions: permfs.All,
				Effect:      permfs.Deny,
				Priority:    50,
			},
			// System admins can access everything
			{
				Subject:     permfs.Role("system-admin"),
				PathPattern: "/**",
				Permissions: permfs.All,
				Effect:      permfs.Allow,
				Priority:    1000,
			},
		},
		Default: permfs.Deny,
	}

	fs, err := permfs.New(t.base, permfs.Config{ACL: acl})
	if err != nil {
		return nil, err
	}

	t.perms[tenantID] = fs
	return fs, nil
}

func main() {
	// Create base filesystem
	base := &mockFS{}

	// Create multi-tenant filesystem manager
	tenantFS := NewTenantFS(base)

	// Example 1: Tenant A user accessing their files
	fmt.Println("Example 1: Tenant A user accessing their files")

	fsA, err := tenantFS.GetFS("tenant-a")
	if err != nil {
		log.Fatal(err)
	}

	ctx := permfs.WithUserAndGroups(
		context.Background(),
		"user1",
		[]string{"tenant-a:users"},
	)

	file, err := fsA.OpenFile(ctx, "/tenants/tenant-a/data.txt", 0, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Success: Tenant A user can access their files")
		file.Close()
	}

	// Example 2: Tenant A user trying to access Tenant B files (should fail)
	fmt.Println("\nExample 2: Tenant A user trying to access Tenant B files")

	file, err = fsA.OpenFile(ctx, "/tenants/tenant-b/data.txt", 0, 0644)
	if err != nil {
		if permfs.IsPermissionDenied(err) {
			fmt.Println("Expected: Permission denied - tenant isolation working")
		} else {
			fmt.Printf("Error: %v\n", err)
		}
	} else {
		fmt.Println("Unexpected: Should have been denied")
		file.Close()
	}

	// Example 3: Tenant admin has full control
	fmt.Println("\nExample 3: Tenant A admin has full control")

	ctx = permfs.WithUserAndGroups(
		context.Background(),
		"admin1",
		[]string{"tenant-a:admins"},
	)

	perms, err := fsA.GetPermissions(ctx, "/tenants/tenant-a/config.json")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Tenant admin permissions: %s\n", perms)
		fmt.Printf("  Has admin access: %v\n", perms.Has(permfs.OperationAdmin))
	}

	// Example 4: System admin can access all tenants
	fmt.Println("\nExample 4: System admin can access all tenants")

	ctx = permfs.WithUserGroupsAndRoles(
		context.Background(),
		"sysadmin",
		nil,
		[]string{"system-admin"},
	)

	// System admin can access tenant A
	file, err = fsA.OpenFile(ctx, "/tenants/tenant-a/data.txt", 0, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Success: System admin can access Tenant A files")
		file.Close()
	}

	// System admin can also access tenant B
	fsB, err := tenantFS.GetFS("tenant-b")
	if err != nil {
		log.Fatal(err)
	}

	file, err = fsB.OpenFile(ctx, "/tenants/tenant-b/data.txt", 0, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Success: System admin can access Tenant B files")
		file.Close()
	}

	fmt.Println("\n✓ Multi-tenant isolation working correctly")
}

// mockFS implementation (same as basic example)
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

func (f *mockFile) Close() error                             { return nil }
func (f *mockFile) Read(p []byte) (n int, err error)         { return 0, nil }
func (f *mockFile) Stat() (os.FileInfo, error)               { return nil, nil }
func (f *mockFile) Write(p []byte) (n int, err error)        { return len(p), nil }
func (f *mockFile) WriteAt(p []byte, off int64) (n int, err error) { return len(p), nil }
func (f *mockFile) ReadAt(p []byte, off int64) (n int, err error)  { return 0, nil }
func (f *mockFile) Seek(offset int64, whence int) (int64, error)   { return 0, nil }
func (f *mockFile) Sync() error                                    { return nil }
func (f *mockFile) Truncate(size int64) error                      { return nil }
