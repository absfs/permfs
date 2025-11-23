package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/absfs/permfs"
)

// This example demonstrates basic usage of permfs with a simple ACL
func main() {
	// Create a base filesystem (using mock for demonstration)
	// In a real application, you would use osfs.New("/data") or another filesystem
	base := &mockFS{}

	// Configure the ACL
	config := permfs.Config{
		ACL: permfs.ACL{
			Entries: []permfs.ACLEntry{
				// Alice can read and write her home directory
				{
					Subject:     permfs.User("alice"),
					PathPattern: "/home/alice/**",
					Permissions: permfs.ReadWrite,
					Effect:      permfs.Allow,
					Priority:    100,
				},
				// Bob can only read his home directory
				{
					Subject:     permfs.User("bob"),
					PathPattern: "/home/bob/**",
					Permissions: permfs.Read,
					Effect:      permfs.Allow,
					Priority:    100,
				},
				// Everyone can read public files
				{
					Subject:     permfs.Everyone(),
					PathPattern: "/public/**",
					Permissions: permfs.Read,
					Effect:      permfs.Allow,
					Priority:    1,
				},
				// Admins can do anything
				{
					Subject:     permfs.Role("admin"),
					PathPattern: "/**",
					Permissions: permfs.All,
					Effect:      permfs.Allow,
					Priority:    1000,
				},
			},
			Default: permfs.Deny, // Deny by default (secure)
		},
	}

	// Create the permission filesystem
	pfs, err := permfs.New(base, config)
	if err != nil {
		log.Fatal(err)
	}

	// Example 1: Alice accessing her files
	fmt.Println("Example 1: Alice accessing her files")
	ctx := permfs.WithUser(context.Background(), "alice")

	file, err := pfs.OpenFile(ctx, "/home/alice/document.txt", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Success: Alice can read/write her files")
		file.Close()
	}

	// Example 2: Alice trying to access Bob's files (should fail)
	fmt.Println("\nExample 2: Alice trying to access Bob's files")
	file, err = pfs.OpenFile(ctx, "/home/bob/document.txt", os.O_RDONLY, 0644)
	if err != nil {
		if permfs.IsPermissionDenied(err) {
			fmt.Println("Expected: Permission denied")
		} else {
			fmt.Printf("Unexpected error: %v\n", err)
		}
	} else {
		fmt.Println("Unexpected: Should have been denied")
		file.Close()
	}

	// Example 3: Anyone can read public files
	fmt.Println("\nExample 3: Bob reading public files")
	ctx = permfs.WithUser(context.Background(), "bob")

	file, err = pfs.OpenFile(ctx, "/public/readme.txt", os.O_RDONLY, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Success: Bob can read public files")
		file.Close()
	}

	// Example 4: Admin can access anything
	fmt.Println("\nExample 4: Admin accessing any file")
	ctx = permfs.WithUserGroupsAndRoles(context.Background(), "adminuser", nil, []string{"admin"})

	file, err = pfs.OpenFile(ctx, "/home/alice/secret.txt", os.O_RDWR, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Success: Admin can access any file")
		file.Close()
	}

	// Example 5: Check permissions programmatically
	fmt.Println("\nExample 5: Checking permissions programmatically")
	ctx = permfs.WithUser(context.Background(), "alice")
	perms, err := pfs.GetPermissions(ctx, "/home/alice/file.txt")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Alice's permissions on /home/alice/file.txt: %s\n", perms)
		fmt.Printf("  Can read: %v\n", perms.Has(permfs.OperationRead))
		fmt.Printf("  Can write: %v\n", perms.Has(permfs.OperationWrite))
		fmt.Printf("  Can delete: %v\n", perms.Has(permfs.OperationDelete))
	}

	// Example 6: Dynamic rule management
	fmt.Println("\nExample 6: Adding a new rule dynamically")
	newRule := permfs.ACLEntry{
		Subject:     permfs.User("charlie"),
		PathPattern: "/shared/**",
		Permissions: permfs.Read,
		Effect:      permfs.Allow,
		Priority:    100,
	}

	err = pfs.AddRule(newRule)
	if err != nil {
		fmt.Printf("Error adding rule: %v\n", err)
	} else {
		fmt.Println("Success: Added rule for Charlie to access /shared")

		// Charlie can now access shared files
		ctx = permfs.WithUser(context.Background(), "charlie")
		file, err = pfs.OpenFile(ctx, "/shared/data.txt", os.O_RDONLY, 0644)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println("Charlie can now access shared files")
			file.Close()
		}
	}
}

// mockFS is a simple mock filesystem for demonstration
type mockFS struct{}

func (m *mockFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (permfs.File, error) {
	return &mockFile{name: name}, nil
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

// mockFile implements permfs.File
type mockFile struct {
	name string
}

func (f *mockFile) Close() error                             { return nil }
func (f *mockFile) Read(p []byte) (n int, err error)         { return 0, nil }
func (f *mockFile) Stat() (os.FileInfo, error)               { return nil, nil }
func (f *mockFile) Write(p []byte) (n int, err error)        { return len(p), nil }
func (f *mockFile) WriteAt(p []byte, off int64) (n int, err error) { return len(p), nil }
func (f *mockFile) ReadAt(p []byte, off int64) (n int, err error)  { return 0, nil }
func (f *mockFile) Seek(offset int64, whence int) (int64, error)   { return 0, nil }
func (f *mockFile) Sync() error                                    { return nil }
func (f *mockFile) Truncate(size int64) error                      { return nil }
