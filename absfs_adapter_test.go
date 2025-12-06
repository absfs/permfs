package permfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/absfs/absfs"
)

// Verify compile-time interface compliance
var (
	_ absfs.FileSystem = (*AbsAdapter)(nil)
	_ absfs.SymLinker  = (*AbsAdapter)(nil)
)

func TestAbsAdapterCreation(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("testuser"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	t.Run("NewAbsAdapter with identity", func(t *testing.T) {
		identity := &Identity{UserID: "testuser"}
		adapter := NewAbsAdapter(pfs, identity)

		if adapter == nil {
			t.Fatal("expected adapter to be created")
		}
		if adapter.PermFS() != pfs {
			t.Error("PermFS() should return the wrapped PermFS")
		}

		cwd, err := adapter.Getwd()
		if err != nil {
			t.Fatalf("Getwd error: %v", err)
		}
		if cwd != string(filepath.Separator) {
			t.Errorf("expected initial cwd to be %q, got %q", string(filepath.Separator), cwd)
		}
	})

	t.Run("NewAbsAdapter with nil identity", func(t *testing.T) {
		adapter := NewAbsAdapter(pfs, nil)
		if adapter == nil {
			t.Fatal("expected adapter to be created even with nil identity")
		}
	})

	t.Run("NewAbsAdapterWithContext", func(t *testing.T) {
		ctx := WithUser(context.Background(), "testuser")
		adapter := NewAbsAdapterWithContext(pfs, ctx)

		if adapter == nil {
			t.Fatal("expected adapter to be created")
		}
	})

	t.Run("NewAbsAdapterWithContext nil context", func(t *testing.T) {
		adapter := NewAbsAdapterWithContext(pfs, nil)
		if adapter == nil {
			t.Fatal("expected adapter to be created with nil context")
		}
	})
}

func TestAbsAdapterSetters(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/alice/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     User("bob"),
				PathPattern: "/bob/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	adapter := NewAbsAdapter(pfs, &Identity{UserID: "alice"})

	t.Run("SetIdentity changes permissions", func(t *testing.T) {
		// Alice can access /alice
		_, err := adapter.Stat("/alice/file.txt")
		if err != nil {
			t.Errorf("alice should access /alice: %v", err)
		}

		// Change to bob
		adapter.SetIdentity(&Identity{UserID: "bob"})

		// Bob cannot access /alice (should fail)
		_, err = adapter.Stat("/alice/file.txt")
		if err == nil {
			t.Error("bob should not access /alice")
		}

		// Bob can access /bob
		_, err = adapter.Stat("/bob/file.txt")
		if err != nil {
			t.Errorf("bob should access /bob: %v", err)
		}
	})

	t.Run("SetContext changes permissions", func(t *testing.T) {
		adapter.SetContext(WithUser(context.Background(), "alice"))

		_, err := adapter.Stat("/alice/file.txt")
		if err != nil {
			t.Errorf("alice should access /alice after SetContext: %v", err)
		}
	})
}

func TestAbsAdapterSeparators(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	pfs, _ := New(mock, Config{ACL: ACL{Default: Allow}})
	adapter := NewAbsAdapter(pfs, &Identity{UserID: "test"})

	t.Run("Separator", func(t *testing.T) {
		sep := adapter.Separator()
		if sep != filepath.Separator {
			t.Errorf("expected separator %d, got %d", filepath.Separator, sep)
		}
	})

	t.Run("ListSeparator", func(t *testing.T) {
		sep := adapter.ListSeparator()
		if sep != filepath.ListSeparator {
			t.Errorf("expected list separator %d, got %d", filepath.ListSeparator, sep)
		}
	})
}

func TestAbsAdapterDirectoryNavigation(t *testing.T) {
	mock := &mockFileSystemWithDir{mockFileSystem: mockFileSystem{shouldReturnFile: true}, isDir: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("testuser"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	adapter := NewAbsAdapter(pfs, &Identity{UserID: "testuser"})

	t.Run("Chdir and Getwd", func(t *testing.T) {
		err := adapter.Chdir("/home/testuser")
		if err != nil {
			t.Fatalf("Chdir error: %v", err)
		}

		cwd, err := adapter.Getwd()
		if err != nil {
			t.Fatalf("Getwd error: %v", err)
		}

		expected := filepath.Clean("/home/testuser")
		if cwd != expected {
			t.Errorf("expected cwd %q, got %q", expected, cwd)
		}
	})

	t.Run("Chdir to non-directory fails", func(t *testing.T) {
		mock.isDir = false
		err := adapter.Chdir("/some/file.txt")
		if err == nil {
			t.Error("expected error when Chdir to non-directory")
		}
		mock.isDir = true
	})

	t.Run("TempDir", func(t *testing.T) {
		tmpDir := adapter.TempDir()
		if tmpDir == "" {
			t.Error("TempDir should not return empty string")
		}
	})
}

func TestAbsAdapterFileOperations(t *testing.T) {
	mock := &mockFileSystemWithDir{mockFileSystem: mockFileSystem{shouldReturnFile: true}}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("testuser"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	adapter := NewAbsAdapter(pfs, &Identity{UserID: "testuser"})

	t.Run("Open", func(t *testing.T) {
		f, err := adapter.Open("/test/file.txt")
		if err != nil {
			t.Fatalf("Open error: %v", err)
		}
		if f == nil {
			t.Fatal("expected file to be returned")
		}
		f.Close()
	})

	t.Run("Create", func(t *testing.T) {
		f, err := adapter.Create("/test/newfile.txt")
		if err != nil {
			t.Fatalf("Create error: %v", err)
		}
		if f == nil {
			t.Fatal("expected file to be returned")
		}
		f.Close()
	})

	t.Run("OpenFile", func(t *testing.T) {
		f, err := adapter.OpenFile("/test/file.txt", os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			t.Fatalf("OpenFile error: %v", err)
		}
		if f == nil {
			t.Fatal("expected file to be returned")
		}
		f.Close()
	})

	t.Run("Mkdir", func(t *testing.T) {
		err := adapter.Mkdir("/test/newdir", 0755)
		if err != nil {
			t.Errorf("Mkdir error: %v", err)
		}
	})

	t.Run("MkdirAll", func(t *testing.T) {
		err := adapter.MkdirAll("/test/a/b/c", 0755)
		if err != nil {
			t.Errorf("MkdirAll error: %v", err)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		err := adapter.Remove("/test/file.txt")
		if err != nil {
			t.Errorf("Remove error: %v", err)
		}
	})

	t.Run("RemoveAll", func(t *testing.T) {
		err := adapter.RemoveAll("/test/dir")
		if err != nil {
			t.Errorf("RemoveAll error: %v", err)
		}
	})

	t.Run("Rename", func(t *testing.T) {
		err := adapter.Rename("/test/old.txt", "/test/new.txt")
		if err != nil {
			t.Errorf("Rename error: %v", err)
		}
	})

	t.Run("Stat", func(t *testing.T) {
		info, err := adapter.Stat("/test/file.txt")
		if err != nil {
			t.Fatalf("Stat error: %v", err)
		}
		if info == nil {
			t.Fatal("expected FileInfo to be returned")
		}
	})

	t.Run("Chmod", func(t *testing.T) {
		err := adapter.Chmod("/test/file.txt", 0600)
		if err != nil {
			t.Errorf("Chmod error: %v", err)
		}
	})

	t.Run("Chown", func(t *testing.T) {
		err := adapter.Chown("/test/file.txt", 1000, 1000)
		if err != nil {
			t.Errorf("Chown error: %v", err)
		}
	})

	t.Run("Chtimes", func(t *testing.T) {
		now := time.Now()
		err := adapter.Chtimes("/test/file.txt", now, now)
		if err != nil {
			t.Errorf("Chtimes error: %v", err)
		}
	})

	t.Run("Truncate", func(t *testing.T) {
		err := adapter.Truncate("/test/file.txt", 100)
		if err != nil {
			t.Errorf("Truncate error: %v", err)
		}
	})
}

func TestAbsAdapterSymLinker(t *testing.T) {
	mock := &mockFileSystemWithDir{mockFileSystem: mockFileSystem{shouldReturnFile: true}}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("testuser"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	adapter := NewAbsAdapter(pfs, &Identity{UserID: "testuser"})

	t.Run("Lstat", func(t *testing.T) {
		info, err := adapter.Lstat("/test/file.txt")
		if err != nil {
			t.Fatalf("Lstat error: %v", err)
		}
		if info == nil {
			t.Fatal("expected FileInfo to be returned")
		}
	})

	t.Run("Lchown", func(t *testing.T) {
		err := adapter.Lchown("/test/file.txt", 1000, 1000)
		if err != nil {
			t.Errorf("Lchown error: %v", err)
		}
	})

	t.Run("Readlink returns not implemented", func(t *testing.T) {
		_, err := adapter.Readlink("/test/symlink")
		if err == nil {
			t.Error("expected error from Readlink")
		}
		if !errors.Is(err, absfs.ErrNotImplemented) {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				if !errors.Is(pathErr.Err, absfs.ErrNotImplemented) {
					t.Errorf("expected ErrNotImplemented, got: %v", err)
				}
			} else {
				t.Errorf("expected PathError with ErrNotImplemented, got: %v", err)
			}
		}
	})

	t.Run("Symlink returns not implemented", func(t *testing.T) {
		err := adapter.Symlink("/test/target", "/test/link")
		if err == nil {
			t.Error("expected error from Symlink")
		}
	})
}

func TestAbsAdapterRelativePaths(t *testing.T) {
	mock := &mockFileSystemWithDir{mockFileSystem: mockFileSystem{shouldReturnFile: true}, isDir: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("testuser"),
				PathPattern: "/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	adapter := NewAbsAdapter(pfs, &Identity{UserID: "testuser"})

	// Change to a directory
	err = adapter.Chdir("/home/testuser")
	if err != nil {
		t.Fatalf("Chdir error: %v", err)
	}

	t.Run("relative path is resolved", func(t *testing.T) {
		_, err := adapter.Stat("subdir/file.txt")
		if err != nil {
			t.Fatalf("Stat error: %v", err)
		}

		// Verify the mock received the resolved path
		expectedPath := filepath.Clean("/home/testuser/subdir/file.txt")
		if mock.lastPath != expectedPath {
			t.Errorf("expected path %q, got %q", expectedPath, mock.lastPath)
		}
	})
}

func TestAbsAdapterPermissionDenied(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/alice/**",
				Permissions: All,
				Effect:      Allow,
				Priority:    100,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	adapter := NewAbsAdapter(pfs, &Identity{UserID: "bob"})

	t.Run("access denied for unauthorized user", func(t *testing.T) {
		_, err := adapter.Stat("/alice/private.txt")
		if err == nil {
			t.Error("expected permission denied error")
		}
	})
}

func TestAbsAdapterNoIdentity(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	pfs, _ := New(mock, Config{ACL: ACL{Default: Allow}})
	adapter := NewAbsAdapter(pfs, nil)

	t.Run("operations fail without identity", func(t *testing.T) {
		_, err := adapter.Stat("/test/file.txt")
		if err == nil {
			t.Error("expected error when no identity set")
		}
		if !errors.Is(err, ErrNoIdentity) {
			t.Errorf("expected ErrNoIdentity, got: %v", err)
		}
	})
}

func TestAbsFile(t *testing.T) {
	mock := &mockFileWithReaddir{}

	af := &absFile{f: mock}

	t.Run("Name", func(t *testing.T) {
		name := af.Name()
		if name != "testfile" {
			t.Errorf("expected name 'testfile', got %q", name)
		}
	})

	t.Run("Read", func(t *testing.T) {
		buf := make([]byte, 10)
		n, err := af.Read(buf)
		if err != nil {
			t.Errorf("Read error: %v", err)
		}
		if n != 5 {
			t.Errorf("expected 5 bytes, got %d", n)
		}
	})

	t.Run("Write", func(t *testing.T) {
		n, err := af.Write([]byte("hello"))
		if err != nil {
			t.Errorf("Write error: %v", err)
		}
		if n != 5 {
			t.Errorf("expected 5 bytes written, got %d", n)
		}
	})

	t.Run("WriteString", func(t *testing.T) {
		n, err := af.WriteString("hello")
		if err != nil {
			t.Errorf("WriteString error: %v", err)
		}
		if n != 5 {
			t.Errorf("expected 5 bytes written, got %d", n)
		}
	})

	t.Run("Close", func(t *testing.T) {
		err := af.Close()
		if err != nil {
			t.Errorf("Close error: %v", err)
		}
	})

	t.Run("Sync", func(t *testing.T) {
		err := af.Sync()
		if err != nil {
			t.Errorf("Sync error: %v", err)
		}
	})

	t.Run("Stat", func(t *testing.T) {
		info, err := af.Stat()
		if err != nil {
			t.Errorf("Stat error: %v", err)
		}
		if info == nil {
			t.Error("expected FileInfo")
		}
	})

	t.Run("Readdir", func(t *testing.T) {
		infos, err := af.Readdir(10)
		if err != nil {
			t.Errorf("Readdir error: %v", err)
		}
		if len(infos) != 2 {
			t.Errorf("expected 2 entries, got %d", len(infos))
		}
	})

	t.Run("Readdirnames", func(t *testing.T) {
		names, err := af.Readdirnames(10)
		if err != nil {
			t.Errorf("Readdirnames error: %v", err)
		}
		if len(names) != 2 {
			t.Errorf("expected 2 names, got %d", len(names))
		}
	})

	t.Run("Seek", func(t *testing.T) {
		pos, err := af.Seek(100, 0)
		if err != nil {
			t.Errorf("Seek error: %v", err)
		}
		if pos != 100 {
			t.Errorf("expected position 100, got %d", pos)
		}
	})

	t.Run("ReadAt", func(t *testing.T) {
		buf := make([]byte, 10)
		n, err := af.ReadAt(buf, 50)
		if err != nil {
			t.Errorf("ReadAt error: %v", err)
		}
		if n != 5 {
			t.Errorf("expected 5 bytes, got %d", n)
		}
	})

	t.Run("WriteAt", func(t *testing.T) {
		n, err := af.WriteAt([]byte("hello"), 50)
		if err != nil {
			t.Errorf("WriteAt error: %v", err)
		}
		if n != 5 {
			t.Errorf("expected 5 bytes written, got %d", n)
		}
	})

	t.Run("Truncate", func(t *testing.T) {
		err := af.Truncate(500)
		if err != nil {
			t.Errorf("Truncate error: %v", err)
		}
	})
}

func TestAbsFileReaddirFallback(t *testing.T) {
	// Test with a file that doesn't have Readdirnames method
	mock := &mockFileWithReaddir{}
	af := &absFile{f: mock}

	names, err := af.Readdirnames(10)
	if err != nil {
		t.Errorf("Readdirnames error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}
}

// Extended mock that supports IsDir for Chdir testing
type mockFileSystemWithDir struct {
	mockFileSystem
	isDir bool
}

func (m *mockFileSystemWithDir) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	m.statCalled = true
	m.lastPath = name
	m.lastOperation = "Stat"
	return &mockFileInfoWithDir{isDir: m.isDir}, nil
}

func (m *mockFileSystemWithDir) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	m.lastPath = name
	m.lastOperation = "Lstat"
	return &mockFileInfoWithDir{isDir: m.isDir}, nil
}

type mockFileInfoWithDir struct {
	isDir bool
}

func (fi *mockFileInfoWithDir) Name() string       { return "mockfile" }
func (fi *mockFileInfoWithDir) Size() int64        { return 0 }
func (fi *mockFileInfoWithDir) Mode() os.FileMode  { return 0644 }
func (fi *mockFileInfoWithDir) ModTime() time.Time { return time.Now() }
func (fi *mockFileInfoWithDir) IsDir() bool        { return fi.isDir }
func (fi *mockFileInfoWithDir) Sys() interface{}   { return nil }

// mockFileWithReaddir is a mock file that supports Readdir
type mockFileWithReaddir struct{}

func (f *mockFileWithReaddir) Name() string                               { return "testfile" }
func (f *mockFileWithReaddir) Stat() (os.FileInfo, error)                 { return &mockFileInfo{}, nil }
func (f *mockFileWithReaddir) Read(p []byte) (n int, err error)           { return 5, nil }
func (f *mockFileWithReaddir) Close() error                               { return nil }
func (f *mockFileWithReaddir) Write(p []byte) (n int, err error)          { return len(p), nil }
func (f *mockFileWithReaddir) WriteAt(p []byte, off int64) (n int, err error) { return len(p), nil }
func (f *mockFileWithReaddir) ReadAt(p []byte, off int64) (n int, err error)  { return 5, nil }
func (f *mockFileWithReaddir) Seek(offset int64, whence int) (int64, error)   { return offset, nil }
func (f *mockFileWithReaddir) Sync() error                                    { return nil }
func (f *mockFileWithReaddir) Truncate(size int64) error                      { return nil }
func (f *mockFileWithReaddir) Readdir(n int) ([]os.FileInfo, error) {
	return []os.FileInfo{&mockFileInfo{}, &mockFileInfo{}}, nil
}

func init() {
	// Make mockFileSystemWithDir implement Stat returning a directory by default
	// for Chdir tests
}
