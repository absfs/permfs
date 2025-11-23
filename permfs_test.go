package permfs

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// mockFileSystem is a simple mock implementation for testing
type mockFileSystem struct {
	openFileCalled   bool
	mkdirCalled      bool
	removeCalled     bool
	renameCalled     bool
	statCalled       bool
	readDirCalled    bool
	chmodCalled      bool
	chownCalled      bool
	chtimesCalled    bool
	lastPath         string
	lastOperation    string
	shouldReturnFile bool
}

func (m *mockFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (File, error) {
	m.openFileCalled = true
	m.lastPath = name
	m.lastOperation = "OpenFile"
	if m.shouldReturnFile {
		return &mockFile{}, nil
	}
	return nil, errors.New("mock error")
}

func (m *mockFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	m.mkdirCalled = true
	m.lastPath = name
	m.lastOperation = "Mkdir"
	return nil
}

func (m *mockFileSystem) MkdirAll(ctx context.Context, name string, perm os.FileMode) error {
	m.lastPath = name
	m.lastOperation = "MkdirAll"
	return nil
}

func (m *mockFileSystem) Remove(ctx context.Context, name string) error {
	m.removeCalled = true
	m.lastPath = name
	m.lastOperation = "Remove"
	return nil
}

func (m *mockFileSystem) RemoveAll(ctx context.Context, name string) error {
	m.lastPath = name
	m.lastOperation = "RemoveAll"
	return nil
}

func (m *mockFileSystem) Rename(ctx context.Context, oldname, newname string) error {
	m.renameCalled = true
	m.lastPath = oldname
	m.lastOperation = "Rename"
	return nil
}

func (m *mockFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	m.statCalled = true
	m.lastPath = name
	m.lastOperation = "Stat"
	return &mockFileInfo{}, nil
}

func (m *mockFileSystem) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	m.lastPath = name
	m.lastOperation = "Lstat"
	return &mockFileInfo{}, nil
}

func (m *mockFileSystem) ReadDir(ctx context.Context, name string) ([]os.FileInfo, error) {
	m.readDirCalled = true
	m.lastPath = name
	m.lastOperation = "ReadDir"
	return []os.FileInfo{&mockFileInfo{}}, nil
}

func (m *mockFileSystem) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	m.chmodCalled = true
	m.lastPath = name
	m.lastOperation = "Chmod"
	return nil
}

func (m *mockFileSystem) Chown(ctx context.Context, name string, uid, gid int) error {
	m.chownCalled = true
	m.lastPath = name
	m.lastOperation = "Chown"
	return nil
}

func (m *mockFileSystem) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	m.chtimesCalled = true
	m.lastPath = name
	m.lastOperation = "Chtimes"
	return nil
}

// mockFile implements the File interface
type mockFile struct{}

func (f *mockFile) Stat() (os.FileInfo, error)         { return &mockFileInfo{}, nil }
func (f *mockFile) Read(p []byte) (n int, err error)   { return 0, nil }
func (f *mockFile) Close() error                       { return nil }
func (f *mockFile) Write(p []byte) (n int, err error)  { return len(p), nil }
func (f *mockFile) WriteAt(p []byte, off int64) (n int, err error) { return len(p), nil }
func (f *mockFile) ReadAt(p []byte, off int64) (n int, err error)  { return 0, nil }
func (f *mockFile) Seek(offset int64, whence int) (int64, error)   { return 0, nil }
func (f *mockFile) Sync() error                                    { return nil }
func (f *mockFile) Truncate(size int64) error                      { return nil }

// mockFileInfo implements os.FileInfo
type mockFileInfo struct{}

func (fi *mockFileInfo) Name() string       { return "mockfile" }
func (fi *mockFileInfo) Size() int64        { return 0 }
func (fi *mockFileInfo) Mode() os.FileMode  { return 0644 }
func (fi *mockFileInfo) ModTime() time.Time { return time.Now() }
func (fi *mockFileInfo) IsDir() bool        { return false }
func (fi *mockFileInfo) Sys() interface{}   { return nil }

func TestPermFSOpenFilePermissions(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite,
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

	tests := []struct {
		name        string
		user        string
		path        string
		flag        int
		shouldAllow bool
	}{
		{
			name:        "alice can read her files",
			user:        "alice",
			path:        "/home/alice/file.txt",
			flag:        os.O_RDONLY,
			shouldAllow: true,
		},
		{
			name:        "alice can write her files",
			user:        "alice",
			path:        "/home/alice/file.txt",
			flag:        os.O_WRONLY,
			shouldAllow: true,
		},
		{
			name:        "alice can read/write her files",
			user:        "alice",
			path:        "/home/alice/file.txt",
			flag:        os.O_RDWR,
			shouldAllow: true,
		},
		{
			name:        "bob cannot read alice's files",
			user:        "bob",
			path:        "/home/alice/file.txt",
			flag:        os.O_RDONLY,
			shouldAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithUser(context.Background(), tt.user)
			_, err := pfs.OpenFile(ctx, tt.path, tt.flag, 0644)

			if tt.shouldAllow && err != nil {
				t.Errorf("expected operation to be allowed, got error: %v", err)
			}
			if !tt.shouldAllow && err == nil {
				t.Error("expected operation to be denied, but it was allowed")
			}
			if !tt.shouldAllow && err != nil && !IsPermissionDenied(err) {
				t.Errorf("expected permission denied error, got: %v", err)
			}
		})
	}
}

func TestPermFSMkdirPermissions(t *testing.T) {
	mock := &mockFileSystem{}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite,
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

	tests := []struct {
		name        string
		user        string
		path        string
		shouldAllow bool
	}{
		{
			name:        "alice can create directories in her home",
			user:        "alice",
			path:        "/home/alice/newdir",
			shouldAllow: true,
		},
		{
			name:        "bob cannot create directories in alice's home",
			user:        "bob",
			path:        "/home/alice/newdir",
			shouldAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithUser(context.Background(), tt.user)
			err := pfs.Mkdir(ctx, tt.path, 0755)

			if tt.shouldAllow && err != nil {
				t.Errorf("expected operation to be allowed, got error: %v", err)
			}
			if !tt.shouldAllow && err == nil {
				t.Error("expected operation to be denied, but it was allowed")
			}
			if tt.shouldAllow && mock.lastOperation != "Mkdir" {
				t.Error("expected Mkdir to be called on base filesystem")
			}
		})
	}
}

func TestPermFSRemovePermissions(t *testing.T) {
	mock := &mockFileSystem{}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite | Delete,
				Effect:      Allow,
				Priority:    100,
			},
			{
				Subject:     User("bob"),
				PathPattern: "/home/bob/**",
				Permissions: ReadWrite,
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

	tests := []struct {
		name        string
		user        string
		path        string
		shouldAllow bool
	}{
		{
			name:        "alice can delete her files",
			user:        "alice",
			path:        "/home/alice/file.txt",
			shouldAllow: true,
		},
		{
			name:        "bob cannot delete his files (no delete permission)",
			user:        "bob",
			path:        "/home/bob/file.txt",
			shouldAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithUser(context.Background(), tt.user)
			err := pfs.Remove(ctx, tt.path)

			if tt.shouldAllow && err != nil {
				t.Errorf("expected operation to be allowed, got error: %v", err)
			}
			if !tt.shouldAllow && err == nil {
				t.Error("expected operation to be denied, but it was allowed")
			}
		})
	}
}

func TestPermFSRenamePermissions(t *testing.T) {
	mock := &mockFileSystem{}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite | Delete,
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

	ctx := WithUser(context.Background(), "alice")

	// Alice can rename within her directory
	err = pfs.Rename(ctx, "/home/alice/old.txt", "/home/alice/new.txt")
	if err != nil {
		t.Errorf("expected rename to be allowed: %v", err)
	}

	// Alice cannot rename to bob's directory
	err = pfs.Rename(ctx, "/home/alice/file.txt", "/home/bob/file.txt")
	if err == nil {
		t.Error("expected rename to be denied")
	}
}

func TestPermFSStatPermissions(t *testing.T) {
	mock := &mockFileSystem{}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: Metadata,
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

	ctx := WithUser(context.Background(), "alice")

	// Alice can stat her files
	_, err = pfs.Stat(ctx, "/home/alice/file.txt")
	if err != nil {
		t.Errorf("expected stat to be allowed: %v", err)
	}

	// Alice cannot stat bob's files
	_, err = pfs.Stat(ctx, "/home/bob/file.txt")
	if err == nil {
		t.Error("expected stat to be denied")
	}
}

func TestPermFSChownPermissions(t *testing.T) {
	mock := &mockFileSystem{}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("admin"),
				PathPattern: "/**",
				Permissions: Admin,
				Effect:      Allow,
				Priority:    1000,
			},
		},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	// Admin can chown
	ctx := WithUser(context.Background(), "admin")
	err = pfs.Chown(ctx, "/any/file.txt", 1000, 1000)
	if err != nil {
		t.Errorf("expected chown to be allowed for admin: %v", err)
	}

	// Regular user cannot chown
	ctx = WithUser(context.Background(), "alice")
	err = pfs.Chown(ctx, "/any/file.txt", 1000, 1000)
	if err == nil {
		t.Error("expected chown to be denied for regular user")
	}
}

func TestPermFSNoIdentityError(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{},
		Default: Allow,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	// Context without identity should return error
	ctx := context.Background()
	_, err = pfs.OpenFile(ctx, "/file.txt", os.O_RDONLY, 0644)
	if err == nil {
		t.Error("expected error when no identity in context")
	}
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("expected ErrNoIdentity, got: %v", err)
	}
}

func TestGetPermissions(t *testing.T) {
	mock := &mockFileSystem{}
	acl := ACL{
		Entries: []ACLEntry{
			{
				Subject:     User("alice"),
				PathPattern: "/home/alice/**",
				Permissions: ReadWrite | Delete,
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

	ctx := WithUser(context.Background(), "alice")
	perms, err := pfs.GetPermissions(ctx, "/home/alice/file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !perms.Has(OperationRead) {
		t.Error("expected Read permission")
	}
	if !perms.Has(OperationWrite) {
		t.Error("expected Write permission")
	}
	if !perms.Has(OperationDelete) {
		t.Error("expected Delete permission")
	}
	if perms.Has(OperationAdmin) {
		t.Error("did not expect Admin permission")
	}
}

func TestAddRemoveRule(t *testing.T) {
	mock := &mockFileSystem{shouldReturnFile: true}
	acl := ACL{
		Entries: []ACLEntry{},
		Default: Deny,
	}

	pfs, err := New(mock, Config{ACL: acl})
	if err != nil {
		t.Fatalf("failed to create PermFS: %v", err)
	}

	ctx := WithUser(context.Background(), "alice")

	// Initially, alice cannot access the file
	_, err = pfs.OpenFile(ctx, "/data/file.txt", os.O_RDONLY, 0644)
	if err == nil {
		t.Error("expected access to be denied initially")
	}

	// Add a rule granting access
	newRule := ACLEntry{
		Subject:     User("alice"),
		PathPattern: "/data/**",
		Permissions: Read,
		Effect:      Allow,
		Priority:    100,
	}
	err = pfs.AddRule(newRule)
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	// Now alice can access the file
	_, err = pfs.OpenFile(ctx, "/data/file.txt", os.O_RDONLY, 0644)
	if err != nil {
		t.Errorf("expected access to be allowed after adding rule: %v", err)
	}

	// Remove the rule
	err = pfs.RemoveRule(newRule)
	if err != nil {
		t.Fatalf("failed to remove rule: %v", err)
	}

	// Access should be denied again
	_, err = pfs.OpenFile(ctx, "/data/file.txt", os.O_RDONLY, 0644)
	if err == nil {
		t.Error("expected access to be denied after removing rule")
	}
}
