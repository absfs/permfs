package permfs

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/absfs/absfs"
)

// Compile-time interface checks
var (
	// Note: absfs.FileSystem no longer requires Separator/ListSeparator in 1.0
	_ absfs.Filer     = (*AbsAdapter)(nil)
	_ absfs.SymLinker = (*AbsAdapter)(nil)
)

// AbsAdapter wraps a PermFS to implement absfs.FileSystem interface.
// It stores a context internally which is used for all permission checks.
// The context can be updated via SetContext or SetIdentity methods.
type AbsAdapter struct {
	pfs *PermFS
	ctx context.Context
	cwd string
	mu  sync.RWMutex
}

// NewAbsAdapter creates a new absfs.FileSystem compatible wrapper around PermFS.
// The provided identity will be used for all permission checks.
// If identity is nil, all operations will fail with ErrNoIdentity until an identity is set.
func NewAbsAdapter(pfs *PermFS, identity *Identity) *AbsAdapter {
	ctx := context.Background()
	if identity != nil {
		ctx = WithIdentity(ctx, identity)
	}
	return &AbsAdapter{
		pfs: pfs,
		ctx: ctx,
		cwd: string(filepath.Separator),
	}
}

// NewAbsAdapterWithContext creates a new absfs.FileSystem compatible wrapper
// using the provided context for permission checks.
func NewAbsAdapterWithContext(pfs *PermFS, ctx context.Context) *AbsAdapter {
	if ctx == nil {
		ctx = context.Background()
	}
	return &AbsAdapter{
		pfs: pfs,
		ctx: ctx,
		cwd: string(filepath.Separator),
	}
}

// SetContext updates the context used for permission checking.
// This is useful when the identity needs to change during the adapter's lifetime.
func (a *AbsAdapter) SetContext(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ctx = ctx
}

// SetIdentity updates the identity used for permission checking.
// This creates a new context with the provided identity.
func (a *AbsAdapter) SetIdentity(identity *Identity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ctx = WithIdentity(context.Background(), identity)
}

// getContext returns the current context in a thread-safe manner.
func (a *AbsAdapter) getContext() context.Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ctx
}

// resolvePath resolves a path relative to the current working directory.
func (a *AbsAdapter) resolvePath(name string) string {
	if filepath.IsAbs(name) || (len(name) > 0 && (name[0] == '/' || name[0] == '\\')) {
		return filepath.Clean(name)
	}
	a.mu.RLock()
	cwd := a.cwd
	a.mu.RUnlock()
	return filepath.Clean(filepath.Join(cwd, name))
}

// PermFS returns the underlying PermFS instance.
func (a *AbsAdapter) PermFS() *PermFS {
	return a.pfs
}

// --- absfs.Filer interface ---

// OpenFile opens a file with the specified flags and permissions.
func (a *AbsAdapter) OpenFile(name string, flag int, perm os.FileMode) (absfs.File, error) {
	path := a.resolvePath(name)
	f, err := a.pfs.OpenFile(a.getContext(), path, flag, perm)
	if err != nil {
		return nil, err
	}
	return &absFile{f}, nil
}

// Mkdir creates a directory.
func (a *AbsAdapter) Mkdir(name string, perm os.FileMode) error {
	path := a.resolvePath(name)
	return a.pfs.Mkdir(a.getContext(), path, perm)
}

// Remove removes a file or empty directory.
func (a *AbsAdapter) Remove(name string) error {
	path := a.resolvePath(name)
	return a.pfs.Remove(a.getContext(), path)
}

// Rename renames (moves) a file.
func (a *AbsAdapter) Rename(oldpath, newpath string) error {
	oldpath = a.resolvePath(oldpath)
	newpath = a.resolvePath(newpath)
	return a.pfs.Rename(a.getContext(), oldpath, newpath)
}

// Stat returns file information.
func (a *AbsAdapter) Stat(name string) (os.FileInfo, error) {
	path := a.resolvePath(name)
	return a.pfs.Stat(a.getContext(), path)
}

// Chmod changes the mode of the named file.
func (a *AbsAdapter) Chmod(name string, mode os.FileMode) error {
	path := a.resolvePath(name)
	return a.pfs.Chmod(a.getContext(), path, mode)
}

// Chtimes changes the access and modification times of the named file.
func (a *AbsAdapter) Chtimes(name string, atime time.Time, mtime time.Time) error {
	path := a.resolvePath(name)
	return a.pfs.Chtimes(a.getContext(), path, atime, mtime)
}

// Chown changes the numeric uid and gid of the named file.
func (a *AbsAdapter) Chown(name string, uid, gid int) error {
	path := a.resolvePath(name)
	return a.pfs.Chown(a.getContext(), path, uid, gid)
}

// --- absfs.FileSystem additional methods ---

// Chdir changes the current working directory.
func (a *AbsAdapter) Chdir(dir string) error {
	path := a.resolvePath(dir)

	// Verify the directory exists and is a directory
	info, err := a.pfs.Stat(a.getContext(), path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return &os.PathError{Op: "chdir", Path: dir, Err: os.ErrInvalid}
	}

	a.mu.Lock()
	a.cwd = path
	a.mu.Unlock()
	return nil
}

// Getwd returns the current working directory.
func (a *AbsAdapter) Getwd() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cwd, nil
}

// TempDir returns the default directory for temporary files.
func (a *AbsAdapter) TempDir() string {
	return os.TempDir()
}

// Open opens the named file for reading.
func (a *AbsAdapter) Open(name string) (absfs.File, error) {
	return a.OpenFile(name, os.O_RDONLY, 0)
}

// Create creates or truncates the named file.
func (a *AbsAdapter) Create(name string) (absfs.File, error) {
	return a.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

// MkdirAll creates a directory and all parent directories.
func (a *AbsAdapter) MkdirAll(name string, perm os.FileMode) error {
	path := a.resolvePath(name)
	return a.pfs.MkdirAll(a.getContext(), path, perm)
}

// RemoveAll removes path and any children it contains.
func (a *AbsAdapter) RemoveAll(path string) error {
	resolvedPath := a.resolvePath(path)
	return a.pfs.RemoveAll(a.getContext(), resolvedPath)
}

// Truncate changes the size of the named file.
func (a *AbsAdapter) Truncate(name string, size int64) error {
	path := a.resolvePath(name)
	// Open the file for writing
	f, err := a.pfs.OpenFile(a.getContext(), path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

// --- absfs.SymLinker interface ---

// Lstat returns file info without following symlinks.
func (a *AbsAdapter) Lstat(name string) (os.FileInfo, error) {
	path := a.resolvePath(name)
	return a.pfs.Lstat(a.getContext(), path)
}

// Lchown changes the numeric uid and gid of the named file without following symlinks.
// Note: This delegates to Chown as the underlying filesystem may not support Lchown.
func (a *AbsAdapter) Lchown(name string, uid, gid int) error {
	// The underlying PermFS doesn't have Lchown, so we use Chown
	// This may follow symlinks on some platforms
	return a.Chown(name, uid, gid)
}

// Readlink returns the destination of the named symbolic link.
func (a *AbsAdapter) Readlink(name string) (string, error) {
	// The underlying PermFS doesn't have Readlink
	// This would need to be implemented by the base filesystem
	return "", &os.PathError{Op: "readlink", Path: name, Err: absfs.ErrNotImplemented}
}

// Symlink creates newname as a symbolic link to oldname.
func (a *AbsAdapter) Symlink(oldname, newname string) error {
	// The underlying PermFS doesn't have Symlink
	// This would need to be implemented by the base filesystem
	return &os.LinkError{Op: "symlink", Old: oldname, New: newname, Err: absfs.ErrNotImplemented}
}

// ReadDir reads the named directory and returns directory entries.
func (a *AbsAdapter) ReadDir(name string) ([]fs.DirEntry, error) {
	path := a.resolvePath(name)
	ctx := a.getContext()

	// Call the context-based ReadDir that returns []os.FileInfo
	infos, err := a.pfs.ReadDir(ctx, path)
	if err != nil {
		return nil, err
	}

	// Convert []os.FileInfo to []fs.DirEntry
	entries := make([]fs.DirEntry, len(infos))
	for i, info := range infos {
		entries[i] = fileInfoDirEntry{info}
	}
	return entries, nil
}

// ReadFile reads the named file and returns its contents.
func (a *AbsAdapter) ReadFile(name string) ([]byte, error) {
	path := a.resolvePath(name)
	ctx := a.getContext()

	// Open file for reading
	f, err := a.pfs.OpenFile(ctx, path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read entire file
	return io.ReadAll(f)
}

// Sub returns a filesystem rooted at dir.
func (a *AbsAdapter) Sub(dir string) (fs.FS, error) {
	path := a.resolvePath(dir)
	ctx := a.getContext()

	// Verify dir exists and is a directory
	info, err := a.pfs.Stat(ctx, path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &os.PathError{Op: "sub", Path: dir, Err: os.ErrInvalid}
	}

	// Return a new adapter with adjusted root
	subAdapter := &subAdapter{
		parent: a,
		root:   filepath.Clean(path),
	}
	return absfs.FilerToFS(subAdapter, path)
}

// subAdapter implements a sub-filesystem adapter
type subAdapter struct {
	parent *AbsAdapter
	root   string
}

func (sa *subAdapter) resolvePath(name string) string {
	return filepath.Join(sa.root, name)
}

func (sa *subAdapter) OpenFile(name string, flag int, perm os.FileMode) (absfs.File, error) {
	ctx := sa.parent.getContext()
	f, err := sa.parent.pfs.OpenFile(ctx, sa.resolvePath(name), flag, perm)
	if err != nil {
		return nil, err
	}
	return &absFile{f}, nil
}

func (sa *subAdapter) Mkdir(name string, perm os.FileMode) error {
	ctx := sa.parent.getContext()
	return sa.parent.pfs.Mkdir(ctx, sa.resolvePath(name), perm)
}

func (sa *subAdapter) Remove(name string) error {
	ctx := sa.parent.getContext()
	return sa.parent.pfs.Remove(ctx, sa.resolvePath(name))
}

func (sa *subAdapter) Rename(oldname, newname string) error {
	ctx := sa.parent.getContext()
	return sa.parent.pfs.Rename(ctx, sa.resolvePath(oldname), sa.resolvePath(newname))
}

func (sa *subAdapter) Stat(name string) (os.FileInfo, error) {
	ctx := sa.parent.getContext()
	return sa.parent.pfs.Stat(ctx, sa.resolvePath(name))
}

func (sa *subAdapter) Chmod(name string, mode os.FileMode) error {
	ctx := sa.parent.getContext()
	return sa.parent.pfs.Chmod(ctx, sa.resolvePath(name), mode)
}

func (sa *subAdapter) Chown(name string, uid, gid int) error {
	ctx := sa.parent.getContext()
	return sa.parent.pfs.Chown(ctx, sa.resolvePath(name), uid, gid)
}

func (sa *subAdapter) Chtimes(name string, atime, mtime time.Time) error {
	ctx := sa.parent.getContext()
	return sa.parent.pfs.Chtimes(ctx, sa.resolvePath(name), atime, mtime)
}

func (sa *subAdapter) ReadDir(name string) ([]fs.DirEntry, error) {
	ctx := sa.parent.getContext()
	infos, err := sa.parent.pfs.ReadDir(ctx, sa.resolvePath(name))
	if err != nil {
		return nil, err
	}
	entries := make([]fs.DirEntry, len(infos))
	for i, info := range infos {
		entries[i] = fileInfoDirEntry{info}
	}
	return entries, nil
}

func (sa *subAdapter) ReadFile(name string) ([]byte, error) {
	ctx := sa.parent.getContext()
	f, err := sa.parent.pfs.OpenFile(ctx, sa.resolvePath(name), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (sa *subAdapter) Sub(dir string) (fs.FS, error) {
	path := sa.resolvePath(dir)
	ctx := sa.parent.getContext()

	// Verify dir exists and is a directory
	info, err := sa.parent.pfs.Stat(ctx, path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &os.PathError{Op: "sub", Path: dir, Err: os.ErrInvalid}
	}

	// Return a new sub-adapter with the new root
	subSubAdapter := &subAdapter{
		parent: sa.parent,
		root:   filepath.Clean(path),
	}
	return absfs.FilerToFS(subSubAdapter, path)
}

// --- absFile wrapper ---

// absFile wraps a permfs.File to implement absfs.File interface.
type absFile struct {
	f File
}

func (af *absFile) Name() string {
	if namer, ok := af.f.(interface{ Name() string }); ok {
		return namer.Name()
	}
	return ""
}

func (af *absFile) Read(p []byte) (n int, err error) {
	return af.f.Read(p)
}

func (af *absFile) Write(p []byte) (n int, err error) {
	return af.f.Write(p)
}

func (af *absFile) Close() error {
	return af.f.Close()
}

func (af *absFile) Sync() error {
	return af.f.Sync()
}

func (af *absFile) Stat() (os.FileInfo, error) {
	return af.f.Stat()
}

func (af *absFile) Readdir(n int) ([]os.FileInfo, error) {
	if reader, ok := af.f.(interface{ Readdir(int) ([]os.FileInfo, error) }); ok {
		return reader.Readdir(n)
	}
	return nil, absfs.ErrNotImplemented
}

func (af *absFile) Seek(offset int64, whence int) (int64, error) {
	return af.f.Seek(offset, whence)
}

func (af *absFile) ReadAt(p []byte, off int64) (n int, err error) {
	return af.f.ReadAt(p, off)
}

func (af *absFile) WriteAt(p []byte, off int64) (n int, err error) {
	return af.f.WriteAt(p, off)
}

func (af *absFile) WriteString(s string) (n int, err error) {
	return af.f.Write([]byte(s))
}

func (af *absFile) Truncate(size int64) error {
	return af.f.Truncate(size)
}

func (af *absFile) Readdirnames(n int) ([]string, error) {
	if reader, ok := af.f.(interface{ Readdirnames(int) ([]string, error) }); ok {
		return reader.Readdirnames(n)
	}
	// Fall back to using Readdir if Readdirnames is not available
	infos, err := af.Readdir(n)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(infos))
	for i, info := range infos {
		names[i] = info.Name()
	}
	return names, nil
}

func (af *absFile) ReadDir(n int) ([]fs.DirEntry, error) {
	// First try direct ReadDir implementation
	if reader, ok := af.f.(interface{ ReadDir(int) ([]fs.DirEntry, error) }); ok {
		return reader.ReadDir(n)
	}

	// Fall back to using Readdir
	infos, err := af.Readdir(n)
	if err != nil {
		return nil, err
	}

	entries := make([]fs.DirEntry, len(infos))
	for i, info := range infos {
		entries[i] = fileInfoDirEntry{info}
	}
	return entries, nil
}
