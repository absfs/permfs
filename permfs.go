package permfs

import (
	"context"
	"io/fs"
	"os"
	"time"
)

// FileSystem is the interface that permfs wraps
// This matches the absfs.FileSystem interface
type FileSystem interface {
	// OpenFile opens a file with the specified flag and perm
	OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (File, error)

	// Mkdir creates a directory
	Mkdir(ctx context.Context, name string, perm os.FileMode) error

	// MkdirAll creates a directory and all parent directories
	MkdirAll(ctx context.Context, name string, perm os.FileMode) error

	// Remove removes a file or directory
	Remove(ctx context.Context, name string) error

	// RemoveAll removes a path and any children it contains
	RemoveAll(ctx context.Context, name string) error

	// Rename renames (moves) a file
	Rename(ctx context.Context, oldname, newname string) error

	// Stat returns file info
	Stat(ctx context.Context, name string) (os.FileInfo, error)

	// Lstat returns file info without following symlinks
	Lstat(ctx context.Context, name string) (os.FileInfo, error)

	// ReadDir reads the directory and returns file info
	ReadDir(ctx context.Context, name string) ([]os.FileInfo, error)

	// Chmod changes the mode of the file
	Chmod(ctx context.Context, name string, mode os.FileMode) error

	// Chown changes the owner and group of the file
	Chown(ctx context.Context, name string, uid, gid int) error

	// Chtimes changes the access and modification times
	Chtimes(ctx context.Context, name string, atime, mtime time.Time) error
}

// File is the interface for file operations
type File interface {
	fs.File
	// Write writes data to the file
	Write(p []byte) (n int, err error)
	// WriteAt writes data at the specified offset
	WriteAt(p []byte, off int64) (n int, err error)
	// Read reads data from the file
	Read(p []byte) (n int, err error)
	// ReadAt reads data from the specified offset
	ReadAt(p []byte, off int64) (n int, err error)
	// Seek sets the offset for the next Read or Write
	Seek(offset int64, whence int) (int64, error)
	// Sync commits the current contents of the file
	Sync() error
	// Truncate changes the size of the file
	Truncate(size int64) error
}

// PermFS wraps a FileSystem with permission checking
type PermFS struct {
	base        FileSystem
	evaluator   *Evaluator
	config      Config
	auditLogger *AuditLogger
}

// New creates a new permission filesystem
func New(base FileSystem, config Config) (*PermFS, error) {
	if base == nil {
		return nil, ErrInvalidConfig
	}

	// Set default cache configuration if not specified
	if config.Performance.CacheEnabled {
		if config.Performance.CacheTTL == 0 {
			config.Performance.CacheTTL = 5 * time.Minute
		}
		if config.Performance.CacheMaxSize == 0 {
			config.Performance.CacheMaxSize = 10000
		}
	}

	// Create evaluator with or without cache
	var evaluator *Evaluator
	if config.Performance.CacheEnabled {
		permCache := NewPermissionCache(
			config.Performance.CacheMaxSize,
			config.Performance.CacheTTL,
		)
		var patternCache *PatternCache
		if config.Performance.PatternCacheEnabled {
			patternCache = NewPatternCache()
		}
		evaluator = NewEvaluatorWithCache(config.ACL, permCache, patternCache)
	} else {
		evaluator = NewEvaluator(config.ACL)
	}

	// Create audit logger
	auditLogger := NewAuditLogger(config.Audit)

	return &PermFS{
		base:        base,
		evaluator:   evaluator,
		config:      config,
		auditLogger: auditLogger,
	}, nil
}

// checkPermission checks if the operation is allowed
func (pfs *PermFS) checkPermission(ctx context.Context, path string, op Operation) error {
	startTime := time.Now()

	identity, err := GetIdentity(ctx)
	if err != nil {
		return err
	}

	evalCtx := &EvaluationContext{
		Identity:  identity,
		Path:      path,
		Operation: op,
		Metadata:  GetMetadata(ctx),
	}

	allowed, err := pfs.evaluator.Evaluate(evalCtx)
	duration := time.Since(startTime)

	// Log audit event
	if pfs.auditLogger != nil {
		event := &AuditEvent{
			Timestamp:  startTime,
			RequestID:  GetRequestID(ctx),
			UserID:     identity.UserID,
			Groups:     identity.Groups,
			Roles:      identity.Roles,
			Operation:  op.String(),
			Path:       path,
			Duration:   duration,
			Metadata:   evalCtx.Metadata,
		}

		if sourceIP, ok := evalCtx.Metadata["source_ip"].(string); ok {
			event.SourceIP = sourceIP
		}

		if err != nil {
			event.Result = AuditResultError
			event.Reason = err.Error()
		} else if allowed {
			event.Result = AuditResultAllowed
		} else {
			event.Result = AuditResultDenied
			event.Reason = "access denied by ACL"
		}

		pfs.auditLogger.Log(event)
	}

	if err != nil {
		return err
	}

	if !allowed {
		return NewPermissionError(path, op, identity.UserID, "access denied by ACL")
	}

	return nil
}

// OpenFile opens a file with permission checking
func (pfs *PermFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (File, error) {
	// Determine the required operation based on flags
	var requiredOp Operation

	// Check if write access is requested
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		requiredOp |= OperationWrite
	}

	// Check if read access is requested (default or explicit)
	if flag&os.O_WRONLY == 0 {
		requiredOp |= OperationRead
	}

	// If creating a new file, we need write permission
	if flag&os.O_CREATE != 0 {
		requiredOp |= OperationWrite
	}

	// Check permission
	if err := pfs.checkPermission(ctx, name, requiredOp); err != nil {
		return nil, err
	}

	// Delegate to underlying filesystem
	return pfs.base.OpenFile(ctx, name, flag, perm)
}

// Mkdir creates a directory with permission checking
func (pfs *PermFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if err := pfs.checkPermission(ctx, name, OperationWrite); err != nil {
		return err
	}
	return pfs.base.Mkdir(ctx, name, perm)
}

// MkdirAll creates a directory and all parents with permission checking
func (pfs *PermFS) MkdirAll(ctx context.Context, name string, perm os.FileMode) error {
	if err := pfs.checkPermission(ctx, name, OperationWrite); err != nil {
		return err
	}
	return pfs.base.MkdirAll(ctx, name, perm)
}

// Remove removes a file or directory with permission checking
func (pfs *PermFS) Remove(ctx context.Context, name string) error {
	if err := pfs.checkPermission(ctx, name, OperationDelete); err != nil {
		return err
	}
	return pfs.base.Remove(ctx, name)
}

// RemoveAll removes a path recursively with permission checking
func (pfs *PermFS) RemoveAll(ctx context.Context, name string) error {
	if err := pfs.checkPermission(ctx, name, OperationDelete); err != nil {
		return err
	}
	return pfs.base.RemoveAll(ctx, name)
}

// Rename renames a file with permission checking
func (pfs *PermFS) Rename(ctx context.Context, oldname, newname string) error {
	// Need delete permission on old path and write permission on new path
	if err := pfs.checkPermission(ctx, oldname, OperationDelete); err != nil {
		return err
	}
	if err := pfs.checkPermission(ctx, newname, OperationWrite); err != nil {
		return err
	}
	return pfs.base.Rename(ctx, oldname, newname)
}

// Stat returns file info with permission checking
func (pfs *PermFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if err := pfs.checkPermission(ctx, name, OperationMetadata); err != nil {
		return nil, err
	}
	return pfs.base.Stat(ctx, name)
}

// Lstat returns file info without following symlinks, with permission checking
func (pfs *PermFS) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	if err := pfs.checkPermission(ctx, name, OperationMetadata); err != nil {
		return nil, err
	}
	return pfs.base.Lstat(ctx, name)
}

// ReadDir reads a directory with permission checking (context-based, returns []os.FileInfo)
// This method implements the internal FileSystem interface
func (pfs *PermFS) ReadDir(ctx context.Context, name string) ([]os.FileInfo, error) {
	if err := pfs.checkPermission(ctx, name, OperationRead); err != nil {
		return nil, err
	}
	return pfs.base.ReadDir(ctx, name)
}

// Chmod changes file mode with permission checking
func (pfs *PermFS) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	if err := pfs.checkPermission(ctx, name, OperationMetadata); err != nil {
		return err
	}
	return pfs.base.Chmod(ctx, name, mode)
}

// Chown changes file ownership with permission checking
func (pfs *PermFS) Chown(ctx context.Context, name string, uid, gid int) error {
	if err := pfs.checkPermission(ctx, name, OperationAdmin); err != nil {
		return err
	}
	return pfs.base.Chown(ctx, name, uid, gid)
}

// Chtimes changes file access and modification times with permission checking
func (pfs *PermFS) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	if err := pfs.checkPermission(ctx, name, OperationMetadata); err != nil {
		return err
	}
	return pfs.base.Chtimes(ctx, name, atime, mtime)
}

// GetPermissions returns the effective permissions for a path and identity
func (pfs *PermFS) GetPermissions(ctx context.Context, path string) (Operation, error) {
	identity, err := GetIdentity(ctx)
	if err != nil {
		return 0, err
	}
	return pfs.evaluator.GetEffectivePermissions(identity, path), nil
}

// GetEffectiveRules returns all ACL entries that apply to a path
func (pfs *PermFS) GetEffectiveRules(path string) []ACLEntry {
	var effective []ACLEntry
	for _, entry := range pfs.evaluator.acl.Entries {
		matched, _ := matchPattern(entry.PathPattern, path)
		if matched {
			effective = append(effective, entry)
		}
	}
	return effective
}

// AddRule adds a new ACL entry (for dynamic rule management)
func (pfs *PermFS) AddRule(entry ACLEntry) error {
	pfs.evaluator.acl.Entries = append(pfs.evaluator.acl.Entries, entry)
	// Invalidate cache since rules have changed
	pfs.ClearCache()
	return nil
}

// RemoveRule removes an ACL entry by matching all fields
func (pfs *PermFS) RemoveRule(entry ACLEntry) error {
	var newEntries []ACLEntry
	for _, e := range pfs.evaluator.acl.Entries {
		if e.Subject != entry.Subject || e.PathPattern != entry.PathPattern ||
			e.Permissions != entry.Permissions || e.Effect != entry.Effect {
			newEntries = append(newEntries, e)
		}
	}
	pfs.evaluator.acl.Entries = newEntries
	// Invalidate cache since rules have changed
	pfs.ClearCache()
	return nil
}

// ClearCache clears the permission cache
func (pfs *PermFS) ClearCache() {
	pfs.evaluator.ClearCache()
}

// InvalidateCache invalidates cache entries for a user and/or path prefix
func (pfs *PermFS) InvalidateCache(userID string, pathPrefix string) {
	pfs.evaluator.InvalidateCache(userID, pathPrefix)
}

// GetCacheStats returns cache statistics
func (pfs *PermFS) GetCacheStats() *CacheStats {
	return pfs.evaluator.GetCacheStats()
}

// GetAuditStats returns audit statistics
func (pfs *PermFS) GetAuditStats() AuditStats {
	if pfs.auditLogger != nil {
		return pfs.auditLogger.GetMetrics().GetStats()
	}
	return AuditStats{}
}

// GetAuditMetrics returns the audit metrics object
func (pfs *PermFS) GetAuditMetrics() *AuditMetrics {
	if pfs.auditLogger != nil {
		return pfs.auditLogger.GetMetrics()
	}
	return nil
}

// Close closes the permission filesystem and shuts down background tasks
func (pfs *PermFS) Close() error {
	if pfs.auditLogger != nil {
		return pfs.auditLogger.Close()
	}
	return nil
}

// fileInfoDirEntry wraps os.FileInfo to implement fs.DirEntry
type fileInfoDirEntry struct {
	info os.FileInfo
}

func (d fileInfoDirEntry) Name() string {
	return d.info.Name()
}

func (d fileInfoDirEntry) IsDir() bool {
	return d.info.IsDir()
}

func (d fileInfoDirEntry) Type() fs.FileMode {
	return d.info.Mode().Type()
}

func (d fileInfoDirEntry) Info() (fs.FileInfo, error) {
	return d.info, nil
}
