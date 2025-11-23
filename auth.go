package permfs

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Authenticator is an interface for extracting identity from a context or token
type Authenticator interface {
	// Authenticate extracts and validates identity from the context
	Authenticate(ctx context.Context) (*Identity, error)
}

// TokenAuthenticator extracts identity from a token string
type TokenAuthenticator interface {
	// AuthenticateToken validates a token and returns the identity
	AuthenticateToken(token string) (*Identity, error)
}

// StaticAuthenticator provides a simple static user mapping
type StaticAuthenticator struct {
	users map[string]*Identity
}

// NewStaticAuthenticator creates a new static authenticator
func NewStaticAuthenticator() *StaticAuthenticator {
	return &StaticAuthenticator{
		users: make(map[string]*Identity),
	}
}

// AddUser adds a user to the static authenticator
func (sa *StaticAuthenticator) AddUser(userID string, groups, roles []string) {
	sa.users[userID] = &Identity{
		UserID: userID,
		Groups: groups,
		Roles:  roles,
	}
}

// Authenticate extracts identity from context
func (sa *StaticAuthenticator) Authenticate(ctx context.Context) (*Identity, error) {
	// Try to get identity directly from context
	if identity, err := GetIdentity(ctx); err == nil {
		return identity, nil
	}

	// Try to get from token
	if token, ok := GetToken(ctx); ok {
		return sa.AuthenticateToken(token)
	}

	return nil, ErrNoIdentity
}

// AuthenticateToken authenticates a token (simple user ID lookup)
func (sa *StaticAuthenticator) AuthenticateToken(token string) (*Identity, error) {
	identity, ok := sa.users[token]
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}
	return identity, nil
}

// APIKeyAuthenticator authenticates using API keys
type APIKeyAuthenticator struct {
	keys map[string]*Identity
}

// NewAPIKeyAuthenticator creates a new API key authenticator
func NewAPIKeyAuthenticator() *APIKeyAuthenticator {
	return &APIKeyAuthenticator{
		keys: make(map[string]*Identity),
	}
}

// AddAPIKey adds an API key
func (aka *APIKeyAuthenticator) AddAPIKey(apiKey string, identity *Identity) {
	aka.keys[apiKey] = identity
}

// Authenticate extracts identity from context using API key
func (aka *APIKeyAuthenticator) Authenticate(ctx context.Context) (*Identity, error) {
	// Try to get from metadata
	metadata := GetMetadata(ctx)
	if apiKey, ok := metadata["api_key"].(string); ok {
		return aka.AuthenticateToken(apiKey)
	}

	// Try to get from token
	if token, ok := GetToken(ctx); ok {
		return aka.AuthenticateToken(token)
	}

	return nil, ErrNoIdentity
}

// AuthenticateToken validates an API key
func (aka *APIKeyAuthenticator) AuthenticateToken(apiKey string) (*Identity, error) {
	identity, ok := aka.keys[apiKey]
	if !ok {
		return nil, fmt.Errorf("invalid API key")
	}
	return identity, nil
}

// ChainAuthenticator tries multiple authenticators in order
type ChainAuthenticator struct {
	authenticators []Authenticator
}

// NewChainAuthenticator creates a new chain authenticator
func NewChainAuthenticator(authenticators ...Authenticator) *ChainAuthenticator {
	return &ChainAuthenticator{
		authenticators: authenticators,
	}
}

// Authenticate tries each authenticator in order
func (ca *ChainAuthenticator) Authenticate(ctx context.Context) (*Identity, error) {
	var lastErr error
	for _, auth := range ca.authenticators {
		identity, err := auth.Authenticate(ctx)
		if err == nil {
			return identity, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoIdentity
}

// FuncAuthenticator wraps a function as an Authenticator
type FuncAuthenticator func(ctx context.Context) (*Identity, error)

// Authenticate calls the wrapped function
func (fa FuncAuthenticator) Authenticate(ctx context.Context) (*Identity, error) {
	return fa(ctx)
}

// HeaderAuthenticator extracts identity from HTTP-style headers in metadata
type HeaderAuthenticator struct {
	userHeader   string
	groupsHeader string
	rolesHeader  string
	separator    string
}

// NewHeaderAuthenticator creates a new header authenticator
func NewHeaderAuthenticator(userHeader, groupsHeader, rolesHeader string) *HeaderAuthenticator {
	return &HeaderAuthenticator{
		userHeader:   userHeader,
		groupsHeader: groupsHeader,
		rolesHeader:  rolesHeader,
		separator:    ",",
	}
}

// Authenticate extracts identity from headers in metadata
func (ha *HeaderAuthenticator) Authenticate(ctx context.Context) (*Identity, error) {
	metadata := GetMetadata(ctx)

	userID, ok := metadata[ha.userHeader].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("user header %s not found", ha.userHeader)
	}

	identity := &Identity{
		UserID:   userID,
		Metadata: make(map[string]string),
	}

	// Extract groups
	if groupsStr, ok := metadata[ha.groupsHeader].(string); ok && groupsStr != "" {
		identity.Groups = strings.Split(groupsStr, ha.separator)
	}

	// Extract roles
	if rolesStr, ok := metadata[ha.rolesHeader].(string); ok && rolesStr != "" {
		identity.Roles = strings.Split(rolesStr, ha.separator)
	}

	return identity, nil
}

// NewPermFSWithAuthenticator creates a new PermFS with an authenticator
func NewPermFSWithAuthenticator(base FileSystem, config Config, auth Authenticator) (*PermFS, error) {
	pfs, err := New(base, config)
	if err != nil {
		return nil, err
	}

	// Wrap the filesystem with authentication
	return &PermFS{
		base:        &authFS{base: pfs, auth: auth},
		evaluator:   pfs.evaluator,
		config:      pfs.config,
		auditLogger: pfs.auditLogger,
	}, nil
}

// authFS wraps a filesystem with authentication
type authFS struct {
	base FileSystem
	auth Authenticator
}

func (afs *authFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (File, error) {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return afs.base.OpenFile(ctx, name, flag, perm)
}

func (afs *authFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.Mkdir(ctx, name, perm)
}

func (afs *authFS) MkdirAll(ctx context.Context, name string, perm os.FileMode) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.MkdirAll(ctx, name, perm)
}

func (afs *authFS) Remove(ctx context.Context, name string) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.Remove(ctx, name)
}

func (afs *authFS) RemoveAll(ctx context.Context, name string) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.RemoveAll(ctx, name)
}

func (afs *authFS) Rename(ctx context.Context, oldname, newname string) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.Rename(ctx, oldname, newname)
}

func (afs *authFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return afs.base.Stat(ctx, name)
}

func (afs *authFS) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return afs.base.Lstat(ctx, name)
}

func (afs *authFS) ReadDir(ctx context.Context, name string) ([]os.FileInfo, error) {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return afs.base.ReadDir(ctx, name)
}

func (afs *authFS) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.Chmod(ctx, name, mode)
}

func (afs *authFS) Chown(ctx context.Context, name string, uid, gid int) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.Chown(ctx, name, uid, gid)
}

func (afs *authFS) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	ctx, err := afs.authenticate(ctx)
	if err != nil {
		return err
	}
	return afs.base.Chtimes(ctx, name, atime, mtime)
}

func (afs *authFS) authenticate(ctx context.Context) (context.Context, error) {
	// Check if identity is already in context
	if _, err := GetIdentity(ctx); err == nil {
		return ctx, nil
	}

	// Authenticate and add identity to context
	identity, err := afs.auth.Authenticate(ctx)
	if err != nil {
		return ctx, err
	}

	return WithIdentity(ctx, identity), nil
}
