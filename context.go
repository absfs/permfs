package permfs

import (
	"context"
)

// contextKey is a private type for context keys to avoid collisions
type contextKey int

const (
	identityKey contextKey = iota
	tokenKey
	metadataKey
)

// WithIdentity returns a new context with the given identity
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

// WithUser returns a new context with a simple user identity
func WithUser(ctx context.Context, userID string) context.Context {
	identity := &Identity{
		UserID: userID,
	}
	return context.WithValue(ctx, identityKey, identity)
}

// WithUserAndGroups returns a new context with a user identity including groups
func WithUserAndGroups(ctx context.Context, userID string, groups []string) context.Context {
	identity := &Identity{
		UserID: userID,
		Groups: groups,
	}
	return context.WithValue(ctx, identityKey, identity)
}

// WithUserGroupsAndRoles returns a new context with a complete user identity
func WithUserGroupsAndRoles(ctx context.Context, userID string, groups, roles []string) context.Context {
	identity := &Identity{
		UserID: userID,
		Groups: groups,
		Roles:  roles,
	}
	return context.WithValue(ctx, identityKey, identity)
}

// GetIdentity extracts the identity from the context
func GetIdentity(ctx context.Context) (*Identity, error) {
	identity, ok := ctx.Value(identityKey).(*Identity)
	if !ok || identity == nil {
		return nil, ErrNoIdentity
	}
	return identity, nil
}

// WithToken returns a new context with an authentication token
// The token can be used by authenticators to extract identity
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

// GetToken extracts the authentication token from the context
func GetToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(tokenKey).(string)
	return token, ok
}

// WithMetadata returns a new context with additional metadata
func WithMetadata(ctx context.Context, metadata map[string]interface{}) context.Context {
	return context.WithValue(ctx, metadataKey, metadata)
}

// GetMetadata extracts metadata from the context
func GetMetadata(ctx context.Context) map[string]interface{} {
	metadata, ok := ctx.Value(metadataKey).(map[string]interface{})
	if !ok {
		return make(map[string]interface{})
	}
	return metadata
}

// AddMetadata adds a key-value pair to the context metadata
func AddMetadata(ctx context.Context, key string, value interface{}) context.Context {
	metadata := GetMetadata(ctx)
	// Create a new map to avoid modifying the original
	newMetadata := make(map[string]interface{}, len(metadata)+1)
	for k, v := range metadata {
		newMetadata[k] = v
	}
	newMetadata[key] = value
	return context.WithValue(ctx, metadataKey, newMetadata)
}
