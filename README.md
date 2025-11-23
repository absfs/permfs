# permfs

Fine-grained access control and permission enforcement for the AbsFS filesystem abstraction layer.

## Overview

`permfs` provides a powerful permission layer for filesystem operations, enabling fine-grained access control with support for path-based rules, Access Control Lists (ACLs), and comprehensive audit logging. It wraps any `absfs.FileSystem` implementation and enforces security policies before delegating operations to the underlying filesystem.

Key features:
- **Path-based permission rules** with wildcard support
- **Access Control Lists (ACLs)** with user/group/role permissions
- **Operation-level control** (read, write, execute, delete, metadata)
- **Audit logging** for compliance and security monitoring
- **Multi-tenant support** with isolated permission contexts
- **Integration with authentication systems** (OAuth, JWT, custom)
- **Performance-optimized** with rule caching and lazy evaluation

## Permission Model

### Permission Levels

`permfs` operates on a hierarchical permission model:

1. **Operation Types**
   - `Read`: Open files for reading, list directories
   - `Write`: Create, modify, or append to files
   - `Execute`: Execute files (relevant for executable files)
   - `Delete`: Remove files or directories
   - `Metadata`: Read/modify file attributes, permissions, timestamps
   - `Admin`: Full control including permission changes

2. **Access Control Entries (ACEs)**
   - **Subject**: User ID, Group ID, Role, or wildcard
   - **Resource**: Path pattern (supports wildcards: `*`, `**`, `?`)
   - **Permission**: Allow or Deny
   - **Operations**: Bitmap of allowed operations
   - **Priority**: For conflict resolution (higher priority wins)

3. **Evaluation Order**
   1. Explicit deny rules (highest priority)
   2. Explicit allow rules
   3. Inherited permissions from parent paths
   4. Default deny (secure by default)

### ACL Structure

```go
type ACL struct {
    Entries []ACLEntry
    Default Permission // Applied when no rules match
}

type ACLEntry struct {
    Subject     Subject         // Who
    PathPattern string          // What (supports glob patterns)
    Permissions OperationSet    // Which operations
    Effect      Effect          // Allow or Deny
    Priority    int             // Conflict resolution
    Conditions  []Condition     // Optional conditions (time, IP, etc.)
}

type Subject struct {
    Type SubjectType // User, Group, Role, Everyone
    ID   string
}

type OperationSet uint32 // Bitmask of operations
```

### Path Pattern Matching

- `/data/user123/**` - All files under user123 directory
- `/public/*.txt` - All .txt files in public directory
- `/temp/**/*.log` - All log files anywhere under temp
- `/home/*/documents/**` - Documents for any user

## Implementation Phases

### Phase 1: Core Permission Engine

**Foundation**
- ACL data structures and parsing
- Path pattern matcher with wildcard support
- Permission evaluation engine
- Context propagation (user identity, request metadata)

**Basic Operations**
- File operation interceptors (Open, Create, Remove, etc.)
- Permission checks before delegation
- Error handling and reporting

**Testing**
- Unit tests for rule evaluation
- Pattern matching test suite
- Permission conflict resolution tests

### Phase 2: Advanced ACL Features

**Enhancements**
- Group and role-based permissions
- Permission inheritance and override
- Time-based access (temporal conditions)
- IP/network-based restrictions
- Custom condition evaluators

**Caching**
- Rule evaluation result cache
- Path pattern compilation cache
- LRU cache with TTL support

### Phase 3: Audit and Monitoring

**Audit Logging**
- Structured audit logs (JSON, syslog)
- Configurable verbosity levels
- Log rotation and retention
- Async logging for performance

**Events**
- Access granted/denied events
- Policy violations
- Administrative actions
- Real-time event streaming

**Metrics**
- Permission check latency
- Cache hit rates
- Access patterns and hotspots
- Security metrics (failed access attempts)

### Phase 4: Integration and Management

**Authentication Integration**
- JWT token validation
- OAuth/OIDC integration
- API key authentication
- Custom authenticator interface

**Management API**
- Dynamic rule updates (no restart required)
- Rule validation and testing
- Permission queries ("what can user X do?")
- Bulk operations for rule management

**Policy Import/Export**
- JSON/YAML policy files
- Version control friendly formats
- Policy migration tools
- Template-based policies

### Phase 5: Advanced Features

**Multi-tenancy**
- Isolated permission contexts per tenant
- Tenant-level policy inheritance
- Cross-tenant resource sharing
- Quota and rate limiting integration

**Delegation**
- Temporary permission grants
- Delegated administration
- Service account permissions
- Impersonation controls

**Compliance**
- Read-only mode enforcement
- Immutability guarantees
- Retention policies
- Compliance reporting

## API Design

### Basic Usage

```go
package main

import (
    "github.com/absfs/absfs"
    "github.com/absfs/permfs"
    "github.com/absfs/osfs"
)

func main() {
    // Wrap any filesystem
    base := osfs.New("/data")

    // Create permission layer
    fs, err := permfs.New(base, permfs.Config{
        ACL: permfs.ACL{
            Entries: []permfs.ACLEntry{
                {
                    Subject:     permfs.User("alice"),
                    PathPattern: "/home/alice/**",
                    Permissions: permfs.ReadWrite,
                    Effect:      permfs.Allow,
                },
                {
                    Subject:     permfs.Group("admins"),
                    PathPattern: "/**",
                    Permissions: permfs.All,
                    Effect:      permfs.Allow,
                },
            },
            Default: permfs.Deny,
        },
    })

    // Use with context containing user identity
    ctx := permfs.WithUser(context.Background(), "alice")

    // Operations are automatically checked
    f, err := fs.OpenFile(ctx, "/home/alice/file.txt", os.O_RDWR, 0644)
    if err != nil {
        // Will fail if alice doesn't have permission
        log.Fatal(err)
    }
    defer f.Close()
}
```

### Dynamic Rule Management

```go
// Add rule at runtime
err := fs.AddRule(permfs.ACLEntry{
    Subject:     permfs.User("bob"),
    PathPattern: "/shared/**",
    Permissions: permfs.Read,
    Effect:      permfs.Allow,
    Priority:    100,
})

// Remove rule
fs.RemoveRule(ruleID)

// Query permissions
perms, err := fs.GetPermissions(ctx, "/shared/file.txt", "bob")
if perms.CanRead() {
    // Bob can read this file
}

// List effective rules for a path
rules := fs.GetEffectiveRules("/shared/data.json")
```

### Audit Configuration

```go
fs, err := permfs.New(base, permfs.Config{
    Audit: permfs.AuditConfig{
        Enabled: true,
        Writer:  os.Stdout, // Or custom writer
        Format:  permfs.JSON,
        Level:   permfs.AuditAll, // Log all access attempts
        Fields: []string{
            "timestamp", "user", "operation",
            "path", "result", "duration",
        },
    },
})

// Audit log example:
// {"timestamp":"2024-01-15T10:30:00Z","user":"alice","operation":"Open",
//  "path":"/data/secret.txt","result":"denied","reason":"insufficient_permissions"}
```

### Rule Engine API

```go
// Create custom condition
fs.RegisterCondition("business_hours", func(ctx context.Context) bool {
    hour := time.Now().Hour()
    return hour >= 9 && hour <= 17
})

// Use in ACL
acl := permfs.ACL{
    Entries: []permfs.ACLEntry{
        {
            Subject:     permfs.User("contractor"),
            PathPattern: "/company/**",
            Permissions: permfs.Read,
            Effect:      permfs.Allow,
            Conditions: []permfs.Condition{
                permfs.TimeCondition("business_hours"),
            },
        },
    },
}
```

## Usage Examples

### Multi-tenant Application

```go
type TenantFS struct {
    perms map[string]*permfs.FileSystem
}

func (t *TenantFS) GetFS(tenantID string) (absfs.FileSystem, error) {
    if fs, ok := t.perms[tenantID]; ok {
        return fs, nil
    }

    // Create tenant-specific permissions
    acl := permfs.ACL{
        Entries: []permfs.ACLEntry{
            {
                Subject:     permfs.Group(tenantID + ":users"),
                PathPattern: fmt.Sprintf("/tenants/%s/**", tenantID),
                Permissions: permfs.ReadWrite,
                Effect:      permfs.Allow,
            },
            {
                Subject:     permfs.Everyone(),
                PathPattern: fmt.Sprintf("/tenants/%s/**", tenantID),
                Permissions: permfs.All,
                Effect:      permfs.Deny,
            },
        },
    }

    fs, err := permfs.New(t.baseFS, permfs.Config{ACL: acl})
    t.perms[tenantID] = fs
    return fs, err
}
```

### Shared File System with Groups

```go
// Engineering team can read/write to /projects
// Managers can read everything
// Interns can only read /public
acl := permfs.ACL{
    Entries: []permfs.ACLEntry{
        {
            Subject:     permfs.Group("engineering"),
            PathPattern: "/projects/**",
            Permissions: permfs.ReadWrite,
            Effect:      permfs.Allow,
            Priority:    100,
        },
        {
            Subject:     permfs.Group("managers"),
            PathPattern: "/**",
            Permissions: permfs.Read | permfs.Metadata,
            Effect:      permfs.Allow,
            Priority:    50,
        },
        {
            Subject:     permfs.Role("intern"),
            PathPattern: "/public/**",
            Permissions: permfs.Read,
            Effect:      permfs.Allow,
            Priority:    10,
        },
    },
    Default: permfs.Deny,
}
```

### Read-only Archive with Exceptions

```go
// Most files are read-only
// Admins can write to /admin
// Metadata service can update timestamps
acl := permfs.ACL{
    Entries: []permfs.ACLEntry{
        {
            Subject:     permfs.Group("admins"),
            PathPattern: "/admin/**",
            Permissions: permfs.All,
            Effect:      permfs.Allow,
            Priority:    1000,
        },
        {
            Subject:     permfs.User("metadata-service"),
            PathPattern: "/**",
            Permissions: permfs.Metadata,
            Effect:      permfs.Allow,
            Priority:    500,
        },
        {
            Subject:     permfs.Everyone(),
            PathPattern: "/**",
            Permissions: permfs.Read,
            Effect:      permfs.Allow,
            Priority:    1,
        },
    },
}
```

## Integration with Authentication Systems

### JWT Integration

```go
// Extract user identity from JWT token
func JWTAuthenticator(tokenString string) (*permfs.Identity, error) {
    token, err := jwt.Parse(tokenString, keyFunc)
    if err != nil {
        return nil, err
    }

    claims := token.Claims.(jwt.MapClaims)
    return &permfs.Identity{
        UserID: claims["sub"].(string),
        Groups: claims["groups"].([]string),
        Roles:  claims["roles"].([]string),
        Metadata: map[string]string{
            "email": claims["email"].(string),
        },
    }, nil
}

// Use with permfs
fs := permfs.NewWithAuthenticator(base, config, JWTAuthenticator)
ctx := permfs.WithToken(context.Background(), jwtToken)
```

### OAuth/OIDC

```go
// Configure OIDC provider
oidcProvider, err := oidc.NewProvider(ctx, "https://accounts.example.com")
verifier := oidcProvider.Verifier(&oidc.Config{ClientID: clientID})

authenticator := func(token string) (*permfs.Identity, error) {
    idToken, err := verifier.Verify(ctx, token)
    if err != nil {
        return nil, err
    }

    var claims struct {
        Sub    string   `json:"sub"`
        Email  string   `json:"email"`
        Groups []string `json:"groups"`
    }
    if err := idToken.Claims(&claims); err != nil {
        return nil, err
    }

    return &permfs.Identity{
        UserID: claims.Sub,
        Groups: claims.Groups,
        Metadata: map[string]string{"email": claims.Email},
    }, nil
}
```

### Custom Authentication

```go
type CustomAuthenticator struct {
    userDB UserDatabase
}

func (a *CustomAuthenticator) Authenticate(ctx context.Context) (*permfs.Identity, error) {
    // Extract credentials from context
    apiKey := ctx.Value("api-key").(string)

    // Validate and lookup user
    user, err := a.userDB.GetUserByAPIKey(apiKey)
    if err != nil {
        return nil, err
    }

    return &permfs.Identity{
        UserID: user.ID,
        Groups: user.Groups,
        Roles:  user.Roles,
    }, nil
}
```

## Audit Logging

### Structured Logging

```go
type AuditEvent struct {
    Timestamp   time.Time         `json:"timestamp"`
    RequestID   string            `json:"request_id"`
    UserID      string            `json:"user_id"`
    Operation   string            `json:"operation"`
    Path        string            `json:"path"`
    Result      string            `json:"result"` // "allowed" or "denied"
    Reason      string            `json:"reason,omitempty"`
    Duration    time.Duration     `json:"duration_ms"`
    Metadata    map[string]string `json:"metadata,omitempty"`
}

// Custom audit handler
fs, err := permfs.New(base, permfs.Config{
    Audit: permfs.AuditConfig{
        Handler: func(event permfs.AuditEvent) {
            // Send to SIEM, log aggregator, etc.
            siem.Send(event)

            // Alert on suspicious activity
            if event.Result == "denied" && event.UserID == "admin" {
                security.Alert("Admin access denied", event)
            }
        },
    },
})
```

### Audit Queries

```go
// Query audit logs
events, err := fs.AuditLog().Query(permfs.AuditQuery{
    StartTime: time.Now().Add(-24 * time.Hour),
    UserID:    "alice",
    Operation: "Delete",
    Result:    "denied",
})

// Export for compliance
fs.AuditLog().Export("/var/log/audit/permfs-2024-01.jsonl")
```

## Performance Considerations

### Caching Strategy

- **Rule compilation cache**: Pre-compiled path patterns (regex/glob)
- **Permission evaluation cache**: Results cached per (user, path, operation)
- **ACL lookup cache**: Fast access to applicable rules
- **Default TTL**: 5 minutes (configurable)
- **Cache invalidation**: On rule updates or explicit flush

### Performance Optimizations

```go
fs, err := permfs.New(base, permfs.Config{
    Performance: permfs.PerformanceConfig{
        // Enable caching
        CacheEnabled:     true,
        CacheTTL:         5 * time.Minute,
        CacheMaxSize:     10000,

        // Lazy evaluation
        LazyEvaluation:   true,

        // Async audit logging
        AsyncAudit:       true,
        AuditBufferSize:  1000,

        // Rule optimization
        CompilePatterns:  true,
        OptimizeRules:    true,
    },
})
```

### Benchmarks

Expected performance (with caching):
- Permission check: < 100 microseconds
- Rule evaluation: < 50 microseconds
- Cache hit rate: > 95% for typical workloads
- Overhead vs raw filesystem: < 5% for cached operations

### Scalability

- Support for 10,000+ concurrent users
- 100,000+ permission rules
- Million+ files per second (cached operations)
- Horizontal scaling via stateless design

## Testing

```go
// Use in tests with mock users
func TestFileAccess(t *testing.T) {
    fs := permfs.NewTestFS(t, permfs.TestConfig{
        Users: []string{"alice", "bob"},
        Groups: map[string][]string{
            "admin": {"alice"},
            "users": {"bob"},
        },
        ACL: testACL,
    })

    ctx := permfs.WithUser(context.Background(), "alice")

    // Test access
    f, err := fs.OpenFile(ctx, "/admin/config.json", os.O_RDONLY, 0)
    require.NoError(t, err)
    defer f.Close()

    // Test denial
    ctx = permfs.WithUser(context.Background(), "bob")
    _, err = fs.OpenFile(ctx, "/admin/config.json", os.O_RDONLY, 0)
    require.Error(t, err)
    require.True(t, permfs.IsPermissionDenied(err))
}
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please see the AbsFS contribution guidelines.

## Related Projects

- [absfs](https://github.com/absfs/absfs) - Core filesystem abstraction
- [basefs](https://github.com/absfs/basefs) - Base filesystem wrapper utilities
- [lockfs](https://github.com/absfs/lockfs) - Concurrent access control
- [rofs](https://github.com/absfs/rofs) - Read-only filesystem wrapper
