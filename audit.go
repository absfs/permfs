package permfs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// AuditLevel defines the verbosity of audit logging
type AuditLevel int

const (
	// AuditLevelNone disables audit logging
	AuditLevelNone AuditLevel = iota
	// AuditLevelDenied logs only denied access attempts
	AuditLevelDenied
	// AuditLevelAll logs all access attempts
	AuditLevelAll
)

// AuditResult represents the result of an access attempt
type AuditResult string

const (
	// AuditResultAllowed indicates access was granted
	AuditResultAllowed AuditResult = "allowed"
	// AuditResultDenied indicates access was denied
	AuditResultDenied AuditResult = "denied"
	// AuditResultError indicates an error occurred
	AuditResultError AuditResult = "error"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`
	// RequestID is a unique identifier for the request
	RequestID string `json:"request_id,omitempty"`
	// UserID is the user who attempted the operation
	UserID string `json:"user_id"`
	// Groups are the groups the user belongs to
	Groups []string `json:"groups,omitempty"`
	// Roles are the roles assigned to the user
	Roles []string `json:"roles,omitempty"`
	// Operation is the filesystem operation attempted
	Operation string `json:"operation"`
	// Path is the filesystem path accessed
	Path string `json:"path"`
	// Result is whether access was allowed or denied
	Result AuditResult `json:"result"`
	// Reason provides additional context for the result
	Reason string `json:"reason,omitempty"`
	// Duration is how long the permission check took
	Duration time.Duration `json:"duration_ms"`
	// Metadata contains additional context information
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// SourceIP is the IP address of the request (if available)
	SourceIP string `json:"source_ip,omitempty"`
}

// AuditLogger handles audit logging
type AuditLogger struct {
	mu           sync.RWMutex
	writer       io.Writer
	level        AuditLevel
	buffer       chan *AuditEvent
	bufferSize   int
	async        bool
	stopCh       chan struct{}
	wg           sync.WaitGroup
	metrics      *AuditMetrics
	handler      AuditHandler
}

// AuditHandler is a function that processes audit events
type AuditHandler func(event *AuditEvent)

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config AuditConfig) *AuditLogger {
	if !config.Enabled {
		return &AuditLogger{
			level: AuditLevelNone,
		}
	}

	writer := config.Writer
	if writer == nil {
		writer = os.Stdout
	}

	level := AuditLevelAll
	if config.Level != nil {
		level = *config.Level
	}

	logger := &AuditLogger{
		writer:     writer,
		level:      level,
		bufferSize: config.BufferSize,
		async:      config.Async,
		metrics:    NewAuditMetrics(),
		handler:    config.Handler,
	}

	// Start async logging if enabled
	if logger.async {
		if logger.bufferSize == 0 {
			logger.bufferSize = 1000
		}
		logger.buffer = make(chan *AuditEvent, logger.bufferSize)
		logger.stopCh = make(chan struct{})
		logger.wg.Add(1)
		go logger.processEvents()
	}

	return logger
}

// Log logs an audit event
func (al *AuditLogger) Log(event *AuditEvent) {
	if al == nil || al.level == AuditLevelNone {
		return
	}

	// Filter based on level
	if al.level == AuditLevelDenied && event.Result != AuditResultDenied {
		return
	}

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Update metrics
	al.metrics.RecordEvent(event)

	// Call custom handler if provided
	if al.handler != nil {
		al.handler(event)
	}

	if al.async {
		// Async logging
		select {
		case al.buffer <- event:
			// Event buffered successfully
		default:
			// Buffer full, log synchronously as fallback
			al.writeEvent(event)
			al.metrics.IncrementDropped()
		}
	} else {
		// Synchronous logging
		al.writeEvent(event)
	}
}

// writeEvent writes an event to the configured writer
func (al *AuditLogger) writeEvent(event *AuditEvent) {
	al.mu.Lock()
	defer al.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	fmt.Fprintf(al.writer, "%s\n", data)
}

// processEvents processes events from the buffer (async mode)
func (al *AuditLogger) processEvents() {
	defer al.wg.Done()

	for {
		select {
		case event := <-al.buffer:
			al.writeEvent(event)
		case <-al.stopCh:
			// Drain remaining events
			for {
				select {
				case event := <-al.buffer:
					al.writeEvent(event)
				default:
					return
				}
			}
		}
	}
}

// Close shuts down the audit logger
func (al *AuditLogger) Close() error {
	if al.async && al.stopCh != nil {
		close(al.stopCh)
		al.wg.Wait()
		close(al.buffer)
	}
	return nil
}

// GetMetrics returns audit metrics
func (al *AuditLogger) GetMetrics() *AuditMetrics {
	return al.metrics
}

// AuditMetrics tracks audit logging statistics
type AuditMetrics struct {
	mu                 sync.RWMutex
	totalEvents        uint64
	allowedEvents      uint64
	deniedEvents       uint64
	errorEvents        uint64
	droppedEvents      uint64
	totalDuration      time.Duration
	operationCounts    map[string]uint64
	userDenialCounts   map[string]uint64
	pathAccessCounts   map[string]uint64
}

// NewAuditMetrics creates a new metrics tracker
func NewAuditMetrics() *AuditMetrics {
	return &AuditMetrics{
		operationCounts:  make(map[string]uint64),
		userDenialCounts: make(map[string]uint64),
		pathAccessCounts: make(map[string]uint64),
	}
}

// RecordEvent records metrics for an audit event
func (am *AuditMetrics) RecordEvent(event *AuditEvent) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.totalEvents++
	am.totalDuration += event.Duration

	switch event.Result {
	case AuditResultAllowed:
		am.allowedEvents++
	case AuditResultDenied:
		am.deniedEvents++
		am.userDenialCounts[event.UserID]++
	case AuditResultError:
		am.errorEvents++
	}

	am.operationCounts[event.Operation]++
	am.pathAccessCounts[event.Path]++
}

// IncrementDropped increments the dropped events counter
func (am *AuditMetrics) IncrementDropped() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.droppedEvents++
}

// GetStats returns current metrics
func (am *AuditMetrics) GetStats() AuditStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	avgDuration := time.Duration(0)
	if am.totalEvents > 0 {
		avgDuration = am.totalDuration / time.Duration(am.totalEvents)
	}

	return AuditStats{
		TotalEvents:     am.totalEvents,
		AllowedEvents:   am.allowedEvents,
		DeniedEvents:    am.deniedEvents,
		ErrorEvents:     am.errorEvents,
		DroppedEvents:   am.droppedEvents,
		AverageDuration: avgDuration,
	}
}

// GetTopDeniedUsers returns users with most denials
func (am *AuditMetrics) GetTopDeniedUsers(limit int) []UserDenialStat {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := make([]UserDenialStat, 0, len(am.userDenialCounts))
	for userID, count := range am.userDenialCounts {
		stats = append(stats, UserDenialStat{
			UserID: userID,
			Count:  count,
		})
	}

	// Simple bubble sort for top N
	for i := 0; i < len(stats) && i < limit; i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].Count > stats[i].Count {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	if len(stats) > limit {
		stats = stats[:limit]
	}

	return stats
}

// GetTopAccessedPaths returns most accessed paths
func (am *AuditMetrics) GetTopAccessedPaths(limit int) []PathAccessStat {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := make([]PathAccessStat, 0, len(am.pathAccessCounts))
	for path, count := range am.pathAccessCounts {
		stats = append(stats, PathAccessStat{
			Path:  path,
			Count: count,
		})
	}

	// Simple bubble sort for top N
	for i := 0; i < len(stats) && i < limit; i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].Count > stats[i].Count {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	if len(stats) > limit {
		stats = stats[:limit]
	}

	return stats
}

// AuditStats contains audit statistics
type AuditStats struct {
	TotalEvents     uint64
	AllowedEvents   uint64
	DeniedEvents    uint64
	ErrorEvents     uint64
	DroppedEvents   uint64
	AverageDuration time.Duration
}

// UserDenialStat tracks denial count for a user
type UserDenialStat struct {
	UserID string
	Count  uint64
}

// PathAccessStat tracks access count for a path
type PathAccessStat struct {
	Path  string
	Count uint64
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, "request_id", requestID)
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value("request_id").(string); ok {
		return requestID
	}
	return ""
}
