package permfs

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewAuditLogger(t *testing.T) {
	t.Run("disabled logger", func(t *testing.T) {
		logger := NewAuditLogger(AuditConfig{Enabled: false})
		if logger.level != AuditLevelNone {
			t.Error("disabled logger should have level None")
		}
	})

	t.Run("enabled logger with defaults", func(t *testing.T) {
		logger := NewAuditLogger(AuditConfig{Enabled: true})
		defer logger.Close()

		if logger.level != AuditLevelAll {
			t.Error("default level should be All")
		}
		if logger.writer == nil {
			t.Error("writer should not be nil")
		}
	})

	t.Run("enabled logger with custom level", func(t *testing.T) {
		level := AuditLevelDenied
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Level:   &level,
		})
		defer logger.Close()

		if logger.level != AuditLevelDenied {
			t.Errorf("expected level Denied, got %v", logger.level)
		}
	})

	t.Run("enabled logger with custom writer", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
		})
		defer logger.Close()

		if logger.writer != &buf {
			t.Error("custom writer should be used")
		}
	})

	t.Run("async logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
			Async:   true,
		})

		if logger.buffer == nil {
			t.Error("async logger should have buffer")
		}
		if logger.bufferSize != 1000 {
			t.Errorf("default buffer size should be 1000, got %d", logger.bufferSize)
		}

		logger.Close()
	})

	t.Run("async logger with custom buffer size", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled:    true,
			Writer:     &buf,
			Async:      true,
			BufferSize: 500,
		})
		defer logger.Close()

		if logger.bufferSize != 500 {
			t.Errorf("expected buffer size 500, got %d", logger.bufferSize)
		}
	})

	t.Run("logger with custom handler", func(t *testing.T) {
		var handlerCalled bool
		handler := func(event *AuditEvent) {
			handlerCalled = true
		}

		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
			Handler: handler,
		})
		defer logger.Close()

		logger.Log(&AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
		})

		if !handlerCalled {
			t.Error("custom handler should be called")
		}
	})
}

func TestAuditLoggerLog(t *testing.T) {
	t.Run("log to disabled logger", func(t *testing.T) {
		logger := NewAuditLogger(AuditConfig{Enabled: false})
		// This should not panic
		logger.Log(&AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
		})
	})

	t.Run("log nil logger", func(t *testing.T) {
		var logger *AuditLogger
		// This should not panic
		logger.Log(&AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
		})
	})

	t.Run("log denied only - allowed event", func(t *testing.T) {
		var buf bytes.Buffer
		level := AuditLevelDenied
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
			Level:   &level,
		})
		defer logger.Close()

		logger.Log(&AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
		})

		if buf.Len() > 0 {
			t.Error("allowed events should not be logged at DeniedLevel")
		}
	})

	t.Run("log denied only - denied event", func(t *testing.T) {
		var buf bytes.Buffer
		level := AuditLevelDenied
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
			Level:   &level,
		})
		defer logger.Close()

		logger.Log(&AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultDenied,
		})

		if buf.Len() == 0 {
			t.Error("denied events should be logged at DeniedLevel")
		}
	})

	t.Run("log sets timestamp if empty", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
		})
		defer logger.Close()

		event := &AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
		}

		logger.Log(event)

		if event.Timestamp.IsZero() {
			t.Error("timestamp should be set")
		}
	})

	t.Run("log preserves existing timestamp", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
		})
		defer logger.Close()

		expectedTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		event := &AuditEvent{
			Timestamp: expectedTime,
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
		}

		logger.Log(event)

		if !event.Timestamp.Equal(expectedTime) {
			t.Error("timestamp should not be modified if already set")
		}
	})

	t.Run("log writes JSON", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
		})
		defer logger.Close()

		logger.Log(&AuditEvent{
			UserID:    "alice",
			Operation: "Read",
			Path:      "/home/alice/file.txt",
			Result:    AuditResultAllowed,
		})

		var event AuditEvent
		if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
			t.Fatalf("output should be valid JSON: %v", err)
		}

		if event.UserID != "alice" {
			t.Errorf("expected user 'alice', got %q", event.UserID)
		}
		if event.Path != "/home/alice/file.txt" {
			t.Errorf("expected path '/home/alice/file.txt', got %q", event.Path)
		}
	})
}

func TestAuditLoggerAsync(t *testing.T) {
	t.Run("async logging", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
			Async:   true,
		})

		logger.Log(&AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
		})

		// Close to ensure all events are flushed
		logger.Close()

		if buf.Len() == 0 {
			t.Error("async event should be written after close")
		}
	})

	t.Run("async with buffer overflow fallback", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled:    true,
			Writer:     &buf,
			Async:      true,
			BufferSize: 1,
		})

		// Fill the buffer and trigger overflow
		for i := 0; i < 10; i++ {
			logger.Log(&AuditEvent{
				UserID:    "test",
				Operation: "Read",
				Path:      "/test",
				Result:    AuditResultAllowed,
			})
		}

		logger.Close()

		// Should have some events logged
		if buf.Len() == 0 {
			t.Error("events should be written")
		}
	})
}

func TestAuditLoggerClose(t *testing.T) {
	t.Run("close sync logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
		})

		err := logger.Close()
		if err != nil {
			t.Errorf("close should not error: %v", err)
		}
	})

	t.Run("close async logger drains buffer", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(AuditConfig{
			Enabled: true,
			Writer:  &buf,
			Async:   true,
		})

		// Log several events
		for i := 0; i < 5; i++ {
			logger.Log(&AuditEvent{
				UserID:    "test",
				Operation: "Read",
				Path:      "/test",
				Result:    AuditResultAllowed,
			})
		}

		err := logger.Close()
		if err != nil {
			t.Errorf("close should not error: %v", err)
		}

		// Count newlines to verify all events written
		lines := strings.Count(buf.String(), "\n")
		if lines != 5 {
			t.Errorf("expected 5 events, got %d", lines)
		}
	})
}

func TestAuditLoggerGetMetrics(t *testing.T) {
	logger := NewAuditLogger(AuditConfig{Enabled: true})
	defer logger.Close()

	metrics := logger.GetMetrics()
	if metrics == nil {
		t.Error("GetMetrics should return non-nil metrics")
	}
}

func TestNewAuditMetrics(t *testing.T) {
	metrics := NewAuditMetrics()

	if metrics == nil {
		t.Fatal("NewAuditMetrics should return non-nil")
	}
	if metrics.operationCounts == nil {
		t.Error("operationCounts should be initialized")
	}
	if metrics.userDenialCounts == nil {
		t.Error("userDenialCounts should be initialized")
	}
	if metrics.pathAccessCounts == nil {
		t.Error("pathAccessCounts should be initialized")
	}
}

func TestAuditMetricsRecordEvent(t *testing.T) {
	metrics := NewAuditMetrics()

	t.Run("record allowed event", func(t *testing.T) {
		metrics.RecordEvent(&AuditEvent{
			UserID:    "alice",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
			Duration:  100 * time.Millisecond,
		})

		stats := metrics.GetStats()
		if stats.TotalEvents != 1 {
			t.Errorf("expected 1 total event, got %d", stats.TotalEvents)
		}
		if stats.AllowedEvents != 1 {
			t.Errorf("expected 1 allowed event, got %d", stats.AllowedEvents)
		}
	})

	t.Run("record denied event", func(t *testing.T) {
		metrics.RecordEvent(&AuditEvent{
			UserID:    "bob",
			Operation: "Write",
			Path:      "/secret",
			Result:    AuditResultDenied,
			Duration:  50 * time.Millisecond,
		})

		stats := metrics.GetStats()
		if stats.DeniedEvents != 1 {
			t.Errorf("expected 1 denied event, got %d", stats.DeniedEvents)
		}
	})

	t.Run("record error event", func(t *testing.T) {
		metrics.RecordEvent(&AuditEvent{
			UserID:    "charlie",
			Operation: "Delete",
			Path:      "/error",
			Result:    AuditResultError,
			Duration:  10 * time.Millisecond,
		})

		stats := metrics.GetStats()
		if stats.ErrorEvents != 1 {
			t.Errorf("expected 1 error event, got %d", stats.ErrorEvents)
		}
	})
}

func TestAuditMetricsIncrementDropped(t *testing.T) {
	metrics := NewAuditMetrics()

	for i := 0; i < 5; i++ {
		metrics.IncrementDropped()
	}

	stats := metrics.GetStats()
	if stats.DroppedEvents != 5 {
		t.Errorf("expected 5 dropped events, got %d", stats.DroppedEvents)
	}
}

func TestAuditMetricsGetStats(t *testing.T) {
	metrics := NewAuditMetrics()

	// Record events with durations
	for i := 0; i < 4; i++ {
		metrics.RecordEvent(&AuditEvent{
			UserID:    "test",
			Operation: "Read",
			Path:      "/test",
			Result:    AuditResultAllowed,
			Duration:  100 * time.Millisecond,
		})
	}

	stats := metrics.GetStats()

	if stats.TotalEvents != 4 {
		t.Errorf("expected 4 total events, got %d", stats.TotalEvents)
	}
	if stats.AverageDuration != 100*time.Millisecond {
		t.Errorf("expected average duration 100ms, got %v", stats.AverageDuration)
	}
}

func TestAuditMetricsGetStatsZeroEvents(t *testing.T) {
	metrics := NewAuditMetrics()

	stats := metrics.GetStats()

	if stats.AverageDuration != 0 {
		t.Errorf("expected 0 average duration with no events, got %v", stats.AverageDuration)
	}
}

func TestAuditMetricsGetTopDeniedUsers(t *testing.T) {
	metrics := NewAuditMetrics()

	// Record denials for different users
	users := []struct {
		id    string
		count int
	}{
		{"alice", 5},
		{"bob", 10},
		{"charlie", 3},
		{"dave", 8},
	}

	for _, u := range users {
		for i := 0; i < u.count; i++ {
			metrics.RecordEvent(&AuditEvent{
				UserID:    u.id,
				Operation: "Read",
				Path:      "/secret",
				Result:    AuditResultDenied,
			})
		}
	}

	t.Run("top 2 users", func(t *testing.T) {
		top := metrics.GetTopDeniedUsers(2)

		if len(top) != 2 {
			t.Fatalf("expected 2 users, got %d", len(top))
		}
		if top[0].UserID != "bob" || top[0].Count != 10 {
			t.Errorf("expected bob with 10 denials first, got %s with %d", top[0].UserID, top[0].Count)
		}
		if top[1].UserID != "dave" || top[1].Count != 8 {
			t.Errorf("expected dave with 8 denials second, got %s with %d", top[1].UserID, top[1].Count)
		}
	})

	t.Run("all users", func(t *testing.T) {
		top := metrics.GetTopDeniedUsers(10)

		if len(top) != 4 {
			t.Errorf("expected 4 users, got %d", len(top))
		}
	})
}

func TestAuditMetricsGetTopAccessedPaths(t *testing.T) {
	metrics := NewAuditMetrics()

	// Record accesses to different paths
	paths := []struct {
		path  string
		count int
	}{
		{"/home/alice", 5},
		{"/home/bob", 15},
		{"/data", 10},
		{"/tmp", 3},
	}

	for _, p := range paths {
		for i := 0; i < p.count; i++ {
			metrics.RecordEvent(&AuditEvent{
				UserID:    "user",
				Operation: "Read",
				Path:      p.path,
				Result:    AuditResultAllowed,
			})
		}
	}

	t.Run("top 2 paths", func(t *testing.T) {
		top := metrics.GetTopAccessedPaths(2)

		if len(top) != 2 {
			t.Fatalf("expected 2 paths, got %d", len(top))
		}
		if top[0].Path != "/home/bob" || top[0].Count != 15 {
			t.Errorf("expected /home/bob with 15 accesses first, got %s with %d", top[0].Path, top[0].Count)
		}
		if top[1].Path != "/data" || top[1].Count != 10 {
			t.Errorf("expected /data with 10 accesses second, got %s with %d", top[1].Path, top[1].Count)
		}
	})

	t.Run("all paths", func(t *testing.T) {
		top := metrics.GetTopAccessedPaths(10)

		if len(top) != 4 {
			t.Errorf("expected 4 paths, got %d", len(top))
		}
	})
}

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	requestID := "req-12345"

	newCtx := WithRequestID(ctx, requestID)

	if newCtx == ctx {
		t.Error("WithRequestID should return a new context")
	}

	retrieved := GetRequestID(newCtx)
	if retrieved != requestID {
		t.Errorf("expected request ID %q, got %q", requestID, retrieved)
	}
}

func TestGetRequestID(t *testing.T) {
	t.Run("context with request ID", func(t *testing.T) {
		ctx := WithRequestID(context.Background(), "test-id")
		id := GetRequestID(ctx)
		if id != "test-id" {
			t.Errorf("expected 'test-id', got %q", id)
		}
	})

	t.Run("context without request ID", func(t *testing.T) {
		ctx := context.Background()
		id := GetRequestID(ctx)
		if id != "" {
			t.Errorf("expected empty string, got %q", id)
		}
	})

	t.Run("context with wrong type value", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "request_id", 12345)
		id := GetRequestID(ctx)
		if id != "" {
			t.Errorf("expected empty string for wrong type, got %q", id)
		}
	})
}

func TestAuditMetricsConcurrency(t *testing.T) {
	metrics := NewAuditMetrics()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			metrics.RecordEvent(&AuditEvent{
				UserID:    "user",
				Operation: "Read",
				Path:      "/test",
				Result:    AuditResultAllowed,
				Duration:  time.Millisecond,
			})
			metrics.IncrementDropped()
			_ = metrics.GetStats()
			_ = metrics.GetTopDeniedUsers(5)
			_ = metrics.GetTopAccessedPaths(5)
		}(i)
	}
	wg.Wait()

	stats := metrics.GetStats()
	if stats.TotalEvents != 100 {
		t.Errorf("expected 100 events, got %d", stats.TotalEvents)
	}
	if stats.DroppedEvents != 100 {
		t.Errorf("expected 100 dropped events, got %d", stats.DroppedEvents)
	}
}
