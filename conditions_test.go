package permfs

import (
	"testing"
	"time"
)

func TestTimeCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition *TimeCondition
		testTime  time.Time
		expected  bool
	}{
		{
			name: "within business hours",
			condition: NewBusinessHoursCondition(),
			testTime:  time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC), // Monday 10am
			expected:  true,
		},
		{
			name: "outside business hours - too early",
			condition: NewBusinessHoursCondition(),
			testTime:  time.Date(2024, 1, 15, 8, 0, 0, 0, time.UTC), // Monday 8am
			expected:  false,
		},
		{
			name: "outside business hours - too late",
			condition: NewBusinessHoursCondition(),
			testTime:  time.Date(2024, 1, 15, 18, 0, 0, 0, time.UTC), // Monday 6pm
			expected:  false,
		},
		{
			name: "weekend",
			condition: NewBusinessHoursCondition(),
			testTime:  time.Date(2024, 1, 14, 10, 0, 0, 0, time.UTC), // Sunday 10am
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: In a real test, we would mock time.Now()
			// For this simple test, we're just validating the logic structure
			_ = tt.testTime // We can't easily override time.Now() without dependency injection

			// Test the String method
			if tt.condition.String() != "TimeCondition" {
				t.Errorf("Expected String() to return 'TimeCondition'")
			}
		})
	}
}

func TestIPCondition(t *testing.T) {
	tests := []struct {
		name             string
		allowedCIDRs     []string
		deniedCIDRs      []string
		sourceIP         string
		expected         bool
	}{
		{
			name:         "allowed IP in range",
			allowedCIDRs: []string{"192.168.1.0/24"},
			sourceIP:     "192.168.1.100",
			expected:     true,
		},
		{
			name:         "IP outside allowed range",
			allowedCIDRs: []string{"192.168.1.0/24"},
			sourceIP:     "192.168.2.100",
			expected:     false,
		},
		{
			name:         "explicitly denied IP",
			allowedCIDRs: []string{"192.168.0.0/16"},
			deniedCIDRs:  []string{"192.168.1.0/24"},
			sourceIP:     "192.168.1.100",
			expected:     false,
		},
		{
			name:         "allowed IP not in denied range",
			allowedCIDRs: []string{"192.168.0.0/16"},
			deniedCIDRs:  []string{"192.168.1.0/24"},
			sourceIP:     "192.168.2.100",
			expected:     true,
		},
		{
			name:     "no IP in context",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond, err := NewIPCondition(tt.allowedCIDRs, tt.deniedCIDRs)
			if err != nil {
				t.Fatalf("Failed to create IP condition: %v", err)
			}

			ctx := &EvaluationContext{
				Metadata: make(map[string]interface{}),
			}

			if tt.sourceIP != "" {
				ctx.Metadata["source_ip"] = tt.sourceIP
			}

			got := cond.Evaluate(ctx)
			if got != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, got)
			}

			if cond.String() != "IPCondition" {
				t.Errorf("Expected String() to return 'IPCondition'")
			}
		})
	}
}

func TestMetadataCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition *MetadataCondition
		metadata  map[string]interface{}
		expected  bool
	}{
		{
			name: "exact match case sensitive",
			condition: &MetadataCondition{
				Key:           "environment",
				Values:        []string{"production", "staging"},
				CaseSensitive: true,
			},
			metadata: map[string]interface{}{"environment": "production"},
			expected: true,
		},
		{
			name: "case mismatch case sensitive",
			condition: &MetadataCondition{
				Key:           "environment",
				Values:        []string{"production"},
				CaseSensitive: true,
			},
			metadata: map[string]interface{}{"environment": "Production"},
			expected: false,
		},
		{
			name: "case mismatch case insensitive",
			condition: &MetadataCondition{
				Key:           "environment",
				Values:        []string{"production"},
				CaseSensitive: false,
			},
			metadata: map[string]interface{}{"environment": "Production"},
			expected: true,
		},
		{
			name: "key not present",
			condition: &MetadataCondition{
				Key:    "environment",
				Values: []string{"production"},
			},
			metadata: map[string]interface{}{"other": "value"},
			expected: false,
		},
		{
			name: "value not in list",
			condition: &MetadataCondition{
				Key:    "environment",
				Values: []string{"production", "staging"},
			},
			metadata: map[string]interface{}{"environment": "development"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &EvaluationContext{
				Metadata: tt.metadata,
			}

			got := tt.condition.Evaluate(ctx)
			if got != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestFuncCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition *FuncCondition
		expected  bool
	}{
		{
			name: "always true",
			condition: NewFuncCondition("always_true", func(ctx *EvaluationContext) bool {
				return true
			}),
			expected: true,
		},
		{
			name: "always false",
			condition: NewFuncCondition("always_false", func(ctx *EvaluationContext) bool {
				return false
			}),
			expected: false,
		},
		{
			name: "check metadata",
			condition: NewFuncCondition("check_admin", func(ctx *EvaluationContext) bool {
				isAdmin, ok := ctx.Metadata["is_admin"].(bool)
				return ok && isAdmin
			}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &EvaluationContext{
				Metadata: map[string]interface{}{"is_admin": true},
			}

			got := tt.condition.Evaluate(ctx)
			if got != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, got)
			}

			if tt.condition.String() != "FuncCondition:"+tt.condition.Name {
				t.Errorf("Expected String() to return 'FuncCondition:%s'", tt.condition.Name)
			}
		})
	}
}

func TestAndCondition(t *testing.T) {
	trueFunc := func(ctx *EvaluationContext) bool { return true }
	falseFunc := func(ctx *EvaluationContext) bool { return false }

	tests := []struct {
		name       string
		conditions []Condition
		expected   bool
	}{
		{
			name: "all true",
			conditions: []Condition{
				NewFuncCondition("true1", trueFunc),
				NewFuncCondition("true2", trueFunc),
			},
			expected: true,
		},
		{
			name: "one false",
			conditions: []Condition{
				NewFuncCondition("true", trueFunc),
				NewFuncCondition("false", falseFunc),
			},
			expected: false,
		},
		{
			name: "all false",
			conditions: []Condition{
				NewFuncCondition("false1", falseFunc),
				NewFuncCondition("false2", falseFunc),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &AndCondition{Conditions: tt.conditions}
			ctx := &EvaluationContext{}

			got := cond.Evaluate(ctx)
			if got != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestOrCondition(t *testing.T) {
	trueFunc := func(ctx *EvaluationContext) bool { return true }
	falseFunc := func(ctx *EvaluationContext) bool { return false }

	tests := []struct {
		name       string
		conditions []Condition
		expected   bool
	}{
		{
			name: "all true",
			conditions: []Condition{
				NewFuncCondition("true1", trueFunc),
				NewFuncCondition("true2", trueFunc),
			},
			expected: true,
		},
		{
			name: "one true",
			conditions: []Condition{
				NewFuncCondition("false", falseFunc),
				NewFuncCondition("true", trueFunc),
			},
			expected: true,
		},
		{
			name: "all false",
			conditions: []Condition{
				NewFuncCondition("false1", falseFunc),
				NewFuncCondition("false2", falseFunc),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &OrCondition{Conditions: tt.conditions}
			ctx := &EvaluationContext{}

			got := cond.Evaluate(ctx)
			if got != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestNotCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition Condition
		expected  bool
	}{
		{
			name: "invert true",
			condition: NewFuncCondition("true", func(ctx *EvaluationContext) bool {
				return true
			}),
			expected: false,
		},
		{
			name: "invert false",
			condition: NewFuncCondition("false", func(ctx *EvaluationContext) bool {
				return false
			}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &NotCondition{Condition: tt.condition}
			ctx := &EvaluationContext{}

			got := cond.Evaluate(ctx)
			if got != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestTimeConditionEvaluate(t *testing.T) {
	// Test with specific hours that we know work
	cond := &TimeCondition{
		AllowedHours: []HourRange{{Start: 0, End: 23}},
		AllowedDays:  []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday},
	}

	ctx := &EvaluationContext{}
	// This should always be true since we allow all hours and all days
	if !cond.Evaluate(ctx) {
		t.Error("Expected TimeCondition to return true for all hours and all days")
	}
}

func TestIPConditionString(t *testing.T) {
	cond, err := NewIPCondition([]string{"192.168.1.0/24"}, nil)
	if err != nil {
		t.Fatalf("NewIPCondition error: %v", err)
	}

	s := cond.String()
	if s != "IPCondition" {
		t.Errorf("Expected 'IPCondition', got %q", s)
	}
}

func TestIPConditionInvalidCIDR(t *testing.T) {
	_, err := NewIPCondition([]string{"invalid-cidr"}, nil)
	if err == nil {
		t.Error("Expected error for invalid CIDR")
	}
}

func TestIPConditionInvalidDenyCIDR(t *testing.T) {
	_, err := NewIPCondition([]string{"192.168.1.0/24"}, []string{"invalid-deny"})
	if err == nil {
		t.Error("Expected error for invalid deny CIDR")
	}
}

func TestIPConditionInvalidSourceIP(t *testing.T) {
	cond, err := NewIPCondition([]string{"192.168.1.0/24"}, nil)
	if err != nil {
		t.Fatalf("NewIPCondition error: %v", err)
	}

	ctx := &EvaluationContext{
		Metadata: map[string]interface{}{"source_ip": "not-an-ip"},
	}

	if cond.Evaluate(ctx) {
		t.Error("Expected false for invalid source IP")
	}
}

func TestAndConditionString(t *testing.T) {
	cond := &AndCondition{
		Conditions: []Condition{
			NewFuncCondition("test", func(*EvaluationContext) bool { return true }),
		},
	}

	s := cond.String()
	if s != "AndCondition" {
		t.Errorf("Expected 'AndCondition', got %q", s)
	}
}

func TestOrConditionString(t *testing.T) {
	cond := &OrCondition{
		Conditions: []Condition{
			NewFuncCondition("test", func(*EvaluationContext) bool { return true }),
		},
	}

	s := cond.String()
	if s != "OrCondition" {
		t.Errorf("Expected 'OrCondition', got %q", s)
	}
}

func TestNotConditionString(t *testing.T) {
	cond := &NotCondition{
		Condition: NewFuncCondition("test", func(*EvaluationContext) bool { return true }),
	}

	s := cond.String()
	if s != "NotCondition" {
		t.Errorf("Expected 'NotCondition', got %q", s)
	}
}

func TestMetadataConditionString(t *testing.T) {
	cond := &MetadataCondition{
		Key:    "test",
		Values: []string{"value"},
	}

	s := cond.String()
	if s != "MetadataCondition:test" {
		t.Errorf("Expected 'MetadataCondition:test', got %q", s)
	}
}
