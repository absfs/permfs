package permfs

import (
	"net"
	"strings"
	"time"
)

// TimeCondition checks if the current time falls within allowed time ranges
type TimeCondition struct {
	// AllowedHours contains allowed hour ranges (0-23)
	AllowedHours []HourRange
	// AllowedDays contains allowed days of week (0=Sunday, 6=Saturday)
	AllowedDays []time.Weekday
	// Timezone for time evaluation (nil uses UTC)
	Timezone *time.Location
}

// HourRange represents a range of hours
type HourRange struct {
	Start int // 0-23
	End   int // 0-23
}

// Evaluate checks if the current time satisfies the condition
func (tc *TimeCondition) Evaluate(ctx *EvaluationContext) bool {
	now := time.Now()
	if tc.Timezone != nil {
		now = now.In(tc.Timezone)
	}

	// Check day of week if specified
	if len(tc.AllowedDays) > 0 {
		dayAllowed := false
		currentDay := now.Weekday()
		for _, day := range tc.AllowedDays {
			if day == currentDay {
				dayAllowed = true
				break
			}
		}
		if !dayAllowed {
			return false
		}
	}

	// Check hours if specified
	if len(tc.AllowedHours) > 0 {
		hourAllowed := false
		currentHour := now.Hour()
		for _, hourRange := range tc.AllowedHours {
			if currentHour >= hourRange.Start && currentHour <= hourRange.End {
				hourAllowed = true
				break
			}
		}
		if !hourAllowed {
			return false
		}
	}

	return true
}

// String returns a string representation
func (tc *TimeCondition) String() string {
	return "TimeCondition"
}

// NewBusinessHoursCondition creates a condition for standard business hours (9am-5pm, weekdays)
func NewBusinessHoursCondition() *TimeCondition {
	return &TimeCondition{
		AllowedHours: []HourRange{{Start: 9, End: 17}},
		AllowedDays: []time.Weekday{
			time.Monday,
			time.Tuesday,
			time.Wednesday,
			time.Thursday,
			time.Friday,
		},
	}
}

// IPCondition checks if the request comes from an allowed IP address or network
type IPCondition struct {
	// AllowedNetworks contains allowed CIDR ranges
	AllowedNetworks []*net.IPNet
	// DeniedNetworks contains explicitly denied CIDR ranges (takes precedence)
	DeniedNetworks []*net.IPNet
}

// Evaluate checks if the source IP satisfies the condition
func (ic *IPCondition) Evaluate(ctx *EvaluationContext) bool {
	// Get IP from metadata
	ipStr, ok := ctx.Metadata["source_ip"].(string)
	if !ok {
		// No IP in context, deny by default
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check denied networks first (explicit deny takes precedence)
	for _, network := range ic.DeniedNetworks {
		if network.Contains(ip) {
			return false
		}
	}

	// Check allowed networks
	if len(ic.AllowedNetworks) == 0 {
		// No restrictions, allow all
		return true
	}

	for _, network := range ic.AllowedNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// String returns a string representation
func (ic *IPCondition) String() string {
	return "IPCondition"
}

// NewIPCondition creates a new IP condition from CIDR strings
func NewIPCondition(allowedCIDRs, deniedCIDRs []string) (*IPCondition, error) {
	cond := &IPCondition{}

	for _, cidr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		cond.AllowedNetworks = append(cond.AllowedNetworks, network)
	}

	for _, cidr := range deniedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		cond.DeniedNetworks = append(cond.DeniedNetworks, network)
	}

	return cond, nil
}

// MetadataCondition checks metadata key-value pairs
type MetadataCondition struct {
	// Key is the metadata key to check
	Key string
	// Values are allowed values (any match allows access)
	Values []string
	// CaseSensitive determines if value comparison is case sensitive
	CaseSensitive bool
}

// Evaluate checks if metadata satisfies the condition
func (mc *MetadataCondition) Evaluate(ctx *EvaluationContext) bool {
	value, ok := ctx.Metadata[mc.Key]
	if !ok {
		return false
	}

	valueStr, ok := value.(string)
	if !ok {
		return false
	}

	for _, allowed := range mc.Values {
		if mc.CaseSensitive {
			if valueStr == allowed {
				return true
			}
		} else {
			if strings.EqualFold(valueStr, allowed) {
				return true
			}
		}
	}

	return false
}

// String returns a string representation
func (mc *MetadataCondition) String() string {
	return "MetadataCondition:" + mc.Key
}

// CustomConditionFunc is a function type for custom conditions
type CustomConditionFunc func(ctx *EvaluationContext) bool

// FuncCondition wraps a function as a Condition
type FuncCondition struct {
	Name string
	Func CustomConditionFunc
}

// Evaluate executes the custom function
func (fc *FuncCondition) Evaluate(ctx *EvaluationContext) bool {
	return fc.Func(ctx)
}

// String returns a string representation
func (fc *FuncCondition) String() string {
	return "FuncCondition:" + fc.Name
}

// NewFuncCondition creates a new function-based condition
func NewFuncCondition(name string, fn CustomConditionFunc) *FuncCondition {
	return &FuncCondition{
		Name: name,
		Func: fn,
	}
}

// AndCondition requires all sub-conditions to be true
type AndCondition struct {
	Conditions []Condition
}

// Evaluate checks if all conditions are satisfied
func (ac *AndCondition) Evaluate(ctx *EvaluationContext) bool {
	for _, cond := range ac.Conditions {
		if !cond.Evaluate(ctx) {
			return false
		}
	}
	return true
}

// String returns a string representation
func (ac *AndCondition) String() string {
	return "AndCondition"
}

// OrCondition requires at least one sub-condition to be true
type OrCondition struct {
	Conditions []Condition
}

// Evaluate checks if any condition is satisfied
func (oc *OrCondition) Evaluate(ctx *EvaluationContext) bool {
	for _, cond := range oc.Conditions {
		if cond.Evaluate(ctx) {
			return true
		}
	}
	return false
}

// String returns a string representation
func (oc *OrCondition) String() string {
	return "OrCondition"
}

// NotCondition inverts a condition
type NotCondition struct {
	Condition Condition
}

// Evaluate inverts the result of the wrapped condition
func (nc *NotCondition) Evaluate(ctx *EvaluationContext) bool {
	return !nc.Condition.Evaluate(ctx)
}

// String returns a string representation
func (nc *NotCondition) String() string {
	return "NotCondition"
}
