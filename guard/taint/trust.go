package taint

import (
	"strings"
	"time"

	"github.com/danielthedm/promptsec/internal/core"
)

// TaintedString wraps a string value with provenance metadata, recording its
// trust level, origin source, and the time it was tainted. This enables
// downstream code to make trust-aware decisions about how the data may be used.
type TaintedString struct {
	Value      string
	TrustLevel core.TrustLevel
	Source     string
	TaintedAt  time.Time
}

// NewTaintedString creates a new TaintedString with the given value, trust
// level, and source identifier. The taint timestamp is set to the current time.
func NewTaintedString(value string, level core.TrustLevel, source string) *TaintedString {
	return &TaintedString{
		Value:      value,
		TrustLevel: level,
		Source:     source,
		TaintedAt:  time.Now(),
	}
}

// CanUseIn reports whether this tainted string meets the minimum trust level
// required for a particular context. It returns true when the string's trust
// level is greater than or equal to the required level.
func (ts *TaintedString) CanUseIn(required core.TrustLevel) bool {
	return ts.TrustLevel >= required
}

// Elevate returns a new TaintedString with a higher trust level. If the
// requested level is not higher than the current level, the original
// TaintedString is returned unchanged. Elevation preserves the original
// source and taint timestamp.
func (ts *TaintedString) Elevate(level core.TrustLevel) *TaintedString {
	if level <= ts.TrustLevel {
		return ts
	}
	return &TaintedString{
		Value:      ts.Value,
		TrustLevel: level,
		Source:     ts.Source,
		TaintedAt:  ts.TaintedAt,
	}
}

// String returns the underlying string value.
func (ts *TaintedString) String() string {
	return ts.Value
}

// Combine merges multiple TaintedString values into a single TaintedString.
// The resulting string is the concatenation of all values, and the trust level
// is set to the lowest (least trusted) level among the parts. This enforces the
// principle that combined data is only as trustworthy as its least trusted
// component. The source is set to "combined" and the timestamp to the current
// time. If no parts are provided, an empty Untrusted TaintedString is returned.
func Combine(parts ...*TaintedString) *TaintedString {
	if len(parts) == 0 {
		return NewTaintedString("", core.Untrusted, "combined")
	}

	minLevel := parts[0].TrustLevel
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Value)
		if p.TrustLevel < minLevel {
			minLevel = p.TrustLevel
		}
	}

	return &TaintedString{
		Value:      b.String(),
		TrustLevel: minLevel,
		Source:     "combined",
		TaintedAt:  time.Now(),
	}
}
