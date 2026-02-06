package taint_test

import (
	"testing"

	"github.com/danielthedm/promptsec/guard/taint"
	"github.com/danielthedm/promptsec/internal/core"
)

func TestSetsTrustLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    core.TrustLevel
		expected core.TrustLevel
	}{
		{"untrusted", core.Untrusted, core.Untrusted},
		{"unknown", core.Unknown, core.Unknown},
		{"trusted", core.Trusted, core.Trusted},
		{"system", core.System, core.System},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewContext("test input")
			g := taint.New(&taint.Options{Level: tt.level, Source: "test"})
			next := func(c *core.Context) {}

			g.Execute(ctx, next)

			if ctx.TrustLevel != tt.expected {
				t.Errorf("expected trust level %v, got %v", tt.expected, ctx.TrustLevel)
			}
		})
	}
}

func TestStoresMetadata(t *testing.T) {
	ctx := core.NewContext("user input here")
	g := taint.New(&taint.Options{Level: core.Untrusted, Source: "user"})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("tainted_input")
	if !ok {
		t.Fatal("expected 'tainted_input' metadata to be set")
	}

	ts, ok := v.(*taint.TaintedString)
	if !ok {
		t.Fatalf("expected *taint.TaintedString, got %T", v)
	}

	if ts.Value != "user input here" {
		t.Errorf("expected tainted value %q, got %q", "user input here", ts.Value)
	}
	if ts.TrustLevel != core.Untrusted {
		t.Errorf("expected trust level Untrusted, got %v", ts.TrustLevel)
	}
	if ts.Source != "user" {
		t.Errorf("expected source 'user', got %q", ts.Source)
	}
}

func TestTaintedStringCanUseIn(t *testing.T) {
	untrusted := taint.NewTaintedString("data", core.Untrusted, "external")
	trusted := taint.NewTaintedString("data", core.Trusted, "internal")
	system := taint.NewTaintedString("data", core.System, "system")

	// Untrusted cannot be used where Trusted is required
	if untrusted.CanUseIn(core.Trusted) {
		t.Error("expected untrusted string to not be usable in trusted context")
	}

	// Untrusted can be used where Untrusted is required
	if !untrusted.CanUseIn(core.Untrusted) {
		t.Error("expected untrusted string to be usable in untrusted context")
	}

	// Trusted can be used where Trusted is required
	if !trusted.CanUseIn(core.Trusted) {
		t.Error("expected trusted string to be usable in trusted context")
	}

	// Trusted cannot be used where System is required
	if trusted.CanUseIn(core.System) {
		t.Error("expected trusted string to not be usable in system context")
	}

	// System can be used anywhere
	if !system.CanUseIn(core.System) {
		t.Error("expected system string to be usable in system context")
	}
	if !system.CanUseIn(core.Untrusted) {
		t.Error("expected system string to be usable in untrusted context")
	}
}

func TestCombine(t *testing.T) {
	ts1 := taint.NewTaintedString("hello ", core.Trusted, "internal")
	ts2 := taint.NewTaintedString("world", core.Untrusted, "external")

	combined := taint.Combine(ts1, ts2)

	if combined.Value != "hello world" {
		t.Errorf("expected combined value 'hello world', got %q", combined.Value)
	}

	// Combined trust level should be the lowest (Untrusted)
	if combined.TrustLevel != core.Untrusted {
		t.Errorf("expected combined trust level Untrusted, got %v", combined.TrustLevel)
	}

	if combined.Source != "combined" {
		t.Errorf("expected combined source 'combined', got %q", combined.Source)
	}
}

func TestCombineEmpty(t *testing.T) {
	combined := taint.Combine()

	if combined.Value != "" {
		t.Errorf("expected empty combined value, got %q", combined.Value)
	}
	if combined.TrustLevel != core.Untrusted {
		t.Errorf("expected Untrusted level for empty combine, got %v", combined.TrustLevel)
	}
}

func TestCombineSameTrust(t *testing.T) {
	ts1 := taint.NewTaintedString("a", core.System, "sys1")
	ts2 := taint.NewTaintedString("b", core.System, "sys2")

	combined := taint.Combine(ts1, ts2)

	if combined.TrustLevel != core.System {
		t.Errorf("expected System trust level when combining two System-level strings, got %v",
			combined.TrustLevel)
	}
}

func TestElevate(t *testing.T) {
	ts := taint.NewTaintedString("data", core.Untrusted, "external")

	elevated := ts.Elevate(core.Trusted)
	if elevated.TrustLevel != core.Trusted {
		t.Errorf("expected elevated trust level Trusted, got %v", elevated.TrustLevel)
	}
	if elevated.Value != "data" {
		t.Errorf("expected value to be preserved after elevation, got %q", elevated.Value)
	}
	if elevated.Source != "external" {
		t.Errorf("expected source to be preserved after elevation, got %q", elevated.Source)
	}

	// Elevating to same or lower level should return unchanged
	sameLevel := ts.Elevate(core.Untrusted)
	if sameLevel != ts {
		t.Error("expected same TaintedString when elevating to same level")
	}

	lowerLevel := elevated.Elevate(core.Unknown)
	if lowerLevel != elevated {
		t.Error("expected same TaintedString when elevating to lower level")
	}
}

func TestTaintedStringString(t *testing.T) {
	ts := taint.NewTaintedString("hello", core.Trusted, "test")
	if ts.String() != "hello" {
		t.Errorf("expected String() to return 'hello', got %q", ts.String())
	}
}

func TestCallsNext(t *testing.T) {
	ctx := core.NewContext("test input")
	g := taint.New(nil)
	called := false
	next := func(c *core.Context) {
		called = true
	}

	g.Execute(ctx, next)

	if !called {
		t.Error("expected next function to be called")
	}
}

func TestDefaultOptions(t *testing.T) {
	ctx := core.NewContext("test input")
	g := taint.New(nil) // nil opts should default to Untrusted
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if ctx.TrustLevel != core.Untrusted {
		t.Errorf("expected default trust level Untrusted, got %v", ctx.TrustLevel)
	}
}

func TestGuardName(t *testing.T) {
	g := taint.New(nil)
	if g.Name() != "taint" {
		t.Errorf("expected guard name 'taint', got %q", g.Name())
	}
}

func TestTaintedAtIsSet(t *testing.T) {
	ts := taint.NewTaintedString("data", core.Trusted, "source")
	if ts.TaintedAt.IsZero() {
		t.Error("expected TaintedAt to be set to a non-zero time")
	}
}
