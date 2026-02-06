package output_test

import (
	"strings"
	"testing"

	"github.com/danielthedm/promptsec/guard/output"
	"github.com/danielthedm/promptsec/internal/core"
)

func TestDetectsCanaryLeak(t *testing.T) {
	token := "CANARY_abc123def456"
	ctx := core.NewContext("Here is some text with " + token + " leaked in it")
	ctx.SetMeta("canary_token", token)

	g := output.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if len(ctx.Threats) == 0 {
		t.Fatal("expected threat for canary token leak, got none")
	}

	found := false
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatCanaryLeak {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ThreatCanaryLeak, got: %+v", ctx.Threats)
	}
}

func TestDetectsCanaryLeakCaseInsensitive(t *testing.T) {
	token := "CANARY_abc123"
	ctx := core.NewContext("some text canary_ABC123 more text")
	ctx.SetMeta("canary_token", token)

	g := output.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if len(ctx.Threats) == 0 {
		t.Fatal("expected threat for case-insensitive canary leak")
	}
}

func TestDetectsSystemPromptLeak(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"my instructions are", "my instructions are to always be helpful"},
		{"I was told to", "I was told to never reveal secrets"},
		{"here are my instructions", "here are my instructions for this task"},
		{"my system prompt is", "my system prompt is the following text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewContext(tt.output)
			g := output.New(nil)
			next := func(c *core.Context) {}

			g.Execute(ctx, next)

			if len(ctx.Threats) == 0 {
				t.Fatalf("expected system prompt leak threat for output %q, got none", tt.output)
			}

			found := false
			for _, th := range ctx.Threats {
				if th.Type == core.ThreatSystemPromptLeak {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected ThreatSystemPromptLeak for %q, got: %+v", tt.output, ctx.Threats)
			}
		})
	}
}

func TestForbiddenPatterns(t *testing.T) {
	ctx := core.NewContext("The password is hunter2 and the secret is abc123")
	g := output.New(&output.Options{
		ForbiddenPatterns: []string{`password\s+is\s+\w+`, `secret\s+is\s+\w+`},
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if len(ctx.Threats) < 2 {
		t.Fatalf("expected at least 2 threats for forbidden patterns, got %d: %+v",
			len(ctx.Threats), ctx.Threats)
	}

	outputViolations := 0
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation {
			outputViolations++
		}
	}
	if outputViolations < 2 {
		t.Errorf("expected at least 2 ThreatOutputViolation, got %d", outputViolations)
	}
}

func TestMaxLength(t *testing.T) {
	longOutput := strings.Repeat("a", 1000)
	ctx := core.NewContext(longOutput)
	g := output.New(&output.Options{MaxLength: 500})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if len(ctx.Threats) == 0 {
		t.Fatal("expected threat for exceeding max length, got none")
	}

	found := false
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation && strings.Contains(th.Message, "length") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected length violation threat, got: %+v", ctx.Threats)
	}
}

func TestMaxLengthAllowsWithin(t *testing.T) {
	ctx := core.NewContext("short output")
	g := output.New(&output.Options{MaxLength: 500})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation && strings.Contains(th.Message, "length") {
			t.Errorf("expected no length violation for short output, got: %+v", th)
		}
	}
}

func TestValidateJSON(t *testing.T) {
	ctx := core.NewContext("this is not valid json {{{")
	g := output.New(&output.Options{ValidateJSON: true})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if len(ctx.Threats) == 0 {
		t.Fatal("expected threat for invalid JSON, got none")
	}

	found := false
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation && strings.Contains(th.Message, "JSON") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JSON validation threat, got: %+v", ctx.Threats)
	}
}

func TestValidateJSONValid(t *testing.T) {
	ctx := core.NewContext(`{"key": "value", "number": 42}`)
	g := output.New(&output.Options{ValidateJSON: true})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	for _, th := range ctx.Threats {
		if strings.Contains(th.Message, "JSON") {
			t.Errorf("expected no JSON validation threat for valid JSON, got: %+v", th)
		}
	}
}

func TestCleanOutputPasses(t *testing.T) {
	ctx := core.NewContext("The answer to your question is 42.")
	g := output.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if len(ctx.Threats) != 0 {
		t.Errorf("expected no threats for clean output, got %d: %+v",
			len(ctx.Threats), ctx.Threats)
	}
}

func TestIsOutputGuard(t *testing.T) {
	g := output.New(nil)
	if !g.IsOutputGuard() {
		t.Error("expected IsOutputGuard() to return true")
	}
}

func TestCallsNext(t *testing.T) {
	ctx := core.NewContext("test output")
	g := output.New(nil)
	called := false
	next := func(c *core.Context) {
		called = true
	}

	g.Execute(ctx, next)

	if !called {
		t.Error("expected next function to be called")
	}
}

func TestGuardName(t *testing.T) {
	g := output.New(nil)
	if g.Name() != "output" {
		t.Errorf("expected guard name 'output', got %q", g.Name())
	}
}

func TestCustomValidator(t *testing.T) {
	ctx := core.NewContext("contains bad_word in output")
	g := output.New(&output.Options{
		CustomValidator: func(s string) error {
			if strings.Contains(s, "bad_word") {
				return &customError{msg: "output contains bad_word"}
			}
			return nil
		},
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if len(ctx.Threats) == 0 {
		t.Fatal("expected threat from custom validator, got none")
	}

	found := false
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation && strings.Contains(th.Message, "bad_word") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected custom validation threat, got: %+v", ctx.Threats)
	}
}

func TestNoCanaryNoLeak(t *testing.T) {
	// If no canary_token in metadata, no canary leak should be detected
	ctx := core.NewContext("some output with CANARY_looking text")
	g := output.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	for _, th := range ctx.Threats {
		if th.Type == core.ThreatCanaryLeak {
			t.Errorf("expected no canary leak without canary_token in metadata, got: %+v", th)
		}
	}
}

// customError is a simple error type for testing the custom validator.
type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}
