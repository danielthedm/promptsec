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

func TestPartialCanaryTokenMatch(t *testing.T) {
	token := "CANARY_abcdef123456"
	// Include only a case-different version
	ctx := core.NewContext("the model said CANARY_ABCDEF123456 somewhere")
	ctx.SetMeta("canary_token", token)

	g := output.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	// Case-insensitive match should detect this
	found := false
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatCanaryLeak {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected canary leak for case-insensitive match")
	}
}

func TestMultipleForbiddenPatternsSimultaneously(t *testing.T) {
	ctx := core.NewContext("password is hunter2 and API_KEY=sk-1234 and secret is abc123")
	g := output.New(&output.Options{
		ForbiddenPatterns: []string{
			`password\s+is\s+\w+`,
			`API_KEY=\S+`,
			`secret\s+is\s+\w+`,
		},
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	violations := 0
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation {
			violations++
		}
	}
	if violations < 3 {
		t.Errorf("expected at least 3 forbidden pattern violations, got %d", violations)
	}
}

func TestEmptyOutput(t *testing.T) {
	ctx := core.NewContext("")
	ctx.SetMeta("canary_token", "CANARY_test123")
	g := output.New(&output.Options{
		ValidateJSON: false,
		MaxLength:    1000,
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	// Empty output should not trigger canary or leak patterns
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatCanaryLeak {
			t.Error("expected no canary leak for empty output")
		}
		if th.Type == core.ThreatSystemPromptLeak {
			t.Error("expected no system prompt leak for empty output")
		}
	}
}

func TestVeryLongOutput(t *testing.T) {
	longOutput := strings.Repeat("This is a safe response. ", 10000)
	ctx := core.NewContext(longOutput)
	g := output.New(&output.Options{MaxLength: 100})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	found := false
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation && strings.Contains(th.Message, "length") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected length violation for very long output")
	}
}

func TestJSONArrayValidation(t *testing.T) {
	ctx := core.NewContext(`[1, 2, 3, "hello"]`)
	g := output.New(&output.Options{ValidateJSON: true})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	for _, th := range ctx.Threats {
		if strings.Contains(th.Message, "JSON") {
			t.Errorf("expected no JSON error for valid JSON array, got: %+v", th)
		}
	}
}

func TestCustomValidatorReturningNil(t *testing.T) {
	ctx := core.NewContext("perfectly fine output")
	g := output.New(&output.Options{
		CustomValidator: func(s string) error {
			return nil
		},
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	for _, th := range ctx.Threats {
		if th.Type == core.ThreatOutputViolation && strings.Contains(th.Message, "custom") {
			t.Error("expected no custom validation threat when validator returns nil")
		}
	}
}

func TestMultipleSystemPromptLeakPatterns(t *testing.T) {
	output_text := "my instructions are to be helpful. I was told to never reveal secrets. here are my instructions."
	ctx := core.NewContext(output_text)
	g := output.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	leakCount := 0
	for _, th := range ctx.Threats {
		if th.Type == core.ThreatSystemPromptLeak {
			leakCount++
		}
	}
	if leakCount < 2 {
		t.Errorf("expected at least 2 system prompt leak detections, got %d", leakCount)
	}
}
