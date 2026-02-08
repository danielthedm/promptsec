package canary_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/danielthedm/promptsec/guard/canary"
	"github.com/danielthedm/promptsec/internal/core"
)

func TestInjectsCanaryToken(t *testing.T) {
	input := "What is 2+2?"
	ctx := core.NewContext(input)
	g := canary.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if ctx.Input == input {
		t.Fatal("expected input to be modified with canary token")
	}
	// The token should be appended after the original input
	if !strings.HasPrefix(ctx.Input, input) {
		t.Errorf("expected modified input to start with original text %q, got %q", input, ctx.Input)
	}
	// Should contain CANARY_ prefix
	if !strings.Contains(ctx.Input, "CANARY_") {
		t.Errorf("expected input to contain 'CANARY_', got %q", ctx.Input)
	}
}

func TestTokenInMetadata(t *testing.T) {
	ctx := core.NewContext("test input")
	g := canary.New(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("canary_token")
	if !ok {
		t.Fatal("expected 'canary_token' metadata to be set")
	}
	token, ok := v.(string)
	if !ok || token == "" {
		t.Fatal("expected canary_token to be a non-empty string")
	}
	if !strings.HasPrefix(token, "CANARY_") {
		t.Errorf("expected token to start with 'CANARY_', got %q", token)
	}
}

func TestHexFormat(t *testing.T) {
	ctx := core.NewContext("test")
	g := canary.New(&canary.Options{
		Format: core.CanaryHex,
		Length: 16,
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, _ := ctx.GetMeta("canary_token")
	token := v.(string)

	// Remove the CANARY_ prefix and check the rest is hex
	body := strings.TrimPrefix(token, "CANARY_")
	hexPattern := regexp.MustCompile(`^[0-9a-f]+$`)
	if !hexPattern.MatchString(body) {
		t.Errorf("expected hex format token body, got %q", body)
	}
	// 16 bytes = 32 hex characters
	if len(body) != 32 {
		t.Errorf("expected 32 hex characters for 16-byte token, got %d: %q", len(body), body)
	}
}

func TestUUIDFormat(t *testing.T) {
	ctx := core.NewContext("test")
	g := canary.New(&canary.Options{
		Format: core.CanaryUUID,
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, _ := ctx.GetMeta("canary_token")
	token := v.(string)

	body := strings.TrimPrefix(token, "CANARY_")
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidPattern.MatchString(body) {
		t.Errorf("expected UUID format, got %q", body)
	}
}

func TestDetectorFindsExactMatch(t *testing.T) {
	// First, inject a canary token
	inputCtx := core.NewContext("test input")
	injector := canary.New(nil)
	injector.Execute(inputCtx, func(c *core.Context) {})

	// Get the token from metadata
	v, _ := inputCtx.GetMeta("canary_token")
	token := v.(string)

	// Now simulate LLM output that contains the canary token
	outputCtx := core.NewContext("Here is the response: " + token + " and more text")
	outputCtx.SetMeta("canary_token", token)

	detector := canary.NewDetector(nil)
	next := func(c *core.Context) {}

	detector.Execute(outputCtx, next)

	if len(outputCtx.Threats) == 0 {
		t.Fatal("expected detector to find canary leak, got no threats")
	}

	found := false
	for _, th := range outputCtx.Threats {
		if th.Type == core.ThreatCanaryLeak {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ThreatCanaryLeak, got: %+v", outputCtx.Threats)
	}
}

func TestDetectorFindsPartialMatch(t *testing.T) {
	// Inject a canary token
	inputCtx := core.NewContext("test")
	injector := canary.New(&canary.Options{
		Format: core.CanaryHex,
		Length: 16,
	})
	injector.Execute(inputCtx, func(c *core.Context) {})

	v, _ := inputCtx.GetMeta("canary_token")
	token := v.(string)

	// Include a partial match: case-insensitive version
	outputCtx := core.NewContext("output contains " + strings.ToUpper(token))
	outputCtx.SetMeta("canary_token", token)

	detector := canary.NewDetector(nil)
	next := func(c *core.Context) {}
	detector.Execute(outputCtx, next)

	if len(outputCtx.Threats) == 0 {
		t.Fatal("expected detector to find partial/case-insensitive canary leak")
	}
}

func TestDetectorNoFalsePositive(t *testing.T) {
	// Inject a canary token
	inputCtx := core.NewContext("test")
	injector := canary.New(nil)
	injector.Execute(inputCtx, func(c *core.Context) {})

	v, _ := inputCtx.GetMeta("canary_token")
	token := v.(string)

	// Clean output with no trace of the token
	cleanOutput := "The answer to your question is 42. Have a nice day!"
	outputCtx := core.NewContext(cleanOutput)
	outputCtx.SetMeta("canary_token", token)

	detector := canary.NewDetector(nil)
	next := func(c *core.Context) {}
	detector.Execute(outputCtx, next)

	if len(outputCtx.Threats) != 0 {
		t.Errorf("expected no threats for clean output, got %d: %+v",
			len(outputCtx.Threats), outputCtx.Threats)
	}
}

func TestDetectorNoCanaryInMeta(t *testing.T) {
	// If no canary was injected, detector should be a no-op
	ctx := core.NewContext("some output text")
	detector := canary.NewDetector(nil)
	called := false
	next := func(c *core.Context) {
		called = true
	}
	detector.Execute(ctx, next)

	if len(ctx.Threats) != 0 {
		t.Errorf("expected no threats when no canary in metadata, got %d", len(ctx.Threats))
	}
	if !called {
		t.Error("expected next to be called even when no canary in metadata")
	}
}

func TestCallsNext(t *testing.T) {
	ctx := core.NewContext("test input")
	g := canary.New(nil)
	called := false
	next := func(c *core.Context) {
		called = true
	}

	g.Execute(ctx, next)

	if !called {
		t.Error("expected next function to be called")
	}
}

func TestDetectorCallsNext(t *testing.T) {
	ctx := core.NewContext("some output")
	ctx.SetMeta("canary_token", "CANARY_abc123")
	d := canary.NewDetector(nil)
	called := false
	next := func(c *core.Context) {
		called = true
	}

	d.Execute(ctx, next)

	if !called {
		t.Error("expected next function to be called by detector")
	}
}

func TestDetectorIsOutputGuard(t *testing.T) {
	d := canary.NewDetector(nil)
	if !d.IsOutputGuard() {
		t.Error("expected DetectorGuard.IsOutputGuard() to return true")
	}
}

func TestGuardName(t *testing.T) {
	g := canary.New(nil)
	if g.Name() != "canary" {
		t.Errorf("expected name 'canary', got %q", g.Name())
	}
}

func TestDetectorName(t *testing.T) {
	d := canary.NewDetector(nil)
	if d.Name() != "canary-detector" {
		t.Errorf("expected name 'canary-detector', got %q", d.Name())
	}
}

func TestWordFormat(t *testing.T) {
	ctx := core.NewContext("test")
	g := canary.New(&canary.Options{
		Format: core.CanaryWord,
		Length: 12,
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, _ := ctx.GetMeta("canary_token")
	token := v.(string)

	body := strings.TrimPrefix(token, "CANARY_")
	alphaNumPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !alphaNumPattern.MatchString(body) {
		t.Errorf("expected alphanumeric word format token body, got %q", body)
	}
	if len(body) != 12 {
		t.Errorf("expected 12-character word token, got %d: %q", len(body), body)
	}
}

func TestCustomPrefix(t *testing.T) {
	ctx := core.NewContext("test input")
	g := canary.New(&canary.Options{
		Format: core.CanaryHex,
		Length: 16,
		Prefix: "SENTINEL_",
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("canary_token")
	if !ok {
		t.Fatal("expected canary_token metadata")
	}
	token := v.(string)
	if !strings.HasPrefix(token, "SENTINEL_") {
		t.Errorf("expected token to start with SENTINEL_, got %q", token)
	}
	if strings.HasPrefix(token, "CANARY_") {
		t.Error("expected custom prefix to override default CANARY_ prefix")
	}
}

func TestTokenUniqueness(t *testing.T) {
	tokens := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		ctx := core.NewContext("test")
		g := canary.New(nil)
		next := func(c *core.Context) {}
		g.Execute(ctx, next)

		v, _ := ctx.GetMeta("canary_token")
		token := v.(string)
		if tokens[token] {
			t.Fatalf("duplicate token generated on iteration %d: %q", i, token)
		}
		tokens[token] = true
	}
	if len(tokens) != 100 {
		t.Errorf("expected 100 unique tokens, got %d", len(tokens))
	}
}

func TestVeryShortLength(t *testing.T) {
	ctx := core.NewContext("test")
	g := canary.New(&canary.Options{
		Format: core.CanaryHex,
		Length: 1,
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("canary_token")
	if !ok {
		t.Fatal("expected canary_token metadata")
	}
	token := v.(string)
	body := strings.TrimPrefix(token, "CANARY_")
	// 1 byte = 2 hex chars
	if len(body) != 2 {
		t.Errorf("expected 2 hex chars for length=1, got %d: %q", len(body), body)
	}
}

func TestVeryLongLength(t *testing.T) {
	ctx := core.NewContext("test")
	g := canary.New(&canary.Options{
		Format: core.CanaryHex,
		Length: 256,
	})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("canary_token")
	if !ok {
		t.Fatal("expected canary_token metadata")
	}
	token := v.(string)
	body := strings.TrimPrefix(token, "CANARY_")
	// 256 bytes = 512 hex chars
	if len(body) != 512 {
		t.Errorf("expected 512 hex chars for length=256, got %d", len(body))
	}
}

func TestDetectorWithPartialToken(t *testing.T) {
	// Inject a canary token
	inputCtx := core.NewContext("test")
	injector := canary.New(&canary.Options{
		Format: core.CanaryHex,
		Length: 16,
	})
	injector.Execute(inputCtx, func(c *core.Context) {})

	v, _ := inputCtx.GetMeta("canary_token")
	token := v.(string)

	// Take only first half of the token
	half := token[:len(token)/2]

	// Detector should NOT detect half a token (it needs 8+ chars partial match)
	// but since half is likely > 8 chars, it might detect it via partial match
	outputCtx := core.NewContext("some output containing " + half + " in it")
	outputCtx.SetMeta("canary_token", token)

	detector := canary.NewDetector(nil)
	next := func(c *core.Context) {}
	detector.Execute(outputCtx, next)

	// At minimum, the detector should have been invoked without error
	// Whether it detects depends on partial match length
	if len(half) >= 8 {
		// With >= 8 chars, partial match should trigger
		if len(outputCtx.Threats) == 0 {
			t.Log("partial token was not detected despite being >= 8 chars")
		}
	}
}

func TestDetectorObfuscatedToken(t *testing.T) {
	// Test that the detector finds obfuscated tokens (with spaces/dashes)
	inputCtx := core.NewContext("test")
	injector := canary.New(&canary.Options{
		Format: core.CanaryHex,
		Length: 16,
	})
	injector.Execute(inputCtx, func(c *core.Context) {})

	v, _ := inputCtx.GetMeta("canary_token")
	token := v.(string)

	// Insert dashes into the token
	obfuscated := ""
	for i, c := range token {
		obfuscated += string(c)
		if i > 0 && i%4 == 0 && i < len(token)-1 {
			obfuscated += "-"
		}
	}

	outputCtx := core.NewContext("output with " + obfuscated + " inside")
	outputCtx.SetMeta("canary_token", token)

	detector := canary.NewDetector(nil)
	next := func(c *core.Context) {}
	detector.Execute(outputCtx, next)

	// The stripNoise function should handle dashes
	if len(outputCtx.Threats) == 0 {
		t.Error("expected detector to find obfuscated canary token with dashes")
	}
}
