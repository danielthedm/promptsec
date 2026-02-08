package spotlight_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/danielthedm/promptsec/guard/spotlight"
	"github.com/danielthedm/promptsec/internal/core"
)

func TestDelimitModifiesInput(t *testing.T) {
	input := "Hello, how are you?"
	ctx := core.NewContext(input)
	g := spotlight.NewDelimit(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if ctx.Input == input {
		t.Fatal("expected input to be modified by delimit guard")
	}
	if !strings.Contains(ctx.Input, input) {
		t.Errorf("expected modified input to contain original text %q, got %q", input, ctx.Input)
	}
	// Should be wrapped in <delimiter>...</delimiter> tags
	if !strings.HasPrefix(ctx.Input, "<") {
		t.Errorf("expected input to start with '<', got %q", ctx.Input[:20])
	}
	if !strings.HasSuffix(ctx.Input, ">") {
		t.Errorf("expected input to end with '>', got %q", ctx.Input[len(ctx.Input)-20:])
	}
}

func TestDelimitSetsMetadata(t *testing.T) {
	ctx := core.NewContext("test input")
	g := spotlight.NewDelimit(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("spotlight_instruction")
	if !ok {
		t.Fatal("expected 'spotlight_instruction' metadata to be set")
	}
	instruction, ok := v.(string)
	if !ok {
		t.Fatal("expected 'spotlight_instruction' to be a string")
	}
	if instruction == "" {
		t.Error("expected non-empty spotlight instruction")
	}
	if !strings.Contains(instruction, "delimiter") {
		t.Errorf("expected instruction to mention 'delimiter', got %q", instruction)
	}
}

func TestDatamarkInsertsTokens(t *testing.T) {
	input := "hello world test"
	ctx := core.NewContext(input)
	customToken := "^"
	g := spotlight.NewDatamark(&spotlight.DatamarkOptions{Token: customToken})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	// Words should be separated by the custom token instead of spaces
	expected := "hello^world^test"
	if ctx.Input != expected {
		t.Errorf("expected input %q, got %q", expected, ctx.Input)
	}
}

func TestDatamarkDefaultToken(t *testing.T) {
	input := "hello world"
	ctx := core.NewContext(input)
	g := spotlight.NewDatamark(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	// Default token is PUA char U+E000
	puaChar := "\uE000"
	if !strings.Contains(ctx.Input, puaChar) {
		t.Errorf("expected input to contain PUA character U+E000, got %q", ctx.Input)
	}
	expected := "hello" + puaChar + "world"
	if ctx.Input != expected {
		t.Errorf("expected input %q, got %q", expected, ctx.Input)
	}
}

func TestDatamarkSetsMetadata(t *testing.T) {
	ctx := core.NewContext("hello world")
	g := spotlight.NewDatamark(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("spotlight_instruction")
	if !ok {
		t.Fatal("expected 'spotlight_instruction' metadata to be set")
	}
	instruction, ok := v.(string)
	if !ok || instruction == "" {
		t.Error("expected non-empty spotlight instruction")
	}
}

func TestEncodeBase64(t *testing.T) {
	input := "Hello, world!"
	ctx := core.NewContext(input)
	g := spotlight.NewEncode(&spotlight.EncodeOptions{Method: "base64"})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	// The input should now be base64 encoded
	decoded, err := base64.StdEncoding.DecodeString(ctx.Input)
	if err != nil {
		t.Fatalf("expected input to be valid base64, got error: %v", err)
	}
	if string(decoded) != input {
		t.Errorf("expected decoded input %q, got %q", input, string(decoded))
	}
}

func TestEncodeROT13(t *testing.T) {
	input := "Hello"
	ctx := core.NewContext(input)
	g := spotlight.NewEncode(&spotlight.EncodeOptions{Method: "rot13"})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	// ROT13 of "Hello" is "Uryyb"
	expected := "Uryyb"
	if ctx.Input != expected {
		t.Errorf("expected ROT13 encoded %q, got %q", expected, ctx.Input)
	}
}

func TestEncodeDefaultIsBase64(t *testing.T) {
	input := "test"
	ctx := core.NewContext(input)
	g := spotlight.NewEncode(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	decoded, err := base64.StdEncoding.DecodeString(ctx.Input)
	if err != nil {
		t.Fatalf("expected default encoding to be base64, got error: %v", err)
	}
	if string(decoded) != input {
		t.Errorf("expected decoded %q, got %q", input, string(decoded))
	}
}

func TestEncodeSetsMetadata(t *testing.T) {
	ctx := core.NewContext("test")
	g := spotlight.NewEncode(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	v, ok := ctx.GetMeta("spotlight_instruction")
	if !ok {
		t.Fatal("expected 'spotlight_instruction' metadata to be set")
	}
	instruction, ok := v.(string)
	if !ok || instruction == "" {
		t.Error("expected non-empty spotlight instruction")
	}
}

func TestCallsNext(t *testing.T) {
	tests := []struct {
		name  string
		guard core.Guard
	}{
		{"delimit", spotlight.NewDelimit(nil)},
		{"datamark", spotlight.NewDatamark(nil)},
		{"encode", spotlight.NewEncode(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewContext("test input")
			called := false
			next := func(c *core.Context) {
				called = true
			}

			tt.guard.Execute(ctx, next)

			if !called {
				t.Errorf("expected next function to be called for %s guard", tt.name)
			}
		})
	}
}

func TestDelimitGuardName(t *testing.T) {
	g := spotlight.NewDelimit(nil)
	if g.Name() != "spotlight:delimit" {
		t.Errorf("expected name 'spotlight:delimit', got %q", g.Name())
	}
}

func TestDatamarkGuardName(t *testing.T) {
	g := spotlight.NewDatamark(nil)
	if g.Name() != "spotlight:datamark" {
		t.Errorf("expected name 'spotlight:datamark', got %q", g.Name())
	}
}

func TestEncodeGuardName(t *testing.T) {
	g := spotlight.NewEncode(nil)
	if g.Name() != "spotlight:encode" {
		t.Errorf("expected name 'spotlight:encode', got %q", g.Name())
	}
}

func TestDelimitEmptyInput(t *testing.T) {
	ctx := core.NewContext("")
	g := spotlight.NewDelimit(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if !strings.HasPrefix(ctx.Input, "<") {
		t.Error("expected empty input to still be wrapped in delimiters")
	}
	if !strings.HasSuffix(ctx.Input, ">") {
		t.Error("expected input to end with closing delimiter")
	}
}

func TestDatamarkEmptyInput(t *testing.T) {
	ctx := core.NewContext("")
	g := spotlight.NewDatamark(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if ctx.Input != "" {
		t.Errorf("expected empty input to remain empty after datamark, got %q", ctx.Input)
	}
}

func TestEncodeEmptyInput(t *testing.T) {
	ctx := core.NewContext("")
	g := spotlight.NewEncode(nil)
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	decoded, err := base64.StdEncoding.DecodeString(ctx.Input)
	if err != nil {
		t.Fatalf("expected valid base64 for empty input, got error: %v", err)
	}
	if string(decoded) != "" {
		t.Errorf("expected decoded empty string, got %q", string(decoded))
	}
}

func TestDatamarkMultiWordSpecialChars(t *testing.T) {
	input := "hello, world! test-case 42"
	ctx := core.NewContext(input)
	g := spotlight.NewDatamark(&spotlight.DatamarkOptions{Token: "|"})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	expected := "hello,|world!|test-case|42"
	if ctx.Input != expected {
		t.Errorf("expected %q, got %q", expected, ctx.Input)
	}
}

func TestDelimitCustomLength(t *testing.T) {
	ctx := core.NewContext("test input")
	g := spotlight.NewDelimit(&spotlight.DelimitOptions{DelimiterLength: 16})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	if !strings.HasPrefix(ctx.Input, "<") {
		t.Fatal("expected input to start with <")
	}
	closingIdx := strings.Index(ctx.Input, ">")
	delimiter := ctx.Input[1:closingIdx]
	if len(delimiter) != 32 {
		t.Errorf("expected 32-char delimiter for 16-byte length, got %d: %q", len(delimiter), delimiter)
	}
}

func TestROT13RoundTrip(t *testing.T) {
	input := "Hello World! This is a test 123."

	ctx1 := core.NewContext(input)
	g := spotlight.NewEncode(&spotlight.EncodeOptions{Method: "rot13"})
	next := func(c *core.Context) {}
	g.Execute(ctx1, next)

	encoded := ctx1.Input
	if encoded == input {
		t.Error("expected ROT13 to change input")
	}

	ctx2 := core.NewContext(encoded)
	g.Execute(ctx2, next)

	if ctx2.Input != input {
		t.Errorf("expected ROT13 round-trip to restore input, got %q", ctx2.Input)
	}
}

func TestEncodeBase64WithUnicode(t *testing.T) {
	input := "Hello with unicode chars"
	ctx := core.NewContext(input)
	g := spotlight.NewEncode(&spotlight.EncodeOptions{Method: "base64"})
	next := func(c *core.Context) {}

	g.Execute(ctx, next)

	decoded, err := base64.StdEncoding.DecodeString(ctx.Input)
	if err != nil {
		t.Fatalf("expected valid base64 encoding, got error: %v", err)
	}
	if string(decoded) != input {
		t.Errorf("expected round-trip to restore input, got %q", string(decoded))
	}
}
