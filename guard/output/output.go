package output

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/danielthedm/promptsec/internal/core"
)

// Options configures the output guard.
type Options struct {
	// ForbiddenPatterns lists regular expression patterns that must NOT appear
	// in the LLM output. Each pattern is compiled once when New is called.
	ForbiddenPatterns []string

	// MaxLength sets the maximum allowed output length in bytes. A value of
	// zero (the default) disables length checking.
	MaxLength int

	// ValidateJSON enables strict JSON syntax validation on the output.
	ValidateJSON bool

	// CustomValidator is an optional function invoked after all built-in
	// checks. If it returns a non-nil error, a ThreatOutputViolation is added.
	CustomValidator func(string) error
}

// Guard validates LLM output for security issues including canary token
// leakage, system prompt leaks, forbidden patterns, length violations, format
// violations, and custom policy rules.
type Guard struct {
	opts     Options
	compiled []*regexp.Regexp
}

// New creates an output guard with the given options. All ForbiddenPatterns
// are compiled immediately; invalid patterns cause a panic. If opts is nil,
// a guard with default (empty) options is returned.
func New(opts *Options) *Guard {
	o := Options{}
	if opts != nil {
		o = *opts
	}
	compiled := make([]*regexp.Regexp, 0, len(o.ForbiddenPatterns))
	for _, p := range o.ForbiddenPatterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return &Guard{
		opts:     o,
		compiled: compiled,
	}
}

// Name returns the guard identifier.
func (g *Guard) Name() string { return "output" }

// IsOutputGuard marks this guard as an output-phase guard. This can be used
// by pipeline orchestrators to distinguish input guards from output guards.
func (g *Guard) IsOutputGuard() bool { return true }

// Execute runs all output validation checks against ctx.Input, which is
// expected to contain the LLM output at this stage of the pipeline.
func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	output := ctx.Input

	// 1. Canary token leak detection.
	g.checkCanary(ctx, output)

	// 2. System prompt leak pattern detection.
	g.checkSystemPromptLeaks(ctx, output)

	// 3. Forbidden pattern matching.
	g.checkForbiddenPatterns(ctx, output)

	// 4. Maximum length enforcement.
	g.checkMaxLength(ctx, output)

	// 5. JSON format validation.
	g.checkJSON(ctx, output)

	// 6. Custom validator.
	g.checkCustom(ctx, output)

	next(ctx)
}

// checkCanary looks up the canary token from metadata and reports a threat if
// the token (or a case-insensitive variant) appears in the LLM output.
func (g *Guard) checkCanary(ctx *core.Context, output string) {
	v, ok := ctx.GetMeta("canary_token")
	if !ok {
		return
	}
	token, ok := v.(string)
	if !ok || token == "" {
		return
	}

	lower := strings.ToLower(output)
	tokenLower := strings.ToLower(token)
	idx := strings.Index(lower, tokenLower)
	if idx < 0 {
		return
	}

	ctx.AddThreat(core.Threat{
		Type:     core.ThreatCanaryLeak,
		Severity: 1.0,
		Message:  "canary token detected in LLM output, indicating prompt data exfiltration",
		Guard:    "output",
		Match:    output[idx : idx+len(token)],
		Start:    idx,
		End:      idx + len(token),
	})
}

// checkSystemPromptLeaks scans the output for natural-language patterns that
// indicate the LLM is revealing its system prompt or internal instructions.
func (g *Guard) checkSystemPromptLeaks(ctx *core.Context, output string) {
	matches := checkLeaks(output)
	for _, m := range matches {
		ctx.AddThreat(core.Threat{
			Type:     core.ThreatSystemPromptLeak,
			Severity: m.severity,
			Message:  m.description,
			Guard:    "output",
			Match:    m.match,
			Start:    m.start,
			End:      m.end,
		})
	}
}

// checkForbiddenPatterns tests each compiled forbidden pattern against the
// output and records a threat for every match.
func (g *Guard) checkForbiddenPatterns(ctx *core.Context, output string) {
	for _, re := range g.compiled {
		locs := re.FindAllStringIndex(output, -1)
		for _, loc := range locs {
			ctx.AddThreat(core.Threat{
				Type:     core.ThreatOutputViolation,
				Severity: 0.8,
				Message:  fmt.Sprintf("output matches forbidden pattern: %s", re.String()),
				Guard:    "output",
				Match:    output[loc[0]:loc[1]],
				Start:    loc[0],
				End:      loc[1],
			})
		}
	}
}

// checkMaxLength reports a threat if the output exceeds the configured maximum
// length.
func (g *Guard) checkMaxLength(ctx *core.Context, output string) {
	if err := validateLength(output, g.opts.MaxLength); err != nil {
		ctx.AddThreat(core.Threat{
			Type:     core.ThreatOutputViolation,
			Severity: 0.5,
			Message:  err.Error(),
			Guard:    "output",
		})
	}
}

// checkJSON validates the output as JSON when ValidateJSON is enabled.
func (g *Guard) checkJSON(ctx *core.Context, output string) {
	if !g.opts.ValidateJSON {
		return
	}
	if err := validateJSON(output); err != nil {
		ctx.AddThreat(core.Threat{
			Type:     core.ThreatOutputViolation,
			Severity: 0.6,
			Message:  err.Error(),
			Guard:    "output",
		})
	}
}

// checkCustom runs the custom validator function, if configured, and adds a
// threat when it returns an error.
func (g *Guard) checkCustom(ctx *core.Context, output string) {
	if g.opts.CustomValidator == nil {
		return
	}
	if err := g.opts.CustomValidator(output); err != nil {
		ctx.AddThreat(core.Threat{
			Type:     core.ThreatOutputViolation,
			Severity: 0.7,
			Message:  fmt.Sprintf("custom validation failed: %v", err),
			Guard:    "output",
		})
	}
}
