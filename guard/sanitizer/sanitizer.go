// Package sanitizer implements an input sanitization guard that cleans
// potentially dangerous content from user input before it reaches downstream
// guards or the LLM. It can strip zero-width characters, normalize
// homoglyph/confusable characters, decode encoded payloads (base64, hex
// escapes), and remove arbitrary regexp patterns.
//
// Unlike the heuristic guard which only detects encoding attacks, the
// sanitizer actively rewrites ctx.Input so that later guards operate on
// a canonical, decoded form of the text.
package sanitizer

import (
	"regexp"

	"github.com/danielthedm/promptsec/internal/core"
	intu "github.com/danielthedm/promptsec/internal/unicode"
)

// Options controls which sanitization steps are applied.
type Options struct {
	// Normalize enables both zero-width stripping and confusable
	// normalization in a single flag. When true, StripZeroWidth and
	// Dehomoglyph are implicitly enabled.
	Normalize bool

	// Dehomoglyph replaces confusable characters (Cyrillic/Greek look-alikes,
	// fullwidth Latin, etc.) with their ASCII equivalents.
	Dehomoglyph bool

	// StripZeroWidth removes zero-width and invisible Unicode characters
	// that can be used to smuggle content past pattern-matching guards.
	StripZeroWidth bool

	// DecodePayloads detects and decodes base64 blocks and hex escape
	// sequences, replacing them with their decoded plaintext when the
	// result is valid UTF-8.
	DecodePayloads bool

	// StripPatterns is a list of regexp patterns whose matches will be
	// removed from the input.
	StripPatterns []string
}

// Guard performs input sanitization as part of the promptsec guard pipeline.
type Guard struct {
	opts     Options
	compiled []*regexp.Regexp
}

// New creates a sanitizer guard. If opts is nil, no sanitization is performed
// (the guard becomes a no-op pass-through).
func New(opts *Options) *Guard {
	g := &Guard{}
	if opts != nil {
		g.opts = *opts
		// Pre-compile strip patterns so Execute does not pay compilation
		// cost on every call.
		for _, p := range opts.StripPatterns {
			if re, err := regexp.Compile(p); err == nil {
				g.compiled = append(g.compiled, re)
			}
		}
	}
	return g
}

// Name returns the guard identifier used in threat reports.
func (g *Guard) Name() string { return "sanitizer" }

// Execute runs all enabled sanitization steps on ctx.Input, records any
// threats detected along the way, stores the original input in metadata,
// and calls the next guard in the pipeline.
func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	original := ctx.Input
	sanitized := ctx.Input

	// 1. Strip zero-width / invisible characters.
	if g.opts.StripZeroWidth || g.opts.Normalize {
		result, changed := normalizeInput(sanitized)
		if changed {
			ctx.AddThreat(core.Threat{
				Type:     core.ThreatEncodingAttack,
				Severity: 0.3,
				Message:  "input contained zero-width or invisible characters that were stripped",
				Guard:    g.Name(),
			})
			sanitized = result
		}
	}

	// 2. Normalize confusable / homoglyph characters.
	if g.opts.Dehomoglyph || g.opts.Normalize {
		hasSuspicious := intu.HasSuspiciousConfusables(sanitized)
		result, changed := dehomoglyph(sanitized)
		if changed {
			// Only report a threat for actual homoglyph attacks (Cyrillic,
			// Greek, fullwidth), not for normal accented Latin characters
			// (ä, ö, ü, é, etc.) found in European languages.
			if hasSuspicious {
				ctx.AddThreat(core.Threat{
					Type:     core.ThreatEncodingAttack,
					Severity: 0.5,
					Message:  "input contained confusable/homoglyph characters that were normalized",
					Guard:    g.Name(),
				})
			}
			sanitized = result
		}
	}

	// 3. Decode encoded payloads (base64, hex escapes).
	if g.opts.DecodePayloads {
		result, segments := decodePayloads(sanitized)
		if len(segments) > 0 {
			for _, seg := range segments {
				ctx.AddThreat(core.Threat{
					Type:     core.ThreatEncodingAttack,
					Severity: 0.7,
					Message:  "encoded payload was decoded and replaced: " + seg.kind,
					Guard:    g.Name(),
					Match:    seg.encoded,
					Start:    seg.start,
					End:      seg.end,
				})
			}
			sanitized = result
		}
	}

	// 4. Strip custom regexp patterns.
	if len(g.compiled) > 0 {
		for _, re := range g.compiled {
			sanitized = re.ReplaceAllString(sanitized, "")
		}
	}

	// 5. Update the context with sanitized input and preserve original.
	ctx.Input = sanitized
	ctx.SetMeta("pre_sanitize", original)

	next(ctx)
}
