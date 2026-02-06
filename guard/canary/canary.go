// Package canary implements canary token injection and leakage detection for
// prompt injection defense. A canary token is a unique, secret string embedded
// into user input before it is sent to an LLM. If the LLM output contains the
// canary token (or a recognisable fragment), it indicates that the model is
// leaking input data -- a strong signal of prompt exfiltration or injection
// attack success.
//
// Two guards are provided:
//
//   - Guard injects a canary token into ctx.Input and stores it in metadata.
//   - DetectorGuard (an output guard) checks LLM output for token leakage.
package canary

import (
	"github.com/danielthedm/promptsec/internal/core"
)

// defaultLength is the number of random bytes used for hex token generation.
// 16 bytes yields a 32-character hex string.
const defaultLength = 16

// defaultPrefix is prepended to every generated canary token so that it is
// easy to identify programmatically.
const defaultPrefix = "CANARY_"

// metaKeyToken is the metadata key where the canary token is stored.
const metaKeyToken = "canary_token"

// Options controls canary token generation and detection behaviour.
type Options struct {
	// Format selects the token format: hex, UUID, or alphanumeric word.
	// Default: CanaryHex.
	Format core.CanaryFormat

	// Length is the number of random bytes (hex) or characters (word) used
	// when generating the token body. Ignored for UUID format. Default: 16.
	Length int

	// Prefix is prepended to the generated token. Default: "CANARY_".
	Prefix string
}

// defaults fills zero-valued fields with sensible defaults.
func (o *Options) defaults() {
	if o.Length <= 0 {
		o.Length = defaultLength
	}
	if o.Prefix == "" {
		o.Prefix = defaultPrefix
	}
}

// Guard is an input guard that generates a canary token, embeds it in
// ctx.Input, and stores it in ctx.Metadata for later verification by
// DetectorGuard.
type Guard struct {
	opts  Options
	token string
}

// New creates a canary injection guard. If opts is nil, defaults are used.
func New(opts *Options) *Guard {
	o := Options{
		Format: core.CanaryHex,
		Length: defaultLength,
		Prefix: defaultPrefix,
	}
	if opts != nil {
		o = *opts
		o.defaults()
	}
	return &Guard{opts: o}
}

// Name returns the guard identifier.
func (g *Guard) Name() string { return "canary" }

// Execute generates a fresh canary token, injects it into ctx.Input, stores
// the token in metadata, and calls the next guard in the pipeline.
func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	g.token = generateToken(g.opts.Format, g.opts.Length, g.opts.Prefix)

	ctx.Input = injectToken(ctx.Input, g.token)
	ctx.SetMeta(metaKeyToken, g.token)

	next(ctx)
}
