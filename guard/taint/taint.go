package taint

import (
	"time"

	"github.com/danielthedm/promptsec/internal/core"
)

// Options configures the taint tracking guard.
type Options struct {
	// Level is the trust level to assign to the input.
	Level core.TrustLevel
	// Source identifies where the input originated (e.g. "user", "api", "webhook").
	Source string
}

// Guard implements taint tracking / data provenance by attaching a TaintedString
// to the pipeline context. This allows downstream guards and application code to
// make trust-aware decisions based on the origin and trust level of the input.
type Guard struct {
	opts Options
}

// New creates a taint tracking guard with the given options. If opts is nil,
// the guard defaults to Untrusted level with an empty source.
func New(opts *Options) *Guard {
	if opts == nil {
		opts = &Options{
			Level:  core.Untrusted,
			Source: "",
		}
	}
	return &Guard{opts: *opts}
}

// Name returns the identifier for this guard.
func (g *Guard) Name() string { return "taint" }

// Execute applies taint tracking to the pipeline context. It creates a
// TaintedString from the current input, sets the context trust level, stores
// the tainted value in metadata, and passes control to the next guard.
func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	ts := &TaintedString{
		Value:      ctx.Input,
		TrustLevel: g.opts.Level,
		Source:     g.opts.Source,
		TaintedAt:  time.Now(),
	}

	ctx.TrustLevel = g.opts.Level
	ctx.SetMeta("tainted_input", ts)

	next(ctx)
}
