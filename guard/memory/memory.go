package memory

import (
	"fmt"

	"github.com/danielthedm/promptsec/internal/core"
)

// defaultThreshold is the minimum similarity score for a stored signature to
// be considered a match.
const defaultThreshold = 0.8

// defaultMaxSignatures is the default upper bound on stored signatures when
// using the built-in in-memory store.
const defaultMaxSignatures = 10000

// Options configures the memory guard.
type Options struct {
	// Store is the storage backend for attack signatures. When nil an
	// in-memory store is used.
	Store Store

	// Threshold is the minimum similarity score (0.0-1.0) for a stored
	// signature to be considered a match. The default is 0.8.
	Threshold float64

	// MaxSignatures is the maximum number of signatures to retain in the
	// default in-memory store. Ignored when a custom Store is provided.
	// The default is 10000.
	MaxSignatures int
}

// Guard implements core.Guard. It stores signatures of previously detected
// attacks and matches new inputs against them, enabling the pipeline to
// self-harden over time.
type Guard struct {
	opts  Options
	store Store
}

// Compile-time interface check.
var _ core.Guard = (*Guard)(nil)

// New creates a memory Guard. If opts is nil, defaults are used.
func New(opts *Options) *Guard {
	if opts == nil {
		opts = &Options{}
	}

	threshold := opts.Threshold
	if threshold <= 0 {
		threshold = defaultThreshold
	}

	maxSigs := opts.MaxSignatures
	if maxSigs <= 0 {
		maxSigs = defaultMaxSignatures
	}

	store := opts.Store
	if store == nil {
		store = NewInMemoryStore(maxSigs)
	}

	return &Guard{
		opts: Options{
			Store:         store,
			Threshold:     threshold,
			MaxSignatures: maxSigs,
		},
		store: store,
	}
}

// Name returns the guard identifier.
func (g *Guard) Name() string { return "memory" }

// Execute checks the current input against stored attack signatures. If a
// match is found, a threat is added immediately. After the downstream guards
// run (via next), any newly detected threats cause the input's signature to be
// stored for future matching.
func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	sig := GenerateSignature(ctx.Input)

	// --- Pre-processing: check for known attack patterns. ---
	if match, ok := g.store.Search(sig, g.opts.Threshold); ok {
		threatType := match.Signature.ThreatType
		if threatType == "" {
			threatType = core.ThreatCustom
		}

		ctx.AddThreat(core.Threat{
			Type:     threatType,
			Severity: match.Signature.Severity,
			Message: fmt.Sprintf(
				"input matches previously seen attack (similarity %.2f)",
				match.Similarity,
			),
			Guard: "memory",
			Match: ctx.Input,
			Start: 0,
			End:   len(ctx.Input),
		})

		ctx.SetMeta("memory.matched", true)
		ctx.SetMeta("memory.similarity", match.Similarity)
	}

	// Snapshot the threat count before downstream guards run.
	threatsBefore := len(ctx.Threats)

	// --- Invoke downstream guards. ---
	if !ctx.Halted {
		next(ctx)
	}

	// --- Post-processing: learn from newly detected threats. ---
	if len(ctx.Threats) > threatsBefore {
		// Pick the highest-severity new threat to characterise this signature.
		var bestType core.ThreatType
		var bestSev float64
		for _, t := range ctx.Threats[threatsBefore:] {
			if t.Severity > bestSev {
				bestSev = t.Severity
				bestType = t.Type
			}
		}
		if bestType == "" {
			bestType = core.ThreatCustom
		}

		sig.ThreatType = bestType
		sig.Severity = bestSev

		_ = g.store.Add(sig) // best-effort; errors are intentionally ignored
		ctx.SetMeta("memory.stored", true)
	}

	// Expose store size for observability.
	ctx.SetMeta("memory.signatures", g.store.Len())
}
