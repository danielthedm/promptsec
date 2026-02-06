// Package embedding provides a lightweight embedding-based classifier for
// prompt injection detection. It converts text into character n-gram frequency
// vectors and compares them against known attack embeddings using cosine
// similarity. No external embedding model is required.
package embedding

import (
	"fmt"

	"github.com/danielthedm/promptsec/internal/core"
)

// DefaultThreshold is the cosine-similarity threshold above which a match is
// considered a potential attack.
const DefaultThreshold = 0.75

// Options configures the embedding guard.
type Options struct {
	// Threshold is the minimum cosine similarity score (0..1) between the
	// input vector and an attack vector for a threat to be reported. The
	// default is 0.75.
	Threshold float64

	// CustomVectors are additional attack vectors to check against,
	// alongside the built-in set.
	CustomVectors []Vector
}

// Vector is a labelled embedding vector used as an attack reference.
type Vector struct {
	Label  string
	Values []float64
	Type   core.ThreatType
}

// Guard implements core.Guard using embedding-based cosine similarity.
type Guard struct {
	opts    Options
	vectors []Vector
}

// Compile-time interface check.
var _ core.Guard = (*Guard)(nil)

// New creates a new embedding Guard. If opts is nil a default configuration
// (threshold 0.75, built-in vectors only) is used.
func New(opts *Options) *Guard {
	if opts == nil {
		opts = &Options{}
	}

	g := &Guard{opts: *opts}

	if g.opts.Threshold == 0 {
		g.opts.Threshold = DefaultThreshold
	}

	// Combine built-in and caller-supplied vectors.
	g.vectors = make([]Vector, 0, len(defaultVectors)+len(g.opts.CustomVectors))
	g.vectors = append(g.vectors, defaultVectors...)
	g.vectors = append(g.vectors, g.opts.CustomVectors...)

	return g
}

// Name returns the guard identifier.
func (g *Guard) Name() string { return "embedding" }

// Execute converts ctx.Input to a feature vector, compares it against every
// known attack vector, and adds a threat for each that exceeds the configured
// threshold. Similarity scores are stored in ctx.Metadata under the key
// "embedding_scores". The next guard in the chain is always invoked (unless
// the context has been halted by a prior guard).
func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	inputVec := TextToVector(ctx.Input)

	scores := make(map[string]float64, len(g.vectors))

	for i := range g.vectors {
		v := &g.vectors[i]
		sim := CosineSimilarity(inputVec, v.Values)
		scores[v.Label] = sim

		if sim >= g.opts.Threshold {
			threatType := v.Type
			if threatType == "" {
				threatType = core.ThreatCustom
			}

			ctx.AddThreat(core.Threat{
				Type:     threatType,
				Severity: sim, // use similarity as severity (0..1)
				Message:  fmt.Sprintf("embedding similarity %.4f with attack vector %q", sim, v.Label),
				Guard:    "embedding",
				Match:    ctx.Input,
				Start:    0,
				End:      len(ctx.Input),
			})
		}
	}

	ctx.SetMeta("embedding_scores", scores)

	if !ctx.Halted {
		next(ctx)
	}
}
