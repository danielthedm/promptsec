package structure

import (
	"github.com/danielthedm/promptsec/internal/core"
	"github.com/danielthedm/promptsec/internal/crypto"
)

// enclosureSequenceLength is the number of random alphanumeric characters used
// to generate the enclosure markers.
const enclosureSequenceLength = 16

type enclosureGuard struct {
	opts Options
}

// NewEnclosure creates a structure guard that wraps user input in
// cryptographically random alphanumeric delimiters. The system prompt is
// placed before the enclosed block with an instruction telling the model to
// treat everything between the markers as untrusted data. Because the markers
// are unpredictable, an attacker cannot craft input that closes and reopens
// the enclosure.
func NewEnclosure(opts *Options) *enclosureGuard {
	g := &enclosureGuard{}
	if opts != nil {
		g.opts = *opts
	}
	return g
}

// Name returns the guard identifier.
func (g *enclosureGuard) Name() string { return "structure-enclosure" }

// Execute generates a random sequence, builds the enclosure prompt, and
// updates ctx.Input.
func (g *enclosureGuard) Execute(ctx *core.Context, next core.NextFn) {
	seq := crypto.RandomAlphaNum(enclosureSequenceLength)

	structured := g.opts.SystemPrompt +
		"\n\nUser input is enclosed between " + seq + " markers:\n" +
		seq + "\n" + ctx.Input + "\n" + seq

	ctx.SetMeta(metaKeyStructuredPrompt, structured)
	ctx.Input = structured

	next(ctx)
}
