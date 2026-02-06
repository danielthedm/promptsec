package structure

import (
	"github.com/danielthedm/promptsec/internal/core"
)

type postPromptGuard struct {
	opts Options
}

// NewPostPrompt creates a structure guard that places the system instructions
// after the user input. Because LLMs exhibit strong recency bias -- giving
// more weight to tokens near the end of the context -- this layout ensures the
// model is most likely to follow the legitimate system prompt rather than any
// injected instructions within the user input.
func NewPostPrompt(opts *Options) *postPromptGuard {
	g := &postPromptGuard{}
	if opts != nil {
		g.opts = *opts
	}
	return g
}

// Name returns the guard identifier.
func (g *postPromptGuard) Name() string { return "structure-postprompt" }

// Execute builds the post-prompt layout and updates ctx.Input.
func (g *postPromptGuard) Execute(ctx *core.Context, next core.NextFn) {
	structured := ctx.Input + "\n\n" + g.opts.SystemPrompt

	ctx.SetMeta(metaKeyStructuredPrompt, structured)
	ctx.Input = structured

	next(ctx)
}
