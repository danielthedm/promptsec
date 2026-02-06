package promptsec

import "time"

type OutputGuard interface {
	IsOutputGuard() bool
}

type Protector struct {
	guards       []Guard
	outputGuards []Guard
	threshold    float64
}

func New(guards ...Guard) *Protector {
	var input, output []Guard
	for _, g := range guards {
		if og, ok := g.(OutputGuard); ok && og.IsOutputGuard() {
			output = append(output, g)
		} else {
			input = append(input, g)
		}
	}
	return &Protector{
		guards:       input,
		outputGuards: output,
		threshold:    0.5,
	}
}

func (p *Protector) Analyze(input string) *Result {
	ctx := newContext(input)
	p.runGuards(ctx, p.guards, 0)
	return p.buildResult(ctx)
}

func (p *Protector) ValidateOutput(output string, metadata map[string]any) *Result {
	ctx := newContext(output)
	for k, v := range metadata {
		ctx.Metadata[k] = v
	}
	p.runGuards(ctx, p.outputGuards, 0)
	return p.buildResult(ctx)
}

func (p *Protector) runGuards(ctx *Context, guards []Guard, idx int) {
	if idx >= len(guards) || ctx.Halted {
		return
	}
	guards[idx].Execute(ctx, func(c *Context) {
		p.runGuards(c, guards, idx+1)
	})
}

func (p *Protector) buildResult(ctx *Context) *Result {
	safe := true
	for _, t := range ctx.Threats {
		if t.Severity >= p.threshold {
			safe = false
			break
		}
	}

	return &Result{
		Safe:     safe,
		Threats:  ctx.Threats,
		Output:   ctx.Input,
		Metadata: ctx.Metadata,
		Duration: time.Since(ctx.StartTime),
	}
}
