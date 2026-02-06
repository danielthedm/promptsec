package core

type GuardFn struct {
	name string
	fn   func(ctx *Context, next NextFn)
}

func NewGuardFunc(name string, fn func(ctx *Context, next NextFn)) Guard {
	return &GuardFn{name: name, fn: fn}
}

func (g *GuardFn) Name() string                      { return g.name }
func (g *GuardFn) Execute(ctx *Context, next NextFn) { g.fn(ctx, next) }
