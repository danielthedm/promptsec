package promptsec

import "github.com/danielthedm/promptsec/internal/core"

func newContext(input string) *Context {
	return core.NewContext(input)
}
