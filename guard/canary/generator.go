package canary

import (
	"github.com/danielthedm/promptsec/internal/core"
	"github.com/danielthedm/promptsec/internal/crypto"
)

// generateToken produces a canary token in the requested format. The returned
// string always starts with prefix so that it can be identified reliably.
func generateToken(format core.CanaryFormat, length int, prefix string) string {
	switch format {
	case core.CanaryUUID:
		return prefix + crypto.RandomUUID()
	case core.CanaryWord:
		return prefix + crypto.RandomAlphaNum(length)
	default: // CanaryHex
		return prefix + crypto.RandomHex(length)
	}
}
