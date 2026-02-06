package sanitizer

import (
	intu "github.com/danielthedm/promptsec/internal/unicode"
)

// dehomoglyph replaces confusable characters (Cyrillic, Greek, fullwidth Latin,
// accented Latin, etc.) with their standard ASCII equivalents. It returns the
// normalized string and a boolean indicating whether any replacements were made.
func dehomoglyph(s string) (string, bool) {
	if !intu.HasConfusables(s) {
		return s, false
	}
	normalized := intu.NormalizeConfusables(s)
	return normalized, normalized != s
}
