package sanitizer

import (
	intu "github.com/danielthedm/promptsec/internal/unicode"
)

// normalizeInput strips zero-width and invisible Unicode characters from the
// input string. It returns the cleaned string and a boolean indicating whether
// any characters were removed.
func normalizeInput(s string) (string, bool) {
	if !intu.HasZeroWidth(s) {
		return s, false
	}
	cleaned := intu.StripZeroWidth(s)
	return cleaned, cleaned != s
}
