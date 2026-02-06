package output

import (
	"encoding/json"
	"fmt"
)

// validateJSON checks whether s is syntactically valid JSON. It returns nil
// if s is valid, or a descriptive error otherwise.
func validateJSON(s string) error {
	if !json.Valid([]byte(s)) {
		return fmt.Errorf("output is not valid JSON")
	}
	return nil
}

// validateLength checks whether s exceeds max bytes. A max of zero or
// negative means unlimited and always returns nil.
func validateLength(s string, max int) error {
	if max <= 0 {
		return nil
	}
	if len(s) > max {
		return fmt.Errorf("output length %d exceeds maximum allowed length %d", len(s), max)
	}
	return nil
}
