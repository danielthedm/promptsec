package spotlight

import (
	"github.com/danielthedm/promptsec/internal/crypto"
)

// defaultDelimiterBytes is the default number of random bytes used to produce
// a hex delimiter. 8 bytes yields a 16-character hex string.
const defaultDelimiterBytes = 8

// randomDelimiter returns a cryptographically random hex string suitable for
// use as a spotlight delimiter. The length parameter specifies the number of
// random bytes; the returned string will be twice as long (hex-encoded).
func randomDelimiter(lengthBytes int) string {
	if lengthBytes <= 0 {
		lengthBytes = defaultDelimiterBytes
	}
	return crypto.RandomHex(lengthBytes)
}
