// Package memory provides a self-hardening guard that stores signatures of
// previously detected attacks and matches new inputs against them. When a new
// input is similar to a known attack signature, the guard raises a threat
// before the rest of the pipeline runs.
package memory

import (
	"hash/fnv"
	"strings"
	"time"

	"github.com/danielthedm/promptsec/internal/core"
)

// Signature is a compact representation of an input text used for approximate
// matching against previously observed attack patterns.
type Signature struct {
	// Hash is an FNV-1a hash of the normalised input.
	Hash uint64

	// NGrams holds character trigram frequencies extracted from the input.
	NGrams map[string]int

	// Length is the rune length of the normalised input.
	Length int

	// ThreatType records the type of threat associated with this signature.
	ThreatType core.ThreatType

	// Severity records the severity of the threat when the signature was stored.
	Severity float64

	// CreatedAt is the time the signature was generated.
	CreatedAt time.Time
}

// GenerateSignature creates a Signature from the given input string. The input
// is lowercased and trimmed before trigram extraction and hashing.
func GenerateSignature(input string) *Signature {
	normalised := strings.ToLower(strings.TrimSpace(input))
	runes := []rune(normalised)

	// Extract character trigrams.
	ngrams := make(map[string]int)
	for i := 0; i+3 <= len(runes); i++ {
		tri := string(runes[i : i+3])
		ngrams[tri]++
	}

	// Compute FNV-1a hash.
	h := fnv.New64a()
	_, _ = h.Write([]byte(normalised))

	return &Signature{
		Hash:      h.Sum64(),
		NGrams:    ngrams,
		Length:    len(runes),
		CreatedAt: time.Now(),
	}
}

// Similarity computes the Jaccard similarity between two signatures based on
// their trigram frequency maps. The result is in the range [0.0, 1.0] where
// 1.0 indicates identical trigram profiles.
func (s *Signature) Similarity(other *Signature) float64 {
	if len(s.NGrams) == 0 && len(other.NGrams) == 0 {
		return 1.0
	}
	if len(s.NGrams) == 0 || len(other.NGrams) == 0 {
		return 0.0
	}

	// Collect the full set of trigram keys from both signatures.
	keys := make(map[string]struct{}, len(s.NGrams)+len(other.NGrams))
	for k := range s.NGrams {
		keys[k] = struct{}{}
	}
	for k := range other.NGrams {
		keys[k] = struct{}{}
	}

	var intersectionSum, unionSum int
	for k := range keys {
		a := s.NGrams[k]
		b := other.NGrams[k]

		// Generalised (min/max) Jaccard for multisets.
		if a < b {
			intersectionSum += a
			unionSum += b
		} else {
			intersectionSum += b
			unionSum += a
		}
	}

	if unionSum == 0 {
		return 0.0
	}
	return float64(intersectionSum) / float64(unionSum)
}
