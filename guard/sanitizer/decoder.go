package sanitizer

import (
	"encoding/hex"
	"regexp"
	"strings"
	"unicode/utf8"

	intb64 "github.com/danielthedm/promptsec/internal/base64"
)

// Compiled regexps for encoded payload detection.
var (
	// reBase64Block matches 32+ contiguous base64 characters with optional padding.
	reBase64Block = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,3}`)

	// reHexEscape matches sequences of 4 or more \xNN hex escape pairs.
	reHexEscape = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){4,}`)

	// reSingleHexEscape extracts individual \xNN pairs from a hex escape sequence.
	reSingleHexEscape = regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)
)

// decodedSegment records a decoded payload that was found and replaced.
type decodedSegment struct {
	kind    string // "base64" or "hex_escape"
	encoded string // the original encoded text
	decoded string // the decoded plaintext
	start   int    // byte offset in the original string
	end     int    // byte offset end in the original string
}

// decodePayloads scans the input for base64-encoded blocks and hex escape
// sequences. When a block decodes to valid UTF-8 text, it is replaced inline
// with the decoded content. The function returns the modified string and a
// slice of all decoded segments.
func decodePayloads(s string) (string, []decodedSegment) {
	var segments []decodedSegment

	// Pass 1: decode base64 blocks.
	s, segments = decodeBase64Blocks(s, segments)

	// Pass 2: decode hex escape sequences.
	s, segments = decodeHexEscapes(s, segments)

	return s, segments
}

// decodeBase64Blocks finds base64-encoded blocks and replaces them with decoded
// content when the result is valid UTF-8.
func decodeBase64Blocks(s string, segments []decodedSegment) (string, []decodedSegment) {
	var result strings.Builder
	result.Grow(len(s))
	lastEnd := 0

	for _, loc := range reBase64Block.FindAllStringIndex(s, -1) {
		candidate := s[loc[0]:loc[1]]
		decoded, err := intb64.DecodeString(candidate)
		if err != nil {
			continue
		}
		if !utf8.ValidString(decoded) {
			continue
		}

		// Write everything before this match, then the decoded content.
		result.WriteString(s[lastEnd:loc[0]])
		result.WriteString(decoded)

		segments = append(segments, decodedSegment{
			kind:    "base64",
			encoded: candidate,
			decoded: decoded,
			start:   loc[0],
			end:     loc[1],
		})
		lastEnd = loc[1]
	}

	if lastEnd == 0 {
		return s, segments
	}
	result.WriteString(s[lastEnd:])
	return result.String(), segments
}

// decodeHexEscapes finds sequences of \xNN hex escape pairs and replaces them
// with decoded content when the result is valid UTF-8.
func decodeHexEscapes(s string, segments []decodedSegment) (string, []decodedSegment) {
	var result strings.Builder
	result.Grow(len(s))
	lastEnd := 0

	for _, loc := range reHexEscape.FindAllStringIndex(s, -1) {
		seq := s[loc[0]:loc[1]]
		decoded := decodeHexSequence(seq)
		if decoded == "" || !utf8.ValidString(decoded) {
			continue
		}

		result.WriteString(s[lastEnd:loc[0]])
		result.WriteString(decoded)

		segments = append(segments, decodedSegment{
			kind:    "hex_escape",
			encoded: seq,
			decoded: decoded,
			start:   loc[0],
			end:     loc[1],
		})
		lastEnd = loc[1]
	}

	if lastEnd == 0 {
		return s, segments
	}
	result.WriteString(s[lastEnd:])
	return result.String(), segments
}

// decodeHexSequence converts a string of \xNN pairs into its byte-decoded form.
func decodeHexSequence(s string) string {
	matches := reSingleHexEscape.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return ""
	}
	var hexStr strings.Builder
	for _, m := range matches {
		hexStr.WriteString(m[1])
	}
	decoded, err := hex.DecodeString(hexStr.String())
	if err != nil {
		return ""
	}
	return string(decoded)
}
