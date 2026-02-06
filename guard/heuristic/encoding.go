package heuristic

import (
	"regexp"
	"strings"

	intb64 "github.com/danielthedm/promptsec/internal/base64"
	"github.com/danielthedm/promptsec/internal/core"
	intu "github.com/danielthedm/promptsec/internal/unicode"
)

// Compiled regexps for encoding attack detection (init at package level).
var (
	reBase64Block   *regexp.Regexp
	reHexEscape     *regexp.Regexp
	reHexLiteral    *regexp.Regexp
	reUnicodeEscape *regexp.Regexp
	reSpacedChars   *regexp.Regexp
)

// suspiciousKeywords are strings that, when found inside a decoded payload,
// indicate a likely injection attempt smuggled through encoding.
var suspiciousKeywords []string

// spacedKeywords are words that, when hidden via single-character spacing
// (e.g. "i g n o r e"), indicate evasion.
var spacedKeywords = []string{
	"ignore", "forget", "disregard", "override", "pretend",
	"instructions", "system", "prompt", "bypass", "reveal",
}

func init() {
	// Base64 block: 32+ contiguous base64 characters (may include padding).
	reBase64Block = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,3}`)

	// Hex escape sequences: \x41, \x6F, etc.
	reHexEscape = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){4,}`)

	// Hex literal sequences: 0x41 0x42 or 0x41,0x42 or 0x410x42
	reHexLiteral = regexp.MustCompile(`(?:0x[0-9A-Fa-f]{2}[\s,]*){4,}`)

	// Unicode escape sequences: \u0041 or \U00000041
	reUnicodeEscape = regexp.MustCompile(`(?:\\[uU][0-9A-Fa-f]{4,8}){3,}`)

	suspiciousKeywords = []string{
		"ignore", "disregard", "forget", "override",
		"instructions", "system", "prompt", "assistant",
		"pretend", "act as", "you are", "new role",
		"reveal", "repeat", "output",
	}

	// Spaced-out chars: 5+ single letters each separated by a space.
	reSpacedChars = regexp.MustCompile(`(?i)\b[a-z]\s[a-z](?:\s[a-z]){3,}\b`)
}

// collapseSpacedChars removes spaces between single characters.
func collapseSpacedChars(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != ' ' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// detectEncodingAttacks scans the input for various encoding-based evasion
// techniques and returns any threats found.
func detectEncodingAttacks(input string) []core.Threat {
	var threats []core.Threat

	// 1. Zero-width / invisible character detection.
	if intu.ContainsInvisible(input) {
		threats = append(threats, core.Threat{
			Type:     core.ThreatEncodingAttack,
			Severity: 0.3,
			Message:  "input contains zero-width or invisible characters that may hide injected content",
			Guard:    "heuristic",
		})
	}

	// 2. Homoglyph / confusable character detection (only suspicious scripts).
	if intu.HasSuspiciousConfusables(input) {
		threats = append(threats, core.Threat{
			Type:     core.ThreatEncodingAttack,
			Severity: 0.7,
			Message:  "input contains confusable/homoglyph characters that may bypass pattern matching",
			Guard:    "heuristic",
		})
	}

	// 3. Base64-encoded payloads.
	for _, loc := range reBase64Block.FindAllStringIndex(input, -1) {
		candidate := input[loc[0]:loc[1]]
		decoded, err := intb64.DecodeString(candidate)
		if err != nil {
			continue
		}
		lower := strings.ToLower(decoded)
		for _, kw := range suspiciousKeywords {
			if strings.Contains(lower, kw) {
				threats = append(threats, core.Threat{
					Type:     core.ThreatEncodingAttack,
					Severity: 0.9,
					Message:  "base64-encoded payload contains suspicious keyword: " + kw,
					Guard:    "heuristic",
					Match:    candidate,
					Start:    loc[0],
					End:      loc[1],
				})
				break
			}
		}
	}

	// 4. Hex escape sequences (\xNN).
	for _, loc := range reHexEscape.FindAllStringIndex(input, -1) {
		threats = append(threats, core.Threat{
			Type:     core.ThreatEncodingAttack,
			Severity: 0.75,
			Message:  "hex escape sequence detected, potential encoding-based evasion",
			Guard:    "heuristic",
			Match:    input[loc[0]:loc[1]],
			Start:    loc[0],
			End:      loc[1],
		})
	}

	// 5. Hex literal sequences (0xNN).
	for _, loc := range reHexLiteral.FindAllStringIndex(input, -1) {
		threats = append(threats, core.Threat{
			Type:     core.ThreatEncodingAttack,
			Severity: 0.7,
			Message:  "hex literal sequence detected, potential encoding-based evasion",
			Guard:    "heuristic",
			Match:    input[loc[0]:loc[1]],
			Start:    loc[0],
			End:      loc[1],
		})
	}

	// 6. Unicode escape sequences (\uXXXX).
	for _, loc := range reUnicodeEscape.FindAllStringIndex(input, -1) {
		threats = append(threats, core.Threat{
			Type:     core.ThreatEncodingAttack,
			Severity: 0.75,
			Message:  "unicode escape sequence detected, potential encoding-based evasion",
			Guard:    "heuristic",
			Match:    input[loc[0]:loc[1]],
			Start:    loc[0],
			End:      loc[1],
		})
	}

	// 7. Spaced-out character evasion (e.g. "I g n o r e" or "S a y t h a t").
	if match := reSpacedChars.FindString(input); match != "" {
		collapsed := collapseSpacedChars(match)
		lower := strings.ToLower(collapsed)
		keywordFound := false
		for _, kw := range spacedKeywords {
			if strings.Contains(lower, kw) {
				threats = append(threats, core.Threat{
					Type:     core.ThreatEncodingAttack,
					Severity: 0.8,
					Message:  "spaced-out characters detected hiding keyword: " + kw,
					Guard:    "heuristic",
					Match:    match,
				})
				keywordFound = true
				break
			}
		}
		// Flag any long spaced-out sequence (7+ chars) as evasion even
		// without a keyword match, since it's an obfuscation technique.
		if !keywordFound && len(collapsed) >= 7 {
			threats = append(threats, core.Threat{
				Type:     core.ThreatEncodingAttack,
				Severity: 0.6,
				Message:  "spaced-out characters detected, potential obfuscation evasion",
				Guard:    "heuristic",
				Match:    match,
			})
		}
	}

	return threats
}
