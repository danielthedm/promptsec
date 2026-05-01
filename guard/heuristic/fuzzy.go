package heuristic

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// leetMap maps common character substitutions used in typoglycemia / leet-speak
// evasion back to their canonical ASCII letter.
var leetMap map[rune]rune

func init() {
	leetMap = map[rune]rune{
		'1': 'i',
		'!': 'i',
		'|': 'i',
		'0': 'o',
		'@': 'a',
		'4': 'a',
		'$': 's',
		'5': 's',
		'3': 'e',
		'7': 't',
		'+': 't',
		'8': 'b',
		'6': 'g',
		'9': 'g',
		'2': 'z',
	}
}

// criticalKeywords are the words that fuzzy matching is applied to.
// These are injection-relevant terms that attackers commonly obfuscate.
var criticalKeywords = []string{
	"ignore",
	"system",
	"instructions",
	"prompt",
	"override",
	"disregard",
	"forget",
	"pretend",
	"reveal",
	"assistant",
	"previous",
}

type fuzzyKeyword struct {
	text    string
	runes   []rune
	maxDist int
}

var fuzzyKeywords []fuzzyKeyword

func init() {
	fuzzyKeywords = make([]fuzzyKeyword, len(criticalKeywords))
	for i, kw := range criticalKeywords {
		kwRunes := []rune(kw)
		maxDist := 1
		if len(kwRunes) >= 8 {
			maxDist = 2
		}
		fuzzyKeywords[i] = fuzzyKeyword{
			text:    kw,
			runes:   kwRunes,
			maxDist: maxDist,
		}
	}
}

// normalizeForFuzzy converts a string to a canonical form for fuzzy matching.
// It lower-cases, applies leet-speak substitution, and strips non-alphanumeric
// characters (except spaces which are preserved to maintain word boundaries).
func normalizeForFuzzy(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size

		// Apply leet-speak mapping first.
		if mapped, ok := leetMap[r]; ok {
			b.WriteRune(mapped)
			continue
		}

		lr := unicode.ToLower(r)

		// Keep alphanumeric and spaces.
		if unicode.IsLetter(lr) || unicode.IsDigit(lr) {
			b.WriteRune(lr)
		} else if lr == ' ' || lr == '\t' || lr == '\n' {
			b.WriteRune(' ')
		}
		// All other characters (punctuation, symbols) are stripped.
	}
	return b.String()
}

// fuzzyContains checks whether the normalised haystack contains a fuzzy match
// for the keyword. It uses a simple edit-distance window: for each position in
// the haystack it extracts a window of len(keyword) +/- 1 characters and
// computes the Levenshtein distance. A match is declared if the distance is
// within the tolerance.
func fuzzyContains(haystack string, haystackRunes []rune, keyword fuzzyKeyword) bool {
	kwLen := len(keyword.runes)
	if kwLen == 0 {
		return false
	}

	// Short-circuit: exact substring present.
	if strings.Contains(haystack, keyword.text) {
		return true
	}

	// Slide a window across the haystack.
	for winSize := kwLen - 1; winSize <= kwLen+1; winSize++ {
		if winSize <= 0 || winSize > len(haystackRunes) {
			continue
		}
		for i := 0; i <= len(haystackRunes)-winSize; i++ {
			window := haystackRunes[i : i+winSize]
			if withinEditDistance(window, keyword.runes, keyword.maxDist) {
				return true
			}
		}
	}
	return false
}

// fuzzyMatch normalizes input and scans it for fuzzy matches against all
// critical keywords. Returns the list of matched keywords.
func fuzzyMatch(input string) []string {
	normalised := normalizeForFuzzy(input)
	normalisedRunes := []rune(normalised)
	var matches []string
	for _, kw := range fuzzyKeywords {
		if fuzzyContains(normalised, normalisedRunes, kw) {
			matches = append(matches, kw.text)
		}
	}
	return matches
}

// withinEditDistance reports whether the Levenshtein distance between a and b
// is within maxDist. The fuzzy keywords are short, so stack-backed rows avoid
// thousands of tiny allocations in the sliding-window loop.
func withinEditDistance(a, b []rune, maxDist int) bool {
	la, lb := len(a), len(b)
	if absInt(la-lb) > maxDist {
		return false
	}

	const maxStackRow = 32
	var prevBuf, currBuf [maxStackRow]int
	var prev, curr []int
	if lb+1 <= maxStackRow {
		prev = prevBuf[:lb+1]
		curr = currBuf[:lb+1]
	} else {
		prev = make([]int, lb+1)
		curr = make([]int, lb+1)
	}

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost

			min := del
			if ins < min {
				min = ins
			}
			if sub < min {
				min = sub
			}
			curr[j] = min
		}
		prev, curr = curr, prev
	}
	return prev[lb] <= maxDist
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
