package unicode

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

var zeroWidthChars = map[rune]bool{
	'\u200B': true, // zero width space
	'\u200C': true, // zero width non-joiner
	'\u200D': true, // zero width joiner
	'\uFEFF': true, // byte order mark / zero width no-break space
	'\u00AD': true, // soft hyphen
	'\u200E': true, // left-to-right mark
	'\u200F': true, // right-to-left mark
	'\u2060': true, // word joiner
	'\u2061': true, // function application
	'\u2062': true, // invisible times
	'\u2063': true, // invisible separator
	'\u2064': true, // invisible plus
	'\u180E': true, // mongolian vowel separator
}

func StripZeroWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !zeroWidthChars[r] {
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func HasZeroWidth(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if zeroWidthChars[r] {
			return true
		}
		i += size
	}
	return false
}

func ContainsInvisible(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if zeroWidthChars[r] || unicode.Is(unicode.Cf, r) {
			return true
		}
		i += size
	}
	return false
}

var confusables = map[rune]rune{
	'\u0410': 'A', '\u0430': 'a', // Cyrillic А/а
	'\u0412': 'B', '\u0432': 'b', // Cyrillic В/в (visual B)
	'\u0421': 'C', '\u0441': 'c', // Cyrillic С/с
	'\u0415': 'E', '\u0435': 'e', // Cyrillic Е/е
	'\u041D': 'H', '\u043D': 'h', // Cyrillic Н/н
	'\u041A': 'K', '\u043A': 'k', // Cyrillic К/к
	'\u041C': 'M', '\u043C': 'm', // Cyrillic М/м
	'\u041E': 'O', '\u043E': 'o', // Cyrillic О/о
	'\u0420': 'P', '\u0440': 'p', // Cyrillic Р/р
	'\u0422': 'T', '\u0442': 't', // Cyrillic Т/т
	'\u0425': 'X', '\u0445': 'x', // Cyrillic Х/х
	'\u0423': 'Y', '\u0443': 'y', // Cyrillic У/у
	'\u0417': '3',                // Cyrillic З
	'\u0405': 'S', '\u0455': 's', // Cyrillic Ѕ/ѕ
	'\u0406': 'I', '\u0456': 'i', // Cyrillic І/і
	'\u0408': 'J', '\u0458': 'j', // Cyrillic Ј/ј
	'\u04AE': 'Y', // Cyrillic Ү
	'\u04BA': 'H', // Cyrillic Һ

	// Greek confusables
	'\u0391': 'A', '\u03B1': 'a', // Alpha
	'\u0392': 'B', '\u03B2': 'B', // Beta
	'\u0395': 'E', '\u03B5': 'e', // Epsilon
	'\u0397': 'H', '\u03B7': 'n', // Eta
	'\u0399': 'I', '\u03B9': 'i', // Iota
	'\u039A': 'K', '\u03BA': 'k', // Kappa
	'\u039C': 'M',                // Mu
	'\u039D': 'N', '\u03BD': 'v', // Nu
	'\u039F': 'O', '\u03BF': 'o', // Omicron
	'\u03A1': 'P', '\u03C1': 'p', // Rho
	'\u03A4': 'T', '\u03C4': 't', // Tau
	'\u03A5': 'Y', '\u03C5': 'u', // Upsilon
	'\u03A7': 'X', '\u03C7': 'x', // Chi
	'\u0396': 'Z', '\u03B6': 'z', // Zeta

	// Latin extended / special
	'\u00C0': 'A', '\u00C1': 'A', '\u00C2': 'A', '\u00C3': 'A', '\u00C4': 'A', '\u00C5': 'A',
	'\u00E0': 'a', '\u00E1': 'a', '\u00E2': 'a', '\u00E3': 'a', '\u00E4': 'a', '\u00E5': 'a',
	'\u00C8': 'E', '\u00C9': 'E', '\u00CA': 'E', '\u00CB': 'E',
	'\u00E8': 'e', '\u00E9': 'e', '\u00EA': 'e', '\u00EB': 'e',
	'\u00CC': 'I', '\u00CD': 'I', '\u00CE': 'I', '\u00CF': 'I',
	'\u00EC': 'i', '\u00ED': 'i', '\u00EE': 'i', '\u00EF': 'i',
	'\u00D2': 'O', '\u00D3': 'O', '\u00D4': 'O', '\u00D5': 'O', '\u00D6': 'O',
	'\u00F2': 'o', '\u00F3': 'o', '\u00F4': 'o', '\u00F5': 'o', '\u00F6': 'o',
	'\u00D9': 'U', '\u00DA': 'U', '\u00DB': 'U', '\u00DC': 'U',
	'\u00F9': 'u', '\u00FA': 'u', '\u00FB': 'u', '\u00FC': 'u',
	'\u0100': 'A', '\u0101': 'a', '\u0102': 'A', '\u0103': 'a',
	'\u0104': 'A', '\u0105': 'a',
	'\u0106': 'C', '\u0107': 'c', '\u0108': 'C', '\u0109': 'c',
	'\u010A': 'C', '\u010B': 'c', '\u010C': 'C', '\u010D': 'c',
	'\u010E': 'D', '\u010F': 'd', '\u0110': 'D', '\u0111': 'd',
	'\u0112': 'E', '\u0113': 'e', '\u0114': 'E', '\u0115': 'e',
	'\u0116': 'E', '\u0117': 'e', '\u0118': 'E', '\u0119': 'e',
	'\u011A': 'E', '\u011B': 'e',
	'\u0124': 'H', '\u0125': 'h',
	'\u0128': 'I', '\u0129': 'i', '\u012A': 'I', '\u012B': 'i',
	'\u012C': 'I', '\u012D': 'i', '\u012E': 'I', '\u012F': 'i',
	'\u0130': 'I', '\u0131': 'i',
	'\u0134': 'J', '\u0135': 'j',
	'\u0139': 'L', '\u013A': 'l', '\u013B': 'L', '\u013C': 'l',
	'\u013D': 'L', '\u013E': 'l',
	'\u0141': 'L', '\u0142': 'l',
	'\u0143': 'N', '\u0144': 'n', '\u0145': 'N', '\u0146': 'n',
	'\u0147': 'N', '\u0148': 'n',
	'\u014C': 'O', '\u014D': 'o', '\u014E': 'O', '\u014F': 'o',
	'\u0150': 'O', '\u0151': 'o',
	'\u0154': 'R', '\u0155': 'r', '\u0156': 'R', '\u0157': 'r',
	'\u0158': 'R', '\u0159': 'r',
	'\u015A': 'S', '\u015B': 's', '\u015C': 'S', '\u015D': 's',
	'\u015E': 'S', '\u015F': 's', '\u0160': 'S', '\u0161': 's',
	'\u0162': 'T', '\u0163': 't', '\u0164': 'T', '\u0165': 't',
	'\u0168': 'U', '\u0169': 'u', '\u016A': 'U', '\u016B': 'u',
	'\u016C': 'U', '\u016D': 'u', '\u016E': 'U', '\u016F': 'u',
	'\u0170': 'U', '\u0171': 'u', '\u0172': 'U', '\u0173': 'u',
	'\u0174': 'W', '\u0175': 'w',
	'\u0176': 'Y', '\u0177': 'y', '\u0178': 'Y',
	'\u0179': 'Z', '\u017A': 'z', '\u017B': 'Z', '\u017C': 'z',
	'\u017D': 'Z', '\u017E': 'z',

	// Fullwidth Latin
	'\uFF21': 'A', '\uFF22': 'B', '\uFF23': 'C', '\uFF24': 'D', '\uFF25': 'E',
	'\uFF26': 'F', '\uFF27': 'G', '\uFF28': 'H', '\uFF29': 'I', '\uFF2A': 'J',
	'\uFF2B': 'K', '\uFF2C': 'L', '\uFF2D': 'M', '\uFF2E': 'N', '\uFF2F': 'O',
	'\uFF30': 'P', '\uFF31': 'Q', '\uFF32': 'R', '\uFF33': 'S', '\uFF34': 'T',
	'\uFF35': 'U', '\uFF36': 'V', '\uFF37': 'W', '\uFF38': 'X', '\uFF39': 'Y',
	'\uFF3A': 'Z',
	'\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd', '\uFF45': 'e',
	'\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h', '\uFF49': 'i', '\uFF4A': 'j',
	'\uFF4B': 'k', '\uFF4C': 'l', '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o',
	'\uFF50': 'p', '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
	'\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x', '\uFF59': 'y',
	'\uFF5A': 'z',

	// Math/symbol confusables
	'\u2010': '-', '\u2011': '-', '\u2012': '-', '\u2013': '-', '\u2014': '-',
	'\u2018': '\'', '\u2019': '\'', '\u201A': '\'',
	'\u201C': '"', '\u201D': '"', '\u201E': '"',
	'\u2024': '.', '\u2025': '.', '\u2026': '.',
}

func NormalizeConfusables(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if replacement, ok := confusables[r]; ok {
			b.WriteRune(replacement)
			changed = true
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	if !changed {
		return s
	}
	return b.String()
}

// HasSuspiciousConfusables checks only for characters from scripts commonly
// used in homoglyph attacks (Cyrillic, Greek, fullwidth Latin). It does NOT
// flag Latin Extended accented characters (ä, ö, ü, é, etc.) which appear in
// normal German, French, Spanish and other European text.
func HasSuspiciousConfusables(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if _, ok := confusables[r]; ok {
			// Only flag Cyrillic, Greek, and Fullwidth ranges
			if (r >= '\u0391' && r <= '\u03C7') || // Greek
				(r >= '\u0400' && r <= '\u04FF') || // Cyrillic
				(r >= '\uFF21' && r <= '\uFF5A') { // Fullwidth
				return true
			}
		}
		i += size
	}
	return false
}

func HasConfusables(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if _, ok := confusables[r]; ok {
			return true
		}
		i += size
	}
	return false
}

func GetConfusableMap() map[rune]rune {
	m := make(map[rune]rune, len(confusables))
	for k, v := range confusables {
		m[k] = v
	}
	return m
}
