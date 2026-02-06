package rot13

func Encode(s string) string {
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			buf[i] = 'A' + (c-'A'+13)%26
		case c >= 'a' && c <= 'z':
			buf[i] = 'a' + (c-'a'+13)%26
		default:
			buf[i] = c
		}
	}
	return string(buf)
}

func Decode(s string) string {
	return Encode(s) // ROT13 is its own inverse
}
