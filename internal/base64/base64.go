package base64

import "encoding/base64"

func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func EncodeString(s string) string {
	return Encode([]byte(s))
}

func DecodeString(s string) (string, error) {
	b, err := Decode(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
