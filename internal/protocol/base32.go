package protocol

import (
	"encoding/base32"
	"strings"
)

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func EncodeBase32NoPad(raw []byte) string {
	return lowerBase32.EncodeToString(raw)
}

func DecodeBase32NoPad(raw string) ([]byte, error) {
	return lowerBase32.DecodeString(strings.ToLower(raw))
}
