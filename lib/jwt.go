package lib

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// decodeJWTSegment base64url-decodes one segment (header or payload) of a JWT,
// without verifying its signature. Used only for trace/debug output.
func decodeJWTSegment(token string, index int) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return "", fmt.Errorf("not a well-formed JWT (expected 3 dot-separated segments)")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		return "", fmt.Errorf("failed to base64-decode JWT segment: %w", err)
	}
	return string(decoded), nil
}

func DecodeJWTHeader(token string) (string, error) {
	return decodeJWTSegment(token, 0)
}

func DecodeJWTClaims(token string) (string, error) {
	return decodeJWTSegment(token, 1)
}
