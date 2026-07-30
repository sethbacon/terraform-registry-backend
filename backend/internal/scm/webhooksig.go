// webhooksig.go provides the shared HMAC-SHA256 webhook delivery-signature
// verification used by SCM connectors that sign payloads with a hex-encoded
// HMAC-SHA256 digest, optionally prefixed "sha256=" — currently GitHub and
// Bitbucket Data Center.
package scm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// VerifyHMACSHA256Signature validates a webhook delivery signature computed as
// HMAC-SHA256(sharedSecret, payloadBytes), hex-encoded, and optionally
// prefixed with "sha256=" (GitHub always sends the prefix; Bitbucket Data
// Center has been observed sending it with or without depending on
// configuration).
//
// Both sharedSecret and signatureHeader are required: an unconfigured secret,
// or a delivery with no signature header, is treated as unverifiable and
// rejected rather than skipped, matching this codebase's fail-closed
// convention for authentication checks.
func VerifyHMACSHA256Signature(payloadBytes []byte, signatureHeader, sharedSecret string) bool {
	if sharedSecret == "" || signatureHeader == "" {
		return false
	}

	sig := strings.TrimPrefix(signatureHeader, "sha256=")
	expected, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write(payloadBytes)
	computed := mac.Sum(nil)

	return hmac.Equal(expected, computed)
}
