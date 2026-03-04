// gpg.go provides validation of GPG public keys and detached signature verification
// for provider release artifacts using ASCII-armored OpenPGP keys.
package validation

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// ParseGPGPublicKey validates that the provided string is a valid GPG public key in ASCII-armored format
func ParseGPGPublicKey(keyArmored string) error {
	if keyArmored == "" {
		return fmt.Errorf("GPG public key cannot be empty")
	}

	// Check for PGP public key block markers
	if !strings.Contains(keyArmored, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return fmt.Errorf("invalid GPG public key: missing BEGIN marker")
	}

	if !strings.Contains(keyArmored, "-----END PGP PUBLIC KEY BLOCK-----") {
		return fmt.Errorf("invalid GPG public key: missing END marker")
	}

	// Try to actually parse the key to validate it
	keyReader := strings.NewReader(keyArmored)
	_, err := openpgp.ReadArmoredKeyRing(keyReader)
	if err != nil {
		return fmt.Errorf("failed to parse GPG public key: %w", err)
	}

	return nil
}

// VerifySignature verifies a GPG signature against data using the provided public key
func VerifySignature(publicKeyArmored string, data []byte, signature []byte) error {
	// Validate the public key format first
	if publicKeyArmored == "" {
		return fmt.Errorf("public key cannot be empty")
	}

	if len(data) == 0 {
		return fmt.Errorf("data to verify cannot be empty")
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature cannot be empty")
	}

	// Parse the public key
	keyReader := strings.NewReader(publicKeyArmored)
	keyring, err := openpgp.ReadArmoredKeyRing(keyReader)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Check if signature is ASCII-armored
	sigReader := bytes.NewReader(signature)
	var decodedSig []byte

	// Try to decode as ASCII armor first
	block, err := armor.Decode(sigReader)
	if err != nil {
		// Not armored, use raw bytes
		decodedSig = signature
	} else {
		// Read the decoded signature
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(block.Body)
		if err != nil {
			return fmt.Errorf("failed to read armored signature: %w", err)
		}
		decodedSig = buf.Bytes()
	}

	// Verify the signature
	dataReader := bytes.NewReader(data)
	sigReadCloser := bytes.NewReader(decodedSig)

	_, err = openpgp.CheckDetachedSignature(keyring, dataReader, sigReadCloser, nil)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// VerifyArmoredSignature verifies an ASCII-armored GPG signature against data
func VerifyArmoredSignature(publicKeyArmored string, data []byte, armoredSignature string) error {
	return VerifySignature(publicKeyArmored, data, []byte(armoredSignature))
}

// VerifyShasumSignature verifies the GPG signature of a SHA256SUMS file
func VerifyShasumSignature(shasumsContent string, signatureContent string, publicKey string) error {
	if shasumsContent == "" {
		return fmt.Errorf("SHA256SUMS content cannot be empty")
	}

	if signatureContent == "" {
		return fmt.Errorf("signature content cannot be empty")
	}

	// Convert signature to bytes
	signatureBytes := []byte(signatureContent)
	dataBytes := []byte(shasumsContent)

	// Verify the signature
	return VerifySignature(publicKey, dataBytes, signatureBytes)
}

// ExtractChecksumFromShasums extracts the checksum for a specific filename from SHA256SUMS content
func ExtractChecksumFromShasums(shasumsContent string, filename string) (string, error) {
	lines := strings.Split(shasumsContent, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// SHA256SUMS format: "<checksum>  <filename>"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			checksum := parts[0]
			file := strings.Join(parts[1:], " ")

			// Remove leading asterisk or space from filename if present
			file = strings.TrimPrefix(file, "*")
			file = strings.TrimSpace(file)

			if file == filename {
				return checksum, nil
			}
		}
	}

	return "", fmt.Errorf("checksum not found for file: %s", filename)
}

// ValidateChecksumMatch verifies that a calculated checksum matches the expected checksum
func ValidateChecksumMatch(calculated string, expected string) error {
	// Normalize to lowercase for comparison
	calculated = strings.ToLower(calculated)
	expected = strings.ToLower(expected)

	if calculated != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, calculated)
	}

	return nil
}

// IsValidGPGKeyFormat performs basic validation on GPG key format
func IsValidGPGKeyFormat(key string) bool {
	if key == "" {
		return false
	}

	// Check for required markers
	hasBegin := strings.Contains(key, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
	hasEnd := strings.Contains(key, "-----END PGP PUBLIC KEY BLOCK-----")

	// Check that BEGIN comes before END
	if hasBegin && hasEnd {
		beginIdx := strings.Index(key, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
		endIdx := strings.Index(key, "-----END PGP PUBLIC KEY BLOCK-----")
		return beginIdx < endIdx
	}

	return false
}

// NormalizeGPGKey normalizes a GPG public key by ensuring proper line endings and format
func NormalizeGPGKey(key string) string {
	// Replace Windows line endings with Unix
	key = strings.ReplaceAll(key, "\r\n", "\n")

	// Trim whitespace
	key = strings.TrimSpace(key)

	// Ensure it ends with a newline
	if !strings.HasSuffix(key, "\n") {
		key += "\n"
	}

	return key
}

// ValidateProviderBinary performs basic validation on a provider binary file
func ValidateProviderBinary(data []byte, maxSize int64) error {
	if len(data) == 0 {
		return fmt.Errorf("provider binary cannot be empty")
	}

	if int64(len(data)) > maxSize {
		return fmt.Errorf("provider binary too large: %d bytes (max %d bytes)", len(data), maxSize)
	}

	// Check for ZIP magic bytes (PK\x03\x04 or PK\x05\x06 for empty ZIP)
	if len(data) < 4 {
		return fmt.Errorf("provider binary too small to be a valid ZIP file")
	}

	if !bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}) && // PK\x03\x04
		!bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x05, 0x06}) { // PK\x05\x06 (empty)
		return fmt.Errorf("provider binary is not a valid ZIP file")
	}

	return nil
}

// GPGVerificationResult contains the result of a GPG verification operation
type GPGVerificationResult struct {
	Verified       bool
	KeyID          string
	KeyFingerprint string
	Error          error
}

// VerifyProviderSignature verifies a provider's SHASUM signature and returns detailed results
func VerifyProviderSignature(shasumsContent []byte, signatureContent []byte, publicKeys []string) *GPGVerificationResult {
	result := &GPGVerificationResult{
		Verified: false,
	}

	if len(shasumsContent) == 0 {
		result.Error = fmt.Errorf("SHASUM content is empty")
		return result
	}

	if len(signatureContent) == 0 {
		result.Error = fmt.Errorf("signature content is empty")
		return result
	}

	if len(publicKeys) == 0 {
		result.Error = fmt.Errorf("no public keys provided")
		return result
	}

	// Try each public key until one verifies
	var lastErr error
	for _, key := range publicKeys {
		if key == "" {
			continue
		}

		err := VerifySignature(key, shasumsContent, signatureContent)
		if err == nil {
			result.Verified = true
			// Try to extract key ID
			keyReader := strings.NewReader(key)
			keyring, err := openpgp.ReadArmoredKeyRing(keyReader)
			if err == nil && len(keyring) > 0 {
				result.KeyID = fmt.Sprintf("%X", keyring[0].PrimaryKey.KeyId)
				result.KeyFingerprint = fmt.Sprintf("%X", keyring[0].PrimaryKey.Fingerprint)
			}
			return result
		}
		lastErr = err
	}

	result.Error = fmt.Errorf("signature verification failed with all provided keys: %v", lastErr)
	return result
}
