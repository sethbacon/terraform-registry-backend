package crypto

import "math"

// MinRecommendedEntropyBitsPerByte is the Shannon-entropy threshold (bits per byte)
// below which a secret is flagged as likely low-entropy (e.g. a human-typed
// passphrase rather than CSPRNG output). Random hex output (the documented way to
// generate ENCRYPTION_KEY / TFR_JWT_SECRET, e.g. `openssl rand -hex 16`) draws from
// a 16-character alphabet with a near-uniform distribution, so it lands close to
// its theoretical maximum of 4 bits/byte. Ordinary typed text/passphrases are
// comfortably below this threshold due to repeated characters and limited alphabet
// diversity. The threshold is intentionally conservative to avoid false positives
// on legitimate hex/base64 keys.
const MinRecommendedEntropyBitsPerByte = 3.0

// EstimateShannonEntropy returns the Shannon entropy of data, in bits per byte.
// Uniformly random bytes over the full 0-255 range approach 8 bits/byte; uniformly
// random hex/base64 text approaches ~4/6 bits/byte respectively; typed passphrases
// and other natural-language-like text are typically well below that.
func EstimateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	n := float64(len(data))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// IsLikelyLowEntropySecret reports whether data's estimated Shannon entropy falls
// below MinRecommendedEntropyBitsPerByte, suggesting it was human-typed rather than
// generated with a CSPRNG (e.g. `openssl rand -hex 16`). This is a heuristic, not a
// security boundary: it can neither prove nor disprove true randomness, so callers
// should only use it to emit an operator-facing warning, never to reject a key outright.
func IsLikelyLowEntropySecret(data []byte) bool {
	return EstimateShannonEntropy(data) < MinRecommendedEntropyBitsPerByte
}
