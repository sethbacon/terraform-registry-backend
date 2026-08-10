// tokencipher.go re-exports the shared TokenCipher from
// github.com/sethbacon/terraform-suite-identity/identity/crypto.
//
// It used to be a 295-line COPY of that implementation, and the copy had
// drifted: suite-identity #153 raised the PBKDF2 floor to OWASP's 600,000 and
// made it reject rather than silently rewrite, and it added the GCM
// additional-authenticated-data pair that binds a ciphertext to the row it
// belongs to. Neither reached this file. A security fix had been applied to one
// copy of a cryptographic primitive and not the other, and nothing anywhere
// produced a signal — the ADO extension repo gates its duplicated modules with
// scripts/check-shared-modules.js, but no equivalent exists between the Go
// repos (#835).
//
// Aliasing rather than re-syncing is deliberate: a parity gate only tells you
// after a copy has already drifted, whereas there is now no second copy to
// drift. It also means the AAD methods arrive here automatically, since they are
// methods on the aliased type.
//
// This is a drop-in for data already at rest. The two implementations were
// verified wire-compatible in both directions before the swap — same
// construction (AES-256-GCM), same framing (nonce prepended), same encoding
// (base64.URLEncoding), same nil AAD, same empty-string handling — so every SCM
// token, client secret, app private key and storage credential already stored
// keeps opening. No re-encryption, no migration.
//
// entropy.go stays local: it is this service's own heuristic, not shared.
package crypto

import (
	identitycrypto "github.com/sethbacon/terraform-suite-identity/identity/crypto"
)

// TokenCipher encrypts and decrypts sensitive values held at rest.
//
// Alias, not a wrapper, so the methods added upstream — SealWithContext,
// OpenWithContext, OpenWithContextOrLegacy and ReSealWithContext — are available
// here without this file having to track them.
type TokenCipher = identitycrypto.TokenCipher

// Constructors. Vars rather than wrapper funcs so the signatures cannot drift
// from upstream's.
var (
	// NewTokenCipher creates a cipher with a 32-byte master key.
	NewTokenCipher = identitycrypto.NewTokenCipher
	// NewTokenCipherWithPrevious creates a cipher that supports dual-key
	// decryption for zero-downtime key rotation.
	NewTokenCipherWithPrevious = identitycrypto.NewTokenCipherWithPrevious
	// DeriveTokenCipher derives a key from a passphrase.
	//
	// Behaviour change from the copy this replaces: an explicit iteration count
	// below MinPBKDF2Iterations is now REJECTED with ErrIterationsTooLow instead
	// of being silently rewritten, and the floor is OWASP's 600,000 rather than
	// 10,000. Nothing in this repo calls it, so the change is latent here — but
	// a future caller now fails loudly instead of deriving a weak key while
	// believing otherwise.
	DeriveTokenCipher = identitycrypto.DeriveTokenCipher
	// GenerateKey creates a cryptographically secure random 32-byte key.
	GenerateKey = identitycrypto.GenerateKey
	// GenerateSalt creates a cryptographically secure random salt.
	GenerateSalt = identitycrypto.GenerateSalt
)

// Sentinel errors, re-exported so existing errors.Is checks in this service keep
// matching. They must be the SAME values upstream returns, not new ones with the
// same text — a fresh errors.New here would compare unequal and silently break
// every errors.Is call site.
var (
	ErrKeyLengthInvalid    = identitycrypto.ErrKeyLengthInvalid
	ErrCiphertextCorrupted = identitycrypto.ErrCiphertextCorrupted
	ErrDecryptionFailed    = identitycrypto.ErrDecryptionFailed
	ErrSaltTooShort        = identitycrypto.ErrSaltTooShort
	// ErrIterationsTooLow has no local predecessor: the copy silently rewrote a
	// low iteration count instead of rejecting it.
	ErrIterationsTooLow = identitycrypto.ErrIterationsTooLow
)

// MinPBKDF2Iterations and DefaultPBKDF2Iterations are re-exported so callers can
// reason about the work factor without importing the upstream package directly.
const (
	MinPBKDF2Iterations     = identitycrypto.MinPBKDF2Iterations
	DefaultPBKDF2Iterations = identitycrypto.DefaultPBKDF2Iterations
)
