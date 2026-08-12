package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
)

// Completing a key rotation (#848).
//
// bind-secrets converts a ciphertext's FORM — unbound to row-bound — and skips
// any row it can already open under its own context. OpenWithContext goes
// through the dual-key path, so a row bound before a rotation opens under
// ENCRYPTION_KEY_PREVIOUS, counts as done, and is never re-encrypted. Nothing
// breaks and nothing signals; the previous key simply becomes permanent, which
// means the rotation never finishes.
//
// The two questions are genuinely different and both need answering, so this is
// a second sweep over the same registry rather than a flag on the first:
//
//	bind-secrets   — is every ciphertext bound to its row?
//	rekey-secrets  — is every ciphertext readable WITHOUT the previous key?
//
// The obvious implementation does not work, and it is worth writing down why.
// Dropping bind-secrets' already-bound short-circuit and always calling
// ReSealWithContext looks like a one-line fix, but ReSealWithContext opens with
// NO additional data — it is the unbound-to-bound converter — so it fails
// outright on an already-bound row. Every row in a converted estate would be
// reported as a failure. Re-encrypting a bound row means opening it WITH its
// context and sealing it again with the same context.

// ErrPreviousKeyStillRequired is returned by a verify run that found rows only
// the previous key can open.
//
// It is the exit criterion for the rotation runbook, in the same way
// ErrUnboundRemain is for the binding migration: while it is returned,
// ENCRYPTION_KEY_PREVIOUS must stay in place, and a nil error is what says the
// key can be deleted. A gate that only prints is not a gate — a runbook step
// needs a non-zero exit to hang off.
var ErrPreviousKeyStillRequired = errors.New("maintenance: secrets remain encrypted under the previous key")

// ErrEncryptionKeyMismatch is returned when the ENCRYPTION_KEY handed to
// RekeySecrets is not the key the supplied cipher seals with.
//
// A sentinel rather than a bare error so the refusal is distinguishable from
// "the sweep ran and something went wrong" — by a caller, and by the test that
// has to prove the check happens before a single row is read.
var ErrEncryptionKeyMismatch = errors.New("maintenance: ENCRYPTION_KEY is not the key this cipher seals with")

// keyProbeContext is the AAD for the sealing-key probe below. It names no row
// and protects no stored value; it exists only so the probe goes through the
// same bound seal/open pair the real rows do.
var keyProbeContext = []byte("maintenance:rekey:sealing-key-probe")

// RekeySecrets re-encrypts every registered secret under the CURRENT encryption
// key, or with verifyOnly reports what still requires the previous one without
// writing.
//
// tc is the cipher the server runs with — current key, previous key as the
// decryption fallback. currentKey is the raw ENCRYPTION_KEY, from which this
// builds a cipher with NO fallback: that second cipher is the only thing that
// can answer "which key is this row under", because a successful open on tc
// cannot distinguish the two. Taking the key bytes rather than a second
// *TokenCipher is what makes the oracle trustworthy — a caller cannot hand in
// something that quietly still has a previous key configured, which would make
// every verify run pass.
//
// Safe to re-run: a row already bound under the current key is left untouched,
// so a second run writes nothing. Safe to interrupt: rows are written one at a
// time and both keys still open, so a half-finished run is resumed by running
// it again.
//
// It also subsumes binding. A row that is unbound converges to bound-and-current
// in the same pass, so a deployment that never ran bind-secrets does not need
// two commands in a particular order.
//
// A row that cannot be opened at all — corrupt, or bound to a DIFFERENT row's
// context — is reported and stepped over, and holds the gate shut. It is never
// re-sealed into the row it was found in: doing so would mint the valid binding
// an attacker who moved it could not forge, turning the rotation into the
// laundering step for exactly the attack the AAD exists to detect.
func RekeySecrets(
	ctx context.Context,
	db *sql.DB,
	tc *crypto.TokenCipher,
	currentKey []byte,
	verifyOnly bool,
) (map[string]Result, error) {
	if tc == nil {
		return nil, errors.New("maintenance: no token cipher configured (set ENCRYPTION_KEY)")
	}
	current, err := crypto.NewTokenCipher(currentKey)
	if err != nil {
		return nil, fmt.Errorf("maintenance: ENCRYPTION_KEY is not a usable AES-256 key: %w", err)
	}
	if err := proveSealingKey(tc, current); err != nil {
		return nil, err
	}

	results, remains, err := sweep(ctx, db, verifyOnly, "already-current",
		func(col column, row sealedRow) (string, bool, error) {
			aad := col.context(row.id)

			// The only question that matters: does this row still need the
			// previous key? A cipher holding just the current key answers it;
			// tc cannot, which is the bug.
			if _, err := current.OpenWithContext(row.sealed, aad); err == nil {
				return "", false, nil
			}

			// Either form, either key. OpenWithContextOrLegacy is what lets one
			// pass converge a row that is unbound AND on the previous key,
			// without a separate branch that would need its own proof.
			//
			// It widens which FORMATS are accepted, never which contexts: a
			// value bound to another row fails both attempts and lands in the
			// error path below, unmodified.
			plaintext, _, err := tc.OpenWithContextOrLegacy(row.sealed, aad)
			if err != nil {
				return "", true, err
			}
			resealed, err := tc.SealWithContext(plaintext, aad)
			if err != nil {
				return "", true, err
			}

			// Prove the replacement before it overwrites a live credential.
			// Everything below the gate depends on this value opening under the
			// current key alone, and the cost of finding out otherwise is an
			// administrator re-entering a secret by hand.
			roundTripped, err := current.OpenWithContext(resealed, aad)
			if err != nil {
				return "", true, fmt.Errorf("re-encrypted value does not open under the current key: %w", err)
			}
			if roundTripped != plaintext {
				return "", true, errors.New("re-encrypted value does not match the secret it was made from")
			}
			return resealed, true, nil
		})
	if err != nil {
		return results, err
	}

	if verifyOnly && remains {
		return results, ErrPreviousKeyStillRequired
	}
	return results, nil
}

// proveSealingKey checks that currentKey really is the key tc seals with, before
// any row is read or written.
//
// Without it, a wrong ENCRYPTION_KEY produces a sweep in which every row appears
// to need re-encryption and every re-encryption then fails its own read-back —
// technically fail-closed, but the operator sees "47 rows failed" during a key
// rotation, which is the worst possible moment to have to work out whether the
// data or the key is at fault.
func proveSealingKey(tc, current *crypto.TokenCipher) error {
	probe, err := tc.SealWithContext("sealing-key-probe", keyProbeContext)
	if err != nil {
		return fmt.Errorf("maintenance: could not seal the key probe: %w", err)
	}
	if _, err := current.OpenWithContext(probe, keyProbeContext); err != nil {
		return fmt.Errorf("%w; re-encryption would write values the running service cannot read",
			ErrEncryptionKeyMismatch)
	}
	return nil
}
