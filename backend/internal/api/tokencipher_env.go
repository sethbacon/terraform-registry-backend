package api

import (
	"errors"
	"os"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
)

// BuildTokenCipherFromEnv constructs the TokenCipher from the same environment
// the server uses: ENCRYPTION_KEY, plus ENCRYPTION_KEY_PREVIOUS for the
// zero-downtime rotation fallback.
//
// Exported so the bind-secrets maintenance command shares this exact key source
// rather than re-reading the environment itself. The backfill must open what the
// server sealed; a second key path is a second thing to drift, which is how the
// duplicated cipher in #835 ended up an OWASP revision behind.
//
// It returns errors instead of calling log.Fatal, because a CLI subcommand
// should report a bad key and exit rather than die inside a library call. The
// server's startup path keeps its own fatal behaviour at the call site, so the
// operator-facing messages there are unchanged.
//
// The low-entropy gate deliberately stays at startup and is NOT applied here. It
// is a policy about whether this deployment should be SERVING, not about whether
// a one-shot conversion may read the data already encrypted under that key —
// refusing to convert because the existing key is weak would strand exactly the
// deployments that most need to re-encrypt.
func BuildTokenCipherFromEnv() (*crypto.TokenCipher, error) {
	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		return nil, errors.New("ENCRYPTION_KEY must be set")
	}
	if previous := os.Getenv("ENCRYPTION_KEY_PREVIOUS"); previous != "" {
		return crypto.NewTokenCipherWithPrevious([]byte(key), []byte(previous))
	}
	return crypto.NewTokenCipher([]byte(key))
}
