package scm_test

import (
	"testing"

	"github.com/google/uuid"
	identitycrypto "github.com/sethbacon/terraform-suite-identity/identity/crypto"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// suite-identity #153 — the contexts that bind each stored SCM secret to the row
// and column it belongs to. What is worth pinning is not the string format but
// the SEPARATIONS: which ciphertexts must not be interchangeable with which.

func cipher(t *testing.T) *identitycrypto.TokenCipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	tc, err := identitycrypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

// The separation that a row-level context alone would NOT give: access and
// refresh live in the same row, so binding only to the row would let a
// long-lived refresh token be written into the access column and still
// authenticate — handing a long-lived credential to a path expecting a short one.
func TestUserTokenContexts_AccessAndRefreshAreNotInterchangeableWithinARow(t *testing.T) {
	tc := cipher(t)
	user, provider := uuid.New(), uuid.New()

	access, err := tc.SealWithContext("access-token", scm.UserTokenContext(user, provider))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tc.OpenWithContext(access, scm.UserRefreshTokenContext(user, provider)); err == nil {
		t.Error("an access token opened as its own row's refresh token")
	}

	refresh, err := tc.SealWithContext("refresh-token", scm.UserRefreshTokenContext(user, provider))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tc.OpenWithContext(refresh, scm.UserTokenContext(user, provider)); err == nil {
		t.Error("a refresh token opened as its own row's access token")
	}
}

// The row is keyed by user AND provider, so a token must not move along either
// axis. Binding to one alone would leave the other replayable.
func TestUserTokenContext_BindsBothAxes(t *testing.T) {
	tc := cipher(t)
	user, provider := uuid.New(), uuid.New()

	sealed, err := tc.SealWithContext("token", scm.UserTokenContext(user, provider))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tc.OpenWithContext(sealed, scm.UserTokenContext(uuid.New(), provider)); err == nil {
		t.Error("opened for a different user on the same provider")
	}
	if _, err := tc.OpenWithContext(sealed, scm.UserTokenContext(user, uuid.New())); err == nil {
		t.Error("opened for the same user on a different provider")
	}
}

// The two tables share the field NAME AccessTokenEncrypted but are keyed
// differently. Nothing in the type system stops one family's context being used
// for the other's ciphertext, so the separation is asserted here instead.
func TestProviderAndUserTokenContexts_AreNotInterchangeable(t *testing.T) {
	tc := cipher(t)
	provider := uuid.New()
	user := uuid.New()

	cached, err := tc.SealWithContext("app-token", scm.ProviderTokenContext(provider))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tc.OpenWithContext(cached, scm.UserTokenContext(user, provider)); err == nil {
		t.Error("a cached app token opened as a user's OAuth token")
	}

	userTok, err := tc.SealWithContext("user-token", scm.UserTokenContext(user, provider))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tc.OpenWithContext(userTok, scm.ProviderTokenContext(provider)); err == nil {
		t.Error("a user's OAuth token opened as the shared app-token cache entry")
	}
}
