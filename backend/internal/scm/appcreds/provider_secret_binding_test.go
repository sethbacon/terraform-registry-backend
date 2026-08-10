package appcreds

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// suite-identity #153, read side for the scm_providers secrets.
//
// entraCreds and githubAppCreds are where the client secret and the GitHub App
// private key are decrypted for the shared, admin-managed credential path. They
// are also the pair that shares a row, so both axes matter here: a ciphertext
// from another provider must be refused, and so must one from the sibling column
// of this provider.
//
// Each case fails if the read is written differently:
//
//	bound          -- reads the new form (fails if the context is dropped)
//	legacy         -- still reads the old form (fails if OpenWithContext replaces
//	                  OpenWithContextOrLegacy before the backfill has run)
//	other provider -- refuses a secret lifted from a different provider row
//	sibling column -- refuses one lifted from the other column of THIS row

func bindingCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 41)
	}
	tc, err := crypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

func TestEntraCreds_ClientSecretBinding(t *testing.T) {
	tc := bindingCipher(t)
	m := NewMinter(tc, &fakeStore{})

	id := uuid.New()
	other := uuid.New()
	tenant := "tenant-1"
	const secret = "s3cr3t-entra-client-secret"

	for _, c := range secretBindingCases(t, tc, secret,
		scm.ProviderClientSecretContext(id.String()),
		scm.ProviderClientSecretContext(other.String()),
		scm.ProviderAppPrivateKeyContext(id.String()),
	) {
		t.Run(c.name, func(t *testing.T) {
			p := &scm.SCMProvider{
				ID:                    id,
				TenantID:              &tenant,
				ClientID:              "client-id",
				ClientSecretEncrypted: c.ciphertext,
			}
			creds, err := m.entraCreds(p)
			if c.wantUsable {
				if err != nil {
					t.Fatalf("the client secret could not be decrypted: %v", err)
				}
				if creds.ClientSecret != secret {
					t.Fatalf("client secret = %q, want %q", creds.ClientSecret, secret)
				}
				return
			}
			if err == nil {
				t.Fatal("a ciphertext that does not belong to this row+column was accepted; " +
					"the binding is not enforced on read")
			}
			if !strings.Contains(err.Error(), "decrypt client secret") {
				t.Fatalf("error = %v, want the decrypt failure", err)
			}
		})
	}
}

func TestGitHubAppCreds_PrivateKeyBinding(t *testing.T) {
	tc := bindingCipher(t)
	m := NewMinter(tc, &fakeStore{})

	id := uuid.New()
	other := uuid.New()
	appID, instID := "12345", "67890"
	keyPEM := generateTestKeyPEM(t)

	for _, c := range secretBindingCases(t, tc, keyPEM,
		scm.ProviderAppPrivateKeyContext(id.String()),
		scm.ProviderAppPrivateKeyContext(other.String()),
		scm.ProviderClientSecretContext(id.String()),
	) {
		t.Run(c.name, func(t *testing.T) {
			ct := c.ciphertext
			p := &scm.SCMProvider{
				ID:                     id,
				GitHubAppID:            &appID,
				GitHubInstallationID:   &instID,
				EncryptedAppPrivateKey: &ct,
			}
			creds, err := m.githubAppCreds(p)
			if c.wantUsable {
				if err != nil {
					t.Fatalf("the app private key could not be decrypted: %v", err)
				}
				if creds.PrivateKeyPEM != keyPEM {
					t.Fatal("the decrypted private key does not match what was sealed")
				}
				return
			}
			if err == nil {
				t.Fatal("a ciphertext that does not belong to this row+column was accepted; " +
					"an App private key could be replayed from another provider row")
			}
			if !strings.Contains(err.Error(), "decrypt app private key") {
				t.Fatalf("error = %v, want the decrypt failure", err)
			}
		})
	}
}

type secretBindingCase struct {
	name       string
	ciphertext string
	wantUsable bool
}

// secretBindingCases builds the four ciphertexts a read has to distinguish:
// sealed under its own context, sealed unbound (the pre-backfill form), sealed
// under the same column of ANOTHER row, and sealed under the SIBLING column of
// this row.
func secretBindingCases(
	t *testing.T,
	tc *crypto.TokenCipher,
	plaintext string,
	own, otherRow, siblingColumn []byte,
) []secretBindingCase {
	t.Helper()
	seal := func(ctx []byte) string {
		s, err := tc.SealWithContext(plaintext, ctx)
		if err != nil {
			t.Fatalf("SealWithContext: %v", err)
		}
		return s
	}
	legacy, err := tc.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return []secretBindingCase{
		{"bound to its own row and column", seal(own), true},
		{"legacy unbound ciphertext still readable", legacy, true},
		{"bound to a different provider", seal(otherRow), false},
		{"bound to the sibling column of the same row", seal(siblingColumn), false},
	}
}
