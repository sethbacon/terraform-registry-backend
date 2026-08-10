package api

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// suite-identity #153, read side for oidc_config.client_secret_encrypted.
//
// applyPersistedOIDCProvider is the ONLY consumer of this column, and it runs at
// startup. A wrong or missing context here does not fail a build or a test that
// only round-trips through the writer; it fails the first time the service boots
// after the backfill, as SSO silently not being configured.
//
// The function is deliberately non-fatal — every failure is logged and the app
// serves without OIDC — so the decrypt outcome is observed through its log line
// rather than a return value. That is also the honest thing to assert: "SSO went
// missing and something was written to the log" is exactly what an operator
// would be looking at.

const decryptFailureLog = "Failed to decrypt OIDC client secret from database"

// oidcConfigCols is the column set identity's GetActiveOIDCConfig scans.
var oidcConfigCols = []string{
	"id", "name", "provider_type", "issuer_url", "client_id",
	"client_secret_encrypted", "redirect_url", "scopes", "is_active",
	"extra_config", "created_at", "updated_at", "created_by", "updated_by",
}

func TestApplyPersistedOIDCProvider_ClientSecretBinding(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 59)
	}
	tc, err := crypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}

	id := uuid.New()
	other := uuid.New()
	const secret = "s3cr3t-oidc-client-secret"

	seal := func(ctx []byte) string {
		s, sErr := tc.SealWithContext(secret, ctx)
		if sErr != nil {
			t.Fatalf("SealWithContext: %v", sErr)
		}
		return s
	}
	legacy, err := tc.Seal(secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name           string
		ciphertext     string
		wantDecryptErr bool
	}{
		{"bound to its own row", seal(models.OIDCConfigClientSecretContext(id.String())), false},
		{"legacy unbound ciphertext still readable", legacy, false},
		{"bound to a different oidc_config row", seal(models.OIDCConfigClientSecretContext(other.String())), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, mock, dbErr := sqlmock.New()
			if dbErr != nil {
				t.Fatal(dbErr)
			}
			defer db.Close()

			mock.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").
				WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
					id, "default", "generic_oidc", "https://issuer.invalid", "client-id",
					c.ciphertext, "https://app/callback", []byte(`["openid"]`), true,
					[]byte(`{}`), time.Now(), time.Now(), nil, nil,
				))
			repo := repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock"))

			logged := captureLogs(t, func() {
				// authHandlers is only touched once a live provider is built,
				// which needs the issuer to be reachable; nil is safe because
				// every path before that point is what this test exercises.
				applyPersistedOIDCProvider(nil, repo, tc)
			})

			failed := strings.Contains(logged, decryptFailureLog)
			if failed != c.wantDecryptErr {
				if c.wantDecryptErr {
					t.Fatalf("a secret belonging to another oidc_config row was accepted; "+
						"the binding is not enforced on read. log=%s", logged)
				}
				t.Fatalf("the client secret could not be decrypted: %s", logged)
			}
		})
	}
}

// captureLogs redirects slog for the duration of fn and returns what was
// written, restoring the previous logger afterwards.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}
