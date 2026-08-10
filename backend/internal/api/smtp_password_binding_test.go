package api

import (
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// suite-identity #153, read side for the SMTP password.
//
// The password lives in a field of the notifications_config JSON blob on the
// system_settings singleton, so it has no row to bind to; its context names the
// blob and the field instead. That is a weaker binding than the row-scoped ones,
// and this test is about the part it does buy: the LDAP bind password sits in
// the OTHER blob on the SAME row, so without the field in the context the two
// would be interchangeable.
//
// reloadNotificationsConfigFromDB writes the decrypted password straight onto
// cfg.Notifications.SMTP.Password, which makes the outcome directly observable —
// no log scraping needed here.

func TestReloadNotificationsConfigFromDB_SMTPPasswordBinding(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 71)
	}
	tc, err := crypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}

	const password = "hunter2"
	seal := func(ctx []byte) string {
		s, sErr := tc.SealWithContext(password, ctx)
		if sErr != nil {
			t.Fatalf("SealWithContext: %v", sErr)
		}
		return s
	}
	legacy, err := tc.Seal(password)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name       string
		ciphertext string
		wantLoaded bool
	}{
		{"bound to its own field", seal(models.SystemSettingsSMTPPasswordContext()), true},
		{"legacy unbound ciphertext still readable", legacy, true},
		// The move this binding exists to stop: the other secret in the same
		// system_settings row, pasted into this field.
		{"bound as the LDAP bind password of the same row",
			seal(models.SystemSettingsLDAPBindPasswordContext()), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, mock, dbErr := sqlmock.New()
			if dbErr != nil {
				t.Fatal(dbErr)
			}
			defer db.Close()

			blob := `{"enabled":true,"smtp":{"host":"smtp.example.com","port":587,` +
				`"smtp_password_encrypted":"` + c.ciphertext + `"}}`
			mock.ExpectQuery("SELECT notifications_config FROM system_settings").
				WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow([]byte(blob)))

			repo := repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock"))
			cfg := &config.Config{}
			reloadNotificationsConfigFromDB(cfg, repo, tc)

			got := cfg.Notifications.SMTP.Password
			if c.wantLoaded {
				if got != password {
					t.Fatalf("SMTP password = %q, want %q; the stored password could not be decrypted",
						got, password)
				}
				return
			}
			if got != "" {
				t.Fatalf("a ciphertext belonging to another field of the same row was accepted as "+
					"the SMTP password (%q); the binding is not enforced on read", got)
			}
			// The rest of the configuration still loads: a credential that will
			// not decrypt must not take the whole notifications config with it.
			if cfg.Notifications.SMTP.Host != "smtp.example.com" {
				t.Errorf("SMTP host = %q; a failed decrypt should not discard the rest of the config",
					cfg.Notifications.SMTP.Host)
			}
		})
	}
}
