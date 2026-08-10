package maintenance

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// suite-identity #153, the config-blob secrets. These two are not columns: they
// are FIELDS inside JSON blobs on the system_settings singleton, so converting
// one is a read-modify-write of the whole blob rather than an UPDATE of a
// column.
//
// That makes the sweep's failure mode different from every other column's. A
// column conversion can only damage the ciphertext it is converting; a blob
// conversion rewrites the entire notifications or LDAP configuration, so a
// mistake in the rewrite loses settings that have nothing to do with
// cryptography. The tests below are weighted accordingly.

const (
	smtpCol = "system_settings.notifications_config:smtp.smtp_password_encrypted"
	ldapCol = "system_settings.ldap_config:bind_password_enc"
)

func TestBindSecrets_ConvertsTheSMTPPasswordInsideItsBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	legacy, err := tc.Seal("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	blob := `{"enabled":true,"recipients":["ops@example.com"],` +
		`"smtp":{"host":"smtp.example.com","port":587,"smtp_password_encrypted":"` + legacy + `"}}`

	var written []byte
	drive(t, mock, smtpCol, func() {
		// list reads the blob...
		mock.ExpectQuery("SELECT notifications_config FROM system_settings").
			WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow([]byte(blob)))
		// ...and update re-reads it before rewriting, so the write is against
		// what is actually stored rather than a stale copy from the listing.
		mock.ExpectQuery("SELECT notifications_config FROM system_settings").
			WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow([]byte(blob)))
		mock.ExpectExec("UPDATE system_settings SET notifications_config").
			WithArgs(blobCapture{into: &written}).
			WillReturnResult(sqlmock.NewResult(0, 1))
	})

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	if got := res[smtpCol]; got.Converted != 1 || got.Failed != 0 {
		t.Fatalf("result = %s; want one conversion", got)
	}

	var out map[string]any
	if err := json.Unmarshal(written, &out); err != nil {
		t.Fatalf("the rewritten blob is not valid JSON: %v", err)
	}

	smtp, ok := out["smtp"].(map[string]any)
	if !ok {
		t.Fatal("the rewritten blob lost its smtp object")
	}
	bound, _ := smtp["smtp_password_encrypted"].(string)
	got, err := tc.OpenWithContext(bound, models.SystemSettingsSMTPPasswordContext())
	if err != nil || got != "hunter2" {
		t.Fatalf("converted password does not open under the application's context: (%q, %v)", got, err)
	}
	if _, err := tc.Open(bound); err == nil {
		t.Error("converted password still opens WITHOUT a context; it was not bound")
	}
	if _, err := tc.OpenWithContext(bound, models.SystemSettingsLDAPBindPasswordContext()); err == nil {
		t.Error("converted password also opens as the LDAP bind password; the two fields of " +
			"system_settings are interchangeable")
	}
}

// The one that matters most. The blob is the whole notifications configuration,
// so rewriting it through the typed struct the application unmarshals into would
// silently drop every key that struct does not know about — an older setting, a
// newer one written by a replica mid-upgrade, anything hand-added — and turn a
// credential conversion into config data loss on a tool that runs once, against
// production, usually unattended.
func TestBindSecrets_BlobRewritePreservesUnknownFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	legacy, err := tc.Seal("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	blob := `{"enabled":true,"a_setting_this_build_has_never_heard_of":{"deep":[1,2,3]},` +
		`"recipients":["ops@example.com"],` +
		`"smtp":{"host":"smtp.example.com","port":587,"an_unknown_smtp_key":"keep me",` +
		`"smtp_password_encrypted":"` + legacy + `"}}`

	var written []byte
	drive(t, mock, smtpCol, func() {
		rows := func() *sqlmock.Rows {
			return sqlmock.NewRows([]string{"notifications_config"}).AddRow([]byte(blob))
		}
		mock.ExpectQuery("SELECT notifications_config FROM system_settings").WillReturnRows(rows())
		mock.ExpectQuery("SELECT notifications_config FROM system_settings").WillReturnRows(rows())
		mock.ExpectExec("UPDATE system_settings SET notifications_config").
			WithArgs(blobCapture{into: &written}).
			WillReturnResult(sqlmock.NewResult(0, 1))
	})

	if _, err := BindSecrets(context.Background(), db, tc, false); err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}

	var before, after map[string]any
	if err := json.Unmarshal([]byte(blob), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(written, &after); err != nil {
		t.Fatalf("the rewritten blob is not valid JSON: %v", err)
	}

	// Everything except the one field being converted must survive byte-for-byte
	// in meaning. Comparing re-marshalled JSON of the pruned maps catches a
	// dropped key, a changed type and a reordered array alike.
	delete(before["smtp"].(map[string]any), "smtp_password_encrypted")
	delete(after["smtp"].(map[string]any), "smtp_password_encrypted")
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Errorf("the sweep changed configuration it was not converting.\n before: %s\n  after: %s", b, a)
	}
}

// The LDAP password sits at the TOP level of its blob rather than nested under
// an object, so it exercises the empty-path branch of the same rewrite.
func TestBindSecrets_ConvertsTheLDAPBindPassword(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	legacy, err := tc.Seal("bind-secret")
	if err != nil {
		t.Fatal(err)
	}
	blob := `{"host":"ldap.example.com","port":636,"bind_dn":"cn=svc","bind_password_enc":"` + legacy + `"}`

	var written []byte
	drive(t, mock, ldapCol, func() {
		rows := func() *sqlmock.Rows {
			return sqlmock.NewRows([]string{"ldap_config"}).AddRow([]byte(blob))
		}
		mock.ExpectQuery("SELECT ldap_config FROM system_settings").WillReturnRows(rows())
		mock.ExpectQuery("SELECT ldap_config FROM system_settings").WillReturnRows(rows())
		mock.ExpectExec("UPDATE system_settings SET ldap_config").
			WithArgs(blobCapture{into: &written}).
			WillReturnResult(sqlmock.NewResult(0, 1))
	})

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	if got := res[ldapCol]; got.Converted != 1 || got.Failed != 0 {
		t.Fatalf("result = %s; want one conversion", got)
	}

	var out map[string]any
	if err := json.Unmarshal(written, &out); err != nil {
		t.Fatal(err)
	}
	bound, _ := out["bind_password_enc"].(string)
	got, err := tc.OpenWithContext(bound, models.SystemSettingsLDAPBindPasswordContext())
	if err != nil || got != "bind-secret" {
		t.Fatalf("converted password does not open under the application's context: (%q, %v)", got, err)
	}
	if _, err := tc.OpenWithContext(bound, models.SystemSettingsSMTPPasswordContext()); err == nil {
		t.Error("converted password also opens as the SMTP password; the two fields are interchangeable")
	}
}

// An unset field is not a conversion candidate, and neither is an absent blob.
// Getting this wrong would report a permanent "1 row failed" against a
// deployment that simply has no SMTP configured, which is how a verify gate
// becomes noise people learn to ignore.
func TestBindSecrets_BlobWithNoSecretIsNotACandidate(t *testing.T) {
	cases := []struct {
		name string
		blob any
	}{
		{"field absent", []byte(`{"enabled":false,"smtp":{"host":""}}`)},
		{"field present but empty", []byte(`{"smtp":{"smtp_password_encrypted":""}}`)},
		{"smtp object absent", []byte(`{"enabled":false}`)},
		{"blob column null", nil},
		{"blob column empty", []byte(``)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tc := newCipher(t)

			drive(t, mock, smtpCol, func() {
				mock.ExpectQuery("SELECT notifications_config FROM system_settings").
					WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow(c.blob))
			})

			// verify mode: nothing to convert must mean a clean exit, which is
			// the signal the whole gate hangs off.
			res, err := BindSecrets(context.Background(), db, tc, true)
			if err != nil {
				t.Fatalf("verify with nothing to convert must succeed, got %v", err)
			}
			if got := res[smtpCol]; got.Total != 0 || got.Converted != 0 || got.Failed != 0 {
				t.Errorf("result = %s; an unset password is not a conversion candidate", got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("no write should have been attempted: %v", err)
			}
		})
	}
}

// blobCapture records the JSON argument of the rewrite.
type blobCapture struct{ into *[]byte }

func (b blobCapture) Match(v driver.Value) bool {
	switch x := v.(type) {
	case []byte:
		*b.into = append([]byte(nil), x...)
	case string:
		*b.into = []byte(x)
	}
	return true
}
