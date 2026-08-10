package maintenance

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// suite-identity #153 backfill. The properties an operator relies on when
// running this against live credentials: safe to re-run, one bad row does not
// abandon the rest, and verify writes nothing but still fails while work remains.

func newCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	tc, err := crypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

type capturedArg struct{ got *string }

func (c capturedArg) Match(v driver.Value) bool {
	if s, ok := v.(string); ok {
		*c.got = s
	}
	return true
}

func channelRows(pairs ...[2]string) *sqlmock.Rows {
	r := sqlmock.NewRows([]string{"id", "encrypted_target"})
	for _, p := range pairs {
		r.AddRow(p[0], p[1])
	}
	return r
}

const chanCol = "notification_channels.encrypted_target"

// drive queues sqlmock expectations for a whole sweep while only one column
// actually has rows: own() runs at that column's position in the registry, and
// every other column gets an empty result.
//
// BindSecrets deliberately sweeps the entire registry, so a test naming only its
// own column leaves the rest as unexpected queries — which sqlmock fails,
// turning "a column was registered" into a pile of unrelated failures in tests
// that have nothing to do with it. Walking `columns` rather than hard-coding a
// count also keeps the expectation ORDER correct wherever a new column is
// inserted.
func drive(t *testing.T, mock sqlmock.Sqlmock, name string, own func()) {
	t.Helper()
	found := false
	for _, c := range columns {
		if c.name == name {
			found = true
			own()
			continue
		}
		mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id", "sealed"}))
	}
	if !found {
		t.Fatalf("column %q is not registered; the test drives nothing", name)
	}
}

func TestBindSecrets_ConvertsAnUnboundRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	legacy, err := tc.Seal("https://hooks.example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	drive(t, mock, chanCol, func() {
		mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
			WillReturnRows(channelRows([2]string{"chan-1", legacy}))
		mock.ExpectExec("UPDATE notification_channels").
			WithArgs(sqlmock.AnyArg(), capturedArg{got: &stored}).
			WillReturnResult(sqlmock.NewResult(0, 1))
	})

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	if got := res[chanCol]; got.Converted != 1 || got.Failed != 0 {
		t.Fatalf("result = %s; want one conversion", got)
	}

	got, err := tc.OpenWithContext(stored, identitynotify.TargetContext("chan-1"))
	if err != nil || got != "https://hooks.example.com/a" {
		t.Fatalf("converted value does not open under its row context: (%q, %v)", got, err)
	}
	if _, err := tc.Open(stored); err == nil {
		t.Error("converted value still opens WITHOUT a context; it was not bound")
	}
}

// Re-running must be a no-op, which is what makes an interrupted sweep safe to
// resume. Asserted by the absence of any UPDATE — sqlmock fails an unexpected one.
func TestBindSecrets_SkipsAnAlreadyBoundRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	bound, err := tc.SealWithContext("https://hooks.example.com/a", identitynotify.TargetContext("chan-1"))
	if err != nil {
		t.Fatal(err)
	}
	drive(t, mock, chanCol, func() {
		mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
			WillReturnRows(channelRows([2]string{"chan-1", bound}))
	})

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	if got := res[chanCol]; got.AlreadyBound != 1 || got.Converted != 0 {
		t.Fatalf("result = %s; want the row recognised as already bound", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an already-bound row should trigger no write: %v", err)
	}
}

func TestBindSecrets_OneUndecryptableRowDoesNotAbortTheSweep(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	good, err := tc.Seal("https://hooks.example.com/good")
	if err != nil {
		t.Fatal(err)
	}
	drive(t, mock, chanCol, func() {
		mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
			WillReturnRows(channelRows(
				[2]string{"chan-bad", "not-a-valid-ciphertext"},
				[2]string{"chan-good", good},
			))
		mock.ExpectExec("UPDATE notification_channels").WillReturnResult(sqlmock.NewResult(0, 1))
	})

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	got := res[chanCol]
	if got.Failed != 1 || got.Converted != 1 {
		t.Errorf("result = %s; want the bad row reported and the good one still converted", got)
	}
}

func TestBindSecrets_VerifyWritesNothingAndFailsWhileUnboundRemain(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	legacy, err := tc.Seal("https://hooks.example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	drive(t, mock, chanCol, func() {
		mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
			WillReturnRows(channelRows([2]string{"chan-1", legacy}))
	})

	res, err := BindSecrets(context.Background(), db, tc, true)
	if !errors.Is(err, ErrUnboundRemain) {
		t.Fatalf("verify error = %v, want ErrUnboundRemain so it can gate a runbook step", err)
	}
	if res[chanCol].Converted != 1 {
		t.Errorf("verify should report what WOULD convert; got %s", res[chanCol])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("verify must not write: %v", err)
	}
}

// The zero that says a column's reads can stop accepting the unbound form.
func TestBindSecrets_VerifySucceedsWhenAllBound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	bound, err := tc.SealWithContext("https://hooks.example.com/a", identitynotify.TargetContext("chan-1"))
	if err != nil {
		t.Fatal(err)
	}
	drive(t, mock, chanCol, func() {
		mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
			WillReturnRows(channelRows([2]string{"chan-1", bound}))
	})

	if _, err := BindSecrets(context.Background(), db, tc, true); err != nil {
		t.Fatalf("verify with everything bound must succeed, got %v", err)
	}
}

func TestBindSecrets_RequiresACipher(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := BindSecrets(context.Background(), db, nil, false); err == nil {
		t.Fatal("a nil cipher must be refused, not treated as 'nothing to do'")
	}
}

// Every registered column must derive its context from the row id. A constant
// context would satisfy the round-trip tests above while making the binding
// vacuous for that column, and this is the cheapest place to catch it as columns
// are added.
func TestRegisteredColumns_ContextsAreRowScoped(t *testing.T) {
	for _, col := range columns {
		if string(col.context("row-a")) == string(col.context("row-b")) {
			t.Errorf("%s derives the same context for different rows; its binding is vacuous", col.name)
		}
	}
}

// The other axis, and the one the storage columns made real: four credential
// columns now share a row, so a context that varies only by row id would let an
// S3 secret access key be written into the access-key-id column of its OWN row
// and still authenticate. Row-scoping alone does not catch that — this does.
func TestRegisteredColumns_ContextsAreColumnDistinct(t *testing.T) {
	const row = "11111111-1111-1111-1111-111111111111"
	seen := map[string]string{}
	for _, col := range columns {
		ctx := string(col.context(row))
		if other, dup := seen[ctx]; dup {
			t.Errorf("%s and %s derive the SAME context for one row; a value could be moved "+
				"between the two columns undetected", other, col.name)
			continue
		}
		seen[ctx] = col.name
	}
}

// ---------------------------------------------------------------------------
// storage_config credential columns (suite-identity #153)
// ---------------------------------------------------------------------------

// storageConfigCases pairs each registered storage column with the context
// function the APPLICATION seals and opens with. Deriving the expectation from
// models rather than from col.context is the point: this asserts the sweep and
// the running service agree, which is the failure that would leave an operator
// re-entering a cloud credential by hand.
var storageConfigCases = []struct {
	column  string
	dbCol   string
	context func(string) []byte
}{
	{"storage_config.azure_account_key_encrypted", "azure_account_key_encrypted",
		models.StorageConfigAzureAccountKeyContext},
	{"storage_config.s3_access_key_id_encrypted", "s3_access_key_id_encrypted",
		models.StorageConfigS3AccessKeyIDContext},
	{"storage_config.s3_secret_access_key_encrypted", "s3_secret_access_key_encrypted",
		models.StorageConfigS3SecretAccessKeyContext},
	{"storage_config.gcs_credentials_json_encrypted", "gcs_credentials_json_encrypted",
		models.StorageConfigGCSCredentialsJSONContext},
}

func TestBindSecrets_ConvertsEveryStorageCredentialColumn(t *testing.T) {
	const configID = "22222222-2222-2222-2222-222222222222"

	for _, sc := range storageConfigCases {
		t.Run(sc.dbCol, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tc := newCipher(t)

			secret := "secret-for-" + sc.dbCol
			legacy, err := tc.Seal(secret)
			if err != nil {
				t.Fatal(err)
			}

			var stored string
			drive(t, mock, sc.column, func() {
				mock.ExpectQuery("SELECT id, " + sc.dbCol + " FROM storage_config").
					WillReturnRows(sqlmock.NewRows([]string{"id", sc.dbCol}).AddRow(configID, legacy))
				mock.ExpectExec("UPDATE storage_config SET "+sc.dbCol).
					WithArgs(sqlmock.AnyArg(), capturedArg{got: &stored}).
					WillReturnResult(sqlmock.NewResult(0, 1))
			})

			res, err := BindSecrets(context.Background(), db, tc, false)
			if err != nil {
				t.Fatalf("BindSecrets: %v", err)
			}
			if got := res[sc.column]; got.Converted != 1 || got.Failed != 0 {
				t.Fatalf("result = %s; want one conversion", got)
			}

			// Opens under the context the application uses...
			got, err := tc.OpenWithContext(stored, sc.context(configID))
			if err != nil || got != secret {
				t.Fatalf("converted value does not open under the application's context: (%q, %v)", got, err)
			}
			// ...and no longer without one.
			if _, err := tc.Open(stored); err == nil {
				t.Error("converted value still opens WITHOUT a context; it was not bound")
			}
			// ...nor as a different column of the same row, which is the move a
			// row-only binding would still authenticate.
			for _, other := range storageConfigCases {
				if other.dbCol == sc.dbCol {
					continue
				}
				if _, err := tc.OpenWithContext(stored, other.context(configID)); err == nil {
					t.Errorf("converted value opened as %s of the same row; the columns are not distinguished",
						other.dbCol)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// scm_providers secret columns (suite-identity #153)
// ---------------------------------------------------------------------------

// The two scm_providers columns are hand-written entries rather than products of
// a shared constructor, so each needs its own proof that the sweep converts to
// the context the application reads with — and that the UPDATE names the column
// the SELECT read. These two share a row, so getting that wrong would move an
// App private key into the client-secret column.
func TestBindSecrets_ConvertsTheSCMProviderSecrets(t *testing.T) {
	const providerID = "44444444-4444-4444-4444-444444444444"

	cases := []struct {
		column  string
		dbCol   string
		context func(string) []byte
	}{
		{"scm_providers.client_secret_encrypted", "client_secret_encrypted",
			scm.ProviderClientSecretContext},
		{"scm_providers.encrypted_app_private_key", "encrypted_app_private_key",
			scm.ProviderAppPrivateKeyContext},
	}

	for _, c := range cases {
		t.Run(c.dbCol, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tc := newCipher(t)

			secret := "secret-for-" + c.dbCol
			legacy, err := tc.Seal(secret)
			if err != nil {
				t.Fatal(err)
			}

			var stored string
			drive(t, mock, c.column, func() {
				mock.ExpectQuery("SELECT id, " + c.dbCol + " FROM scm_providers").
					WillReturnRows(sqlmock.NewRows([]string{"id", c.dbCol}).AddRow(providerID, legacy))
				// Anchored on this column name: sqlmock rejects the exec if the
				// UPDATE names the sibling instead.
				mock.ExpectExec(`UPDATE scm_providers SET `+c.dbCol+` = \$2`).
					WithArgs(sqlmock.AnyArg(), capturedArg{got: &stored}).
					WillReturnResult(sqlmock.NewResult(0, 1))
			})

			res, err := BindSecrets(context.Background(), db, tc, false)
			if err != nil {
				t.Fatalf("BindSecrets: %v", err)
			}
			if got := res[c.column]; got.Converted != 1 || got.Failed != 0 {
				t.Fatalf("result = %s; want one conversion", got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the UPDATE did not target %s: %v", c.dbCol, err)
			}

			got, err := tc.OpenWithContext(stored, c.context(providerID))
			if err != nil || got != secret {
				t.Fatalf("converted value does not open under the application's context: (%q, %v)", got, err)
			}
			if _, err := tc.Open(stored); err == nil {
				t.Error("converted value still opens WITHOUT a context; it was not bound")
			}
			for _, other := range cases {
				if other.dbCol == c.dbCol {
					continue
				}
				if _, err := tc.OpenWithContext(stored, other.context(providerID)); err == nil {
					t.Errorf("converted value opened as %s of the same row; the columns are not distinguished",
						other.dbCol)
				}
			}
		})
	}
}

// The sweep must write back to the column it read. A constructor shared by four
// columns makes "select one column, update another" a single typo away, and the
// result would be a credential silently moved between columns — the exact defect
// this change exists to prevent.
func TestBindSecrets_StorageColumnWritesBackToTheColumnItRead(t *testing.T) {
	const configID = "33333333-3333-3333-3333-333333333333"

	for _, sc := range storageConfigCases {
		t.Run(sc.dbCol, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tc := newCipher(t)

			legacy, err := tc.Seal("a-credential")
			if err != nil {
				t.Fatal(err)
			}
			drive(t, mock, sc.column, func() {
				mock.ExpectQuery("SELECT id, " + sc.dbCol + " FROM storage_config").
					WillReturnRows(sqlmock.NewRows([]string{"id", sc.dbCol}).AddRow(configID, legacy))
				// A regexp anchored on this column name only: sqlmock fails the
				// exec if the UPDATE names any other column.
				mock.ExpectExec(`UPDATE storage_config SET ` + sc.dbCol + ` = \$2`).
					WillReturnResult(sqlmock.NewResult(0, 1))
			})

			if _, err := BindSecrets(context.Background(), db, tc, false); err != nil {
				t.Fatalf("BindSecrets: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the UPDATE did not target %s: %v", sc.dbCol, err)
			}
		})
	}
}
