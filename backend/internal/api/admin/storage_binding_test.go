package admin

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// suite-identity #153 — the storage-backend credentials are bound to the
// storage_config row AND the column they belong to, so a sealed credential
// cannot be lifted out of one configuration and written into another, or into a
// different credential column of its own row, by anyone with database write
// access.
//
// These assert on the values REACHING the database rather than on the model the
// builder returned, because the row id that goes into the context and the row id
// that goes into the INSERT are set in different places; a test of the builder
// alone would pass even if the handler stored the credential against a different
// row.

// storageInsertArgs and storageUpdateArgs are the positional-parameter counts of
// StorageConfigRepository's INSERT and UPDATE. sqlmock's WithArgs needs one
// matcher per parameter and has no "match the rest" form. If the repository's
// column list ever changes, sqlmock fails with both counts, which points
// straight back here.
const (
	storageInsertArgs = 29
	storageUpdateArgs = 27
)

// recordArg accepts any value and records it. Recording every argument, rather
// than pinning the credential's ordinal, keeps this test out of the business of
// the repository's column order: the assertions below FIND the credential by
// trying to open it, which is the property under test anyway.
type recordArg struct {
	into []driver.Value
	idx  int
}

func (r recordArg) Match(v driver.Value) bool {
	r.into[r.idx] = v
	return true
}

func recordAll(n int) ([]driver.Value, []driver.Value) {
	seen := make([]driver.Value, n)
	matchers := make([]driver.Value, n)
	for i := range matchers {
		matchers[i] = recordArg{into: seen, idx: i}
	}
	return seen, matchers
}

// storageCredential is one encrypted column: what the request supplies and the
// context the stored ciphertext must be bound to.
type storageCredential struct {
	column  string
	secret  string
	context func(string) []byte
}

// storageBackendCases covers all four encrypted columns across the three
// backends that have them. S3 appears with both of its columns populated at
// once on purpose: that row is the one where a column-blind binding would let
// the access key id and the secret access key be swapped.
var storageBackendCases = []struct {
	name        string
	input       map[string]interface{}
	credentials []storageCredential
}{
	{
		name: "azure",
		input: map[string]interface{}{
			"backend_type":         "azure",
			"azure_account_name":   "acct",
			"azure_container_name": "ctr",
			"azure_account_key":    "dGVzdC1henVyZS1rZXk=",
		},
		credentials: []storageCredential{
			{"azure_account_key_encrypted", "dGVzdC1henVyZS1rZXk=",
				models.StorageConfigAzureAccountKeyContext},
		},
	},
	{
		name: "s3",
		input: map[string]interface{}{
			"backend_type":         "s3",
			"s3_bucket":            "bkt",
			"s3_region":            "us-east-1",
			"s3_auth_method":       "static",
			"s3_access_key_id":     "AKIAEXAMPLEKEYID",
			"s3_secret_access_key": "wJalrXUtnFEMI-EXAMPLE-SECRET",
		},
		credentials: []storageCredential{
			{"s3_access_key_id_encrypted", "AKIAEXAMPLEKEYID",
				models.StorageConfigS3AccessKeyIDContext},
			{"s3_secret_access_key_encrypted", "wJalrXUtnFEMI-EXAMPLE-SECRET",
				models.StorageConfigS3SecretAccessKeyContext},
		},
	},
	{
		name: "gcs",
		input: map[string]interface{}{
			"backend_type":         "gcs",
			"gcs_bucket":           "bkt",
			"gcs_project_id":       "proj",
			"gcs_auth_method":      "service_account",
			"gcs_credentials_json": `{"type":"service_account","private_key":"-----BEGIN"}`,
		},
		credentials: []storageCredential{
			{"gcs_credentials_json_encrypted", `{"type":"service_account","private_key":"-----BEGIN"}`,
				models.StorageConfigGCSCredentialsJSONContext},
		},
	},
}

// assertStoredCredentials checks every credential the request carried against
// the values that reached the database.
//
// The negative assertions are the ones with teeth. Opening under the right
// context only proves the seal round-trips; it is the failures — no context, a
// different row, a sibling column of the same row — that prove the binding is
// not decorative.
func assertStoredCredentials(
	t *testing.T,
	tc *crypto.TokenCipher,
	stored []driver.Value,
	configID string,
	creds []storageCredential,
) {
	t.Helper()

	for _, cred := range creds {
		raw := findSealed(t, tc, stored, cred.context(configID))
		if raw == "" {
			t.Errorf("%s: no stored value opens under the row+column context; "+
				"the credential was not bound to config %s", cred.column, configID)
			continue
		}

		got, err := tc.OpenWithContext(raw, cred.context(configID))
		if err != nil || got != cred.secret {
			t.Errorf("%s: stored value = (%q, %v), want %q", cred.column, got, err, cred.secret)
		}
		if _, err := tc.Open(raw); err == nil {
			t.Errorf("%s: stored value still opens WITHOUT a context; it was not bound", cred.column)
		}
		if _, err := tc.OpenWithContext(raw, cred.context(otherConfigID)); err == nil {
			t.Errorf("%s: stored value opened under another config's context; "+
				"it could be moved between storage configurations", cred.column)
		}
		for _, sibling := range allStorageContexts {
			if sibling.column == cred.column {
				continue
			}
			if _, err := tc.OpenWithContext(raw, sibling.context(configID)); err == nil {
				t.Errorf("%s: stored value also opened as %s of the SAME row; "+
					"the two columns are interchangeable", cred.column, sibling.column)
			}
		}
	}
}

const otherConfigID = "99999999-9999-9999-9999-999999999999"

// allStorageContexts is the whole column family, used for the sibling-column
// assertions above.
var allStorageContexts = []storageCredential{
	{column: "azure_account_key_encrypted", context: models.StorageConfigAzureAccountKeyContext},
	{column: "s3_access_key_id_encrypted", context: models.StorageConfigS3AccessKeyIDContext},
	{column: "s3_secret_access_key_encrypted", context: models.StorageConfigS3SecretAccessKeyContext},
	{column: "gcs_credentials_json_encrypted", context: models.StorageConfigGCSCredentialsJSONContext},
}

// findSealed returns the single recorded argument that opens under ctx, or "".
func findSealed(t *testing.T, tc *crypto.TokenCipher, stored []driver.Value, ctx []byte) string {
	t.Helper()
	var found string
	for _, v := range stored {
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		if _, err := tc.OpenWithContext(s, ctx); err != nil {
			continue
		}
		if found != "" {
			t.Fatalf("two stored arguments open under the same context; the test cannot tell them apart")
		}
		found = s
	}
	return found
}

func newBindingCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	tc, err := crypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

func TestCreateStorageConfig_BindsCredentialsToTheNewRow(t *testing.T) {
	for _, bc := range storageBackendCases {
		t.Run(bc.name, func(t *testing.T) {
			tc := newBindingCipher(t)
			mock, r := newStorageRouterWithCipher(t, tc)

			mock.ExpectQuery("SELECT storage_configured FROM system_settings").
				WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))

			stored, matchers := recordAll(storageInsertArgs)
			mock.ExpectExec("INSERT INTO storage_config").
				WithArgs(matchers...).
				WillReturnResult(sqlmock.NewResult(1, 1))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/storage/configs", jsonBody(bc.input)))
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
			}

			// The id the handler minted, as the API reported it. Binding to the
			// wrong id would still round-trip inside the handler; only the
			// stored id makes the assertion real.
			var resp struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ID == "" {
				t.Fatalf("create response carried no id: %v (body=%s)", err, w.Body.String())
			}

			assertStoredCredentials(t, tc, stored, resp.ID, bc.credentials)
		})
	}
}

func TestUpdateStorageConfig_BindsCredentialsToTheRowBeingUpdated(t *testing.T) {
	for _, bc := range storageBackendCases {
		t.Run(bc.name, func(t *testing.T) {
			tc := newBindingCipher(t)
			mock, r := newStorageRouterWithCipher(t, tc)

			mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
				WillReturnRows(sampleStorageCfgRow())
			mock.ExpectQuery("SELECT storage_configured FROM system_settings").
				WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))

			stored, matchers := recordAll(storageUpdateArgs)
			mock.ExpectExec("UPDATE storage_config").
				WithArgs(matchers...).
				WillReturnResult(sqlmock.NewResult(1, 1))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/storage/configs/"+knownUUID,
				jsonBody(bc.input)))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
			}

			// Bound to the row actually being written -- sampleStorageCfgRow's
			// id, which is also the path id.
			assertStoredCredentials(t, tc, stored, knownUUID, bc.credentials)
		})
	}
}
