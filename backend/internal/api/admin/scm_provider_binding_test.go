package admin

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// suite-identity #153 — an SCM provider's OAuth client secret and its GitHub App
// private key are bound to the scm_providers row and the column they belong to.
//
// The App private key is the sharpest case in this service. It authenticates as
// the installation itself, and unbound it could be copied into any other
// provider row — including one an attacker with database write access had just
// created in their own organization — and used to mint installation tokens for
// the victim's repositories.

// scmProviderInsertArgs and scmProviderUpdateArgs are the positional-parameter
// counts of SCMRepository's INSERT and UPDATE. sqlmock needs one matcher per
// parameter; a mismatch fails with both counts and points back here.
const (
	scmProviderInsertArgs = 16
	scmProviderUpdateArgs = 13
)

// scmSecret is one encrypted column: the plaintext the request carried and the
// context the stored ciphertext must be bound to.
type scmSecret struct {
	column  string
	secret  string
	context func(string) []byte
}

// allSCMProviderContexts is the column family, for the sibling assertions.
var allSCMProviderContexts = []scmSecret{
	{column: "client_secret_encrypted", context: scm.ProviderClientSecretContext},
	{column: "encrypted_app_private_key", context: scm.ProviderAppPrivateKeyContext},
}

// assertBoundToProvider checks each secret against the values that reached the
// database.
//
// The negative assertions carry the weight: opening under the right context only
// shows the seal round-trips, while the failures — no context, another provider
// row, the sibling column of the same row — are what show the binding is real.
// The sibling case is not hypothetical here: both columns sit in one row, so
// without it an App private key could be written into the client-secret column
// of its own provider and still decrypt.
func assertBoundToProvider(
	t *testing.T,
	tc *crypto.TokenCipher,
	stored []driver.Value,
	providerID string,
	secrets []scmSecret,
) {
	t.Helper()

	for _, s := range secrets {
		raw := findSealed(t, tc, stored, s.context(providerID))
		if raw == "" {
			t.Errorf("%s: no stored value opens under the row+column context; "+
				"it was not bound to provider %s", s.column, providerID)
			continue
		}

		got, err := tc.OpenWithContext(raw, s.context(providerID))
		if err != nil || got != s.secret {
			t.Errorf("%s: stored value = (%q, %v), want %q", s.column, got, err, s.secret)
		}
		if _, err := tc.Open(raw); err == nil {
			t.Errorf("%s: stored value still opens WITHOUT a context; it was not bound", s.column)
		}
		if _, err := tc.OpenWithContext(raw, s.context(otherProviderID)); err == nil {
			t.Errorf("%s: stored value opened under another provider's context; it could be "+
				"copied into a provider row the attacker controls", s.column)
		}
		for _, sibling := range allSCMProviderContexts {
			if sibling.column == s.column {
				continue
			}
			if _, err := tc.OpenWithContext(raw, sibling.context(providerID)); err == nil {
				t.Errorf("%s: stored value also opened as %s of the SAME row; "+
					"the two columns are interchangeable", s.column, sibling.column)
			}
		}
	}
}

const otherProviderID = "88888888-8888-8888-8888-888888888888"

func TestCreateSCMProvider_BindsSecretsToTheNewRow(t *testing.T) {
	keyPEM := testRSAKeyPEM(t)

	cases := []struct {
		name    string
		body    map[string]interface{}
		secrets []scmSecret
	}{
		{
			name: "oauth_user client secret",
			body: map[string]interface{}{
				"provider_type": "github",
				"name":          "gh-oauth",
				"client_id":     "client-id",
				"client_secret": "s3cr3t-oauth-client-secret",
			},
			secrets: []scmSecret{
				{"client_secret_encrypted", "s3cr3t-oauth-client-secret",
					scm.ProviderClientSecretContext},
			},
		},
		{
			// github_app seals BOTH columns on one request, which is the shape
			// that makes the sibling-column assertion meaningful. The client
			// secret is the handler's own "not-applicable" placeholder: those
			// columns are NOT NULL and unused in this auth mode, and the
			// placeholder is sealed like anything else.
			name: "github_app private key and placeholder secret",
			body: map[string]interface{}{
				"provider_type":          "github",
				"name":                   "gh-app",
				"auth_mode":              "github_app",
				"github_app_id":          "12345",
				"github_installation_id": "67890",
				"app_private_key":        keyPEM,
			},
			secrets: []scmSecret{
				{"client_secret_encrypted", "not-applicable",
					scm.ProviderClientSecretContext},
				{"encrypted_app_private_key", keyPEM,
					scm.ProviderAppPrivateKeyContext},
			},
		},
	}

	for _, tc2 := range cases {
		t.Run(tc2.name, func(t *testing.T) {
			mock, r := newSCMProviderRouter(t)
			tc := testTokenCipher(t)
			expectActingOrgAndNoDuplicate(mock)

			stored, matchers := recordAll(scmProviderInsertArgs)
			mock.ExpectExec("INSERT INTO scm_providers").
				WithArgs(matchers...).
				WillReturnResult(sqlmock.NewResult(1, 1))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, withActingOrg(httptest.NewRequest(http.MethodPost, "/scm-providers", jsonBody(tc2.body)), knownUUID))
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
			}

			// The id the handler minted, as stored. Both secrets on this path
			// are sealed BEFORE the struct literal that used to mint the id, so
			// this is the assertion that the id moved rather than being
			// generated twice.
			var resp struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ID == "" {
				t.Fatalf("create response carried no id: %v (body=%s)", err, w.Body.String())
			}
			if !idIsStored(stored, resp.ID) {
				t.Fatalf("the id in the response (%s) is not the id inserted; the secrets are "+
					"bound to a row that does not exist", resp.ID)
			}

			assertBoundToProvider(t, tc, stored, resp.ID, tc2.secrets)
		})
	}
}

// idIsStored reports whether id appears among the INSERT's arguments.
//
// Without this the create test would still pass if the handler minted one uuid
// for the seals and a different one for the row: the response would report the
// row's id, nothing would open under it, and the failure would read as "not
// bound" rather than "bound to the wrong row".
func idIsStored(stored []driver.Value, id string) bool {
	for _, v := range stored {
		if s, ok := v.(string); ok && s == id {
			return true
		}
		if u, ok := v.([]byte); ok && string(u) == id {
			return true
		}
		if str, ok := v.(interface{ String() string }); ok && str.String() == id {
			return true
		}
	}
	return false
}

func TestUpdateSCMProvider_BindsSecretsToTheRowBeingUpdated(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	tc := testTokenCipher(t)
	keyPEM := testRSAKeyPEM(t)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())

	stored, matchers := recordAll(scmProviderUpdateArgs)
	mock.ExpectExec("UPDATE scm_providers SET").
		WithArgs(matchers...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{
			"client_secret":   "rotated-client-secret",
			"app_private_key": keyPEM,
		})))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	// Bound to the row being written — the fixture's id, which is also the path
	// id — not to a fresh uuid.
	assertBoundToProvider(t, tc, stored, knownUUID, []scmSecret{
		{"client_secret_encrypted", "rotated-client-secret", scm.ProviderClientSecretContext},
		{"encrypted_app_private_key", keyPEM, scm.ProviderAppPrivateKeyContext},
	})
}
