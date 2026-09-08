package admin

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Issue #1037 -- an entra_app provider may prove itself with workload identity
// federation instead of a stored client secret. The credential type is only
// worth having if it SURVIVES THE WRITE: a provider that reports itself as
// federated over the API but persists as client_secret would keep asking for a
// secret it no longer has, and the failure would appear at mint time, far from
// the request that caused it.

// storedCredentialType returns the value bound to the statement's last
// parameter, which is where entra_credential_type sits in both the INSERT and
// the UPDATE. Reading the value, not just counting parameters, is what makes
// these tests fail when the column is dropped from the statement or bound from
// the wrong variable.
func storedCredentialType(t *testing.T, stored []driver.Value) string {
	t.Helper()
	if len(stored) == 0 {
		t.Fatal("no arguments were captured")
	}
	last := stored[len(stored)-1]
	switch v := last.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		t.Fatalf("last statement parameter is %T (%v), not the entra_credential_type text", last, last)
		return ""
	}
}

func TestSCMCreate_EntraApp_FederatedPersistsItsCredentialType(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	expectActingOrgAndNoDuplicate(mock)

	stored, matchers := recordAll(scmProviderInsertArgs)
	mock.ExpectExec("INSERT INTO scm_providers").
		WithArgs(matchers...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type":         "azuredevops",
			"name":                  "ado-federated",
			"base_url":              "https://dev.azure.com/acme",
			"auth_mode":             "entra_app",
			"client_id":             "federated-client-1",
			"entra_credential_type": "federated",
		})), knownUUID))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if got := storedCredentialType(t, stored); got != scm.EntraCredentialFederated {
		t.Errorf("stored entra_credential_type = %q, want %q -- the provider would mint with a "+
			"client secret it does not have", got, scm.EntraCredentialFederated)
	}
}

// A federated provider needs no tenant_id: the platform supplies it alongside
// the projected token. Requiring one anyway would make the mode unreachable for
// exactly the deployments it exists for.
func TestSCMCreate_EntraApp_FederatedNeedsNoTenantID(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	expectActingOrgAndNoDuplicate(mock)
	mock.ExpectExec("INSERT INTO scm_providers").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type":         "azuredevops",
			"name":                  "ado-federated-no-tenant",
			"base_url":              "https://dev.azure.com/acme",
			"auth_mode":             "entra_app",
			"client_id":             "federated-client-1",
			"entra_credential_type": "federated",
		})), knownUUID))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// The default has to hold: every caller written before this column exists, and
// the whole installed base, sends no entra_credential_type at all.
func TestSCMCreate_EntraApp_DefaultsToClientSecret(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	expectActingOrgAndNoDuplicate(mock)

	stored, matchers := recordAll(scmProviderInsertArgs)
	mock.ExpectExec("INSERT INTO scm_providers").
		WithArgs(matchers...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "azuredevops",
			"name":          "ado-secret",
			"base_url":      "https://dev.azure.com/acme",
			"auth_mode":     "entra_app",
			"tenant_id":     "tenant-1",
			"client_id":     "client-1",
			"client_secret": "super-secret",
		})), knownUUID))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	// An empty string here would violate the column's CHECK on a real database,
	// where sqlmock accepts anything.
	if got := storedCredentialType(t, stored); got != scm.EntraCredentialClientSecret {
		t.Errorf("stored entra_credential_type = %q, want %q", got, scm.EntraCredentialClientSecret)
	}
}

// Storing a secret next to a credential type that ignores it is how a
// rotated-away secret survives in the database and is later mistaken for the
// live credential. The database CHECK refuses it; the handler should say why.
func TestSCMCreate_EntraApp_FederatedRejectsAClientSecret(t *testing.T) {
	_, r := newSCMProviderAppRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type":         "azuredevops",
			"name":                  "ado-both",
			"base_url":              "https://dev.azure.com/acme",
			"auth_mode":             "entra_app",
			"client_id":             "client-1",
			"client_secret":         "super-secret",
			"entra_credential_type": "federated",
		})), knownUUID))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_EntraApp_RejectsUnknownCredentialType(t *testing.T) {
	_, r := newSCMProviderAppRouter(t)

	// managed_identity and certificate are real modes, tracked as #1042 and
	// #1041, and NOT implemented. Accepting the word here would write a value
	// the column's CHECK refuses, or -- worse, if the CHECK were widened first
	// -- one the minter silently treats as a client secret.
	// "" is absent, not invalid: it defaults to client_secret, which the
	// defaults test above covers.
	for _, ct := range []string{"managed_identity", "certificate", "FEDERATED", "workload_identity"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
			jsonBody(map[string]interface{}{
				"provider_type":         "azuredevops",
				"name":                  "ado-bad-" + ct,
				"base_url":              "https://dev.azure.com/acme",
				"auth_mode":             "entra_app",
				"tenant_id":             "tenant-1",
				"client_id":             "client-1",
				"client_secret":         "super-secret",
				"entra_credential_type": ct,
			})), knownUUID))
		if w.Code != http.StatusBadRequest {
			t.Errorf("entra_credential_type=%q: status = %d, want 400: body=%s", ct, w.Code, w.Body.String())
		}
	}
}

func TestSCMUpdate_SwitchToFederatedRetiresTheSecret(t *testing.T) {
	mock, r := newSCMProviderRouter(t)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())
	stored, matchers := recordAll(scmProviderUpdateArgs)
	mock.ExpectExec("UPDATE scm_providers SET").
		WithArgs(matchers...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// The migration path an operator actually walks: an existing entra_app
	// provider moves off its client secret. Clearing the secret and setting the
	// credential type must happen in ONE request, because neither intermediate
	// state satisfies scm_providers_entra_credential_shape.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{
			"auth_mode":             "entra_app",
			"client_id":             "federated-client-1",
			"client_secret":         "",
			"entra_credential_type": "federated",
		})))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if got := storedCredentialType(t, stored); got != scm.EntraCredentialFederated {
		t.Errorf("stored entra_credential_type = %q, want %q", got, scm.EntraCredentialFederated)
	}
	// The secret column must actually be empty. A sealed "" is a non-empty
	// value and the CHECK would refuse the row on a real database.
	for _, v := range stored {
		if s, ok := v.(string); ok && s == "encrypted-secret" {
			t.Error("the row's previous client secret survived the switch to federated")
		}
	}
}

// Switching the credential type while leaving the secret in place is the
// mistake this refuses: the row would claim federation and still carry the
// secret it was supposed to retire.
func TestSCMUpdate_FederatedWithASurvivingSecretIsRefused(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{
			"auth_mode":             "entra_app",
			"client_id":             "federated-client-1",
			"entra_credential_type": "federated",
		})))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}
