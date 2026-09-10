package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Issue #1042 -- a user-assigned managed identity. The hosting platform holds
// the credential, so the row carries only client_id: no tenant, no secret, no
// certificate. Whether a deployment OFFERS the type is an operator declaration
// (TFR_SCM_ENTRA_CREDENTIAL_TYPES), because it only works on Azure compute.

func offering(types ...string) *config.Config {
	return &config.Config{SCM: config.SCMConfig{Entra: config.EntraSCMConfig{CredentialTypes: types}}}
}

func miCreateBody() map[string]interface{} {
	return map[string]interface{}{
		"provider_type": "azuredevops", "name": "ado-mi",
		"base_url": "https://dev.azure.com/acme", "auth_mode": "entra_app",
		"client_id": "uami-1", "entra_credential_type": "managed_identity",
	}
}

func TestSCMCreate_ManagedIdentity_NeedsNoTenantSecretOrCertificate(t *testing.T) {
	mock, r := newSCMProviderAppRouterWithConfig(t,
		offering("client_secret", "federated", "certificate", "managed_identity"))
	expectActingOrgAndNoDuplicate(mock)
	stored, matchers := recordAll(scmProviderInsertArgs)
	mock.ExpectExec("INSERT INTO scm_providers").WithArgs(matchers...).WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(miCreateBody())), knownUUID))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if got := storedCredentialType(t, stored); got != scm.EntraCredentialManagedIdentity {
		t.Errorf("stored entra_credential_type = %q, want managed_identity", got)
	}
	if got := storedEntraCertificate(t, stored); got != "" {
		t.Errorf("a certificate was stored for a managed identity: %q", got)
	}
	body := w.Body.String()
	if strings.Contains(body, `"has_client_secret":true`) {
		t.Error("a managed identity provider reports a client secret")
	}
}

func TestSCMCreate_ManagedIdentity_Rejections(t *testing.T) {
	cases := []struct {
		name string
		mut  func(m map[string]interface{})
		want string
	}{
		{"a client_secret alongside", func(m map[string]interface{}) { m["client_secret"] = "s" },
			"must not be set when entra_credential_type is managed_identity"},
		{"a certificate alongside", func(m map[string]interface{}) { m["entra_certificate"] = "pem" },
			"must not be set when entra_credential_type is managed_identity"},
		{"no client_id -- would select the system-assigned identity", func(m map[string]interface{}) { delete(m, "client_id") },
			"client_id is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, r := newSCMProviderAppRouterWithConfig(t, offering("managed_identity"))
			body := miCreateBody()
			tc.mut(body)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(body)), knownUUID))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("status = %d body=%s, want 400 saying %q", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

// The allow-list is the point of #1042's design: a type the deployment does not
// offer must be refused at the door, so an admin never saves a provider that
// can never mint here.
func TestSCMCreate_RefusesACredentialTypeThisDeploymentDoesNotOffer(t *testing.T) {
	_, r := newSCMProviderAppRouterWithConfig(t, offering("client_secret", "certificate"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(miCreateBody())), knownUUID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
	// The admin cannot fix this themselves; the message must say whom to ask.
	if !strings.Contains(w.Body.String(), "TFR_SCM_ENTRA_CREDENTIAL_TYPES") {
		t.Errorf("the refusal does not name the config key an operator would change: %s", w.Body.String())
	}
}

// A deployment that moved hosts must be able to correct its providers, so a row
// already ON an unoffered type stays editable -- only SWITCHING TO one is
// refused.
func TestSCMUpdate_AnExistingProviderOnAnUnofferedTypeStaysEditable(t *testing.T) {
	cols := append(append([]string{}, scmProvCols...), "auth_mode", "entra_credential_type", "encrypted_entra_certificate")
	miRow := func() *sqlmock.Rows {
		return sqlmock.NewRows(cols).AddRow(
			knownUUID, "00000000-0000-0000-0000-000000000000", "azuredevops", "ado",
			"https://dev.azure.com/acme", nil, "uami-1", "", "wh",
			true, time.Now(), time.Now(), "entra_app", "managed_identity", nil)
	}

	t.Run("renaming it is allowed even though the type is not offered", func(t *testing.T) {
		mock, r := newSCMProviderRouterWithConfig(t, offering("client_secret"))
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(miRow())
		mock.ExpectExec("UPDATE scm_providers SET").WillReturnResult(sqlmock.NewResult(1, 1))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
			jsonBody(map[string]interface{}{"name": "renamed"})))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
		}
	})

	// The shape the edit form actually produces: it round-trips the provider's
	// CURRENT credential type on every save. If a no-op type value were treated
	// as a switch, a provider on an unoffered type could never be edited at all
	// -- exactly the deployment-moved-hosts case the allow-list must not strand.
	t.Run("re-sending its own unoffered type is not a switch", func(t *testing.T) {
		mock, r := newSCMProviderRouterWithConfig(t, offering("client_secret"))
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(miRow())
		mock.ExpectExec("UPDATE scm_providers SET").WillReturnResult(sqlmock.NewResult(1, 1))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
			jsonBody(map[string]interface{}{
				"name": "renamed", "entra_credential_type": "managed_identity",
			})))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("switching TO an unoffered type is refused", func(t *testing.T) {
		mock, r := newSCMProviderRouterWithConfig(t, offering("client_secret"))
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(sampleSCMProviderRow())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
			jsonBody(map[string]interface{}{"auth_mode": "entra_app", "entra_credential_type": "managed_identity"})))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not offered by this deployment") {
			t.Fatalf("status = %d body=%s, want 400", w.Code, w.Body.String())
		}
	})
}

func TestSCMCapabilities_ReportsEveryKnownTypeWithAvailability(t *testing.T) {
	_, r := newSCMProviderAppRouterWithConfig(t, offering("client_secret", "managed_identity"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("GET", "/scm-providers/capabilities", nil), knownUUID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	var out SCMCapabilitiesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not the documented shape: %v (body=%s)", err, w.Body.String())
	}

	// EVERY known type must be present, not just the offered ones. A type
	// missing from the map is indistinguishable from an older backend that
	// never heard of it -- the ambiguity that left capabilities.oci dead and
	// unnoticed for its whole life (frontend #921).
	for _, want := range scm.KnownEntraCredentialTypes() {
		entry, ok := out.EntraCredentialTypes[want]
		if !ok {
			t.Errorf("%s is missing from the response; the UI cannot tell that from an older backend", want)
			continue
		}
		shouldOffer := want == "client_secret" || want == "managed_identity"
		if entry.Available != shouldOffer {
			t.Errorf("%s available=%v, want %v", want, entry.Available, shouldOffer)
		}
		if !entry.Available && entry.Reason == "" {
			t.Errorf("%s is unavailable with no reason; the UI has nothing to show the admin", want)
		}
	}
}

// Switching TO managed identity must retire the secret in the same request:
// neither intermediate state is a legal row under the shape CHECK.
func TestSCMUpdate_SwitchToManagedIdentityMustRetireTheSecret(t *testing.T) {
	t.Run("a leftover secret is refused", func(t *testing.T) {
		mock, r := newSCMProviderRouterWithConfig(t, offering("client_secret", "managed_identity"))
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(entraSecretRow())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
			jsonBody(map[string]interface{}{"entra_credential_type": "managed_identity"})))
		if w.Code != http.StatusBadRequest ||
			!strings.Contains(w.Body.String(), "must not carry a client_secret") {
			t.Fatalf("status = %d body=%s, want 400 refusing the leftover secret", w.Code, w.Body.String())
		}
	})

	t.Run("a leftover certificate is refused", func(t *testing.T) {
		cols := append(append([]string{}, scmProvCols...), "auth_mode", "entra_credential_type", "encrypted_entra_certificate")
		certRow := sqlmock.NewRows(cols).AddRow(
			knownUUID, "00000000-0000-0000-0000-000000000000", "azuredevops", "ado",
			"https://dev.azure.com/acme", "tenant-1", "client-1", "", "wh",
			true, time.Now(), time.Now(), "entra_app", "certificate", "sealed-bundle")
		mock, r := newSCMProviderRouterWithConfig(t, offering("certificate", "managed_identity"))
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(certRow)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
			jsonBody(map[string]interface{}{"entra_credential_type": "managed_identity"})))
		if w.Code != http.StatusBadRequest ||
			!strings.Contains(w.Body.String(), "must not carry an entra_certificate") {
			t.Fatalf("status = %d body=%s, want 400 refusing the leftover bundle", w.Code, w.Body.String())
		}
	})

	t.Run("clearing both in the same request is accepted", func(t *testing.T) {
		mock, r := newSCMProviderRouterWithConfig(t, offering("client_secret", "managed_identity"))
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(entraSecretRow())
		stored, matchers := recordAll(scmProviderUpdateArgs)
		mock.ExpectExec("UPDATE scm_providers SET").WithArgs(matchers...).WillReturnResult(sqlmock.NewResult(1, 1))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID,
			jsonBody(map[string]interface{}{
				"entra_credential_type": "managed_identity", "client_secret": "", "entra_certificate": "",
			})))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
		}
		if got := storedCredentialType(t, stored); got != scm.EntraCredentialManagedIdentity {
			t.Errorf("stored type = %q, want managed_identity", got)
		}
		for _, v := range stored {
			if s, ok := v.(string); ok && s == "encrypted-secret" {
				t.Error("the previous client secret survived the switch to managed identity")
			}
		}
	})
}
