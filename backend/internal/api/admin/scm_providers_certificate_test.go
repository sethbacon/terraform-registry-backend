package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Issue #1041 -- an entra_app provider may prove itself with a certificate:
// a client assertion signed by a held key, so no secret crosses the wire. The
// bundle is stored sealed and bound to its row exactly as the GitHub App key
// is, and each credential type carries exactly its own material.

// testCertificateBundle is a real self-signed certificate and key, generated
// per test so ValidCertificateBundle meets genuine material.
func testCertificateBundle(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func certificateCreateBody(bundle string) map[string]interface{} {
	return map[string]interface{}{
		"provider_type": "azuredevops", "name": "ado-cert",
		"base_url": "https://dev.azure.com/acme", "auth_mode": "entra_app",
		"tenant_id": "tenant-1", "client_id": "client-1",
		"entra_credential_type": "certificate", "entra_certificate": bundle,
	}
}

func TestSCMCreate_EntraApp_CertificatePersistsAndBindsTheBundle(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	tc := testTokenCipher(t)
	expectActingOrgAndNoDuplicate(mock)
	stored, matchers := recordAll(scmProviderInsertArgs)
	mock.ExpectExec("INSERT INTO scm_providers").WithArgs(matchers...).WillReturnResult(sqlmock.NewResult(1, 1))

	bundle := testCertificateBundle(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(certificateCreateBody(bundle))), knownUUID))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if got := storedCredentialType(t, stored); got != scm.EntraCredentialCertificate {
		t.Errorf("stored entra_credential_type = %q, want certificate", got)
	}
	// The bundle must open under ITS row's context and no other -- a bundle
	// copied into another provider's row must not decrypt there.
	sealed := storedEntraCertificate(t, stored)
	if sealed == "" {
		t.Fatal("the bundle was not written")
	}
	var id string
	for _, v := range stored {
		if s, ok := v.(string); ok && len(s) == 36 && strings.Count(s, "-") == 4 {
			id = s
			break
		}
	}
	if id == "" {
		t.Fatal("could not find the inserted row id among the arguments")
	}
	if got, err := tc.OpenWithContext(sealed, scm.ProviderEntraCertificateContext(id)); err != nil || got != bundle {
		t.Errorf("bundle does not open under its own row context: %v", err)
	}
	if _, err := tc.OpenWithContext(sealed, scm.ProviderEntraCertificateContext(knownUUID)); err == nil {
		t.Error("bundle opened under ANOTHER provider's context; it is not bound to its row")
	}
	if _, err := tc.OpenWithContext(sealed, scm.ProviderAppPrivateKeyContext(id)); err == nil {
		t.Error("bundle opened under the sibling app-private-key context of its own row")
	}
	if _, err := tc.Open(sealed); err == nil {
		t.Error("bundle opened with no context at all")
	}
	// No secret placeholder: a certificate provider carries none.
	if strings.Contains(w.Body.String(), `"has_client_secret":true`) {
		t.Error("a certificate provider reports a client secret")
	}
}

func TestSCMCreate_EntraApp_CertificateRejections(t *testing.T) {
	bundle := testCertificateBundle(t)
	cases := []struct {
		name string
		mut  func(m map[string]interface{})
		want string
	}{
		{"a client_secret alongside", func(m map[string]interface{}) { m["client_secret"] = "s" }, "must not be set when entra_credential_type is certificate"},
		{"no bundle", func(m map[string]interface{}) { delete(m, "entra_certificate") }, "entra_certificate is required"},
		{"a bundle that does not parse", func(m map[string]interface{}) { m["entra_certificate"] = "not a bundle" }, "entra_certificate:"},
		{"certificate only, no key", func(m map[string]interface{}) {
			m["entra_certificate"] = bundle[:strings.Index(bundle, "-----BEGIN PRIVATE KEY-----")]
		}, "no private key"},
		{"no tenant_id", func(m map[string]interface{}) { delete(m, "tenant_id") }, "tenant_id is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, r := newSCMProviderAppRouter(t)
			body := certificateCreateBody(bundle)
			tc.mut(body)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(body)), knownUUID))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("body %s does not say %q", w.Body.String(), tc.want)
			}
		})
	}
}

// The other two types must refuse a bundle: each carries exactly its own
// material, and a stray certificate on a client_secret row is how a retired
// credential survives in the database.
func TestSCMCreate_EntraApp_OtherTypesRejectACertificate(t *testing.T) {
	bundle := testCertificateBundle(t)
	for _, ct := range []string{"client_secret", "federated"} {
		t.Run(ct, func(t *testing.T) {
			_, r := newSCMProviderAppRouter(t)
			body := certificateCreateBody(bundle)
			body["entra_credential_type"] = ct
			if ct == "client_secret" {
				body["client_secret"] = "s"
			} else {
				delete(body, "tenant_id")
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(body)), knownUUID))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "entra_certificate must not be set") {
				t.Fatalf("status = %d body=%s, want 400 refusing the bundle", w.Code, w.Body.String())
			}
		})
	}
}

// entraSecretRow is an existing client_secret entra_app provider, as the
// update handler loads it. Includes the two #1037/#1041 columns so the loaded
// provider carries its type and (no) certificate.
func entraSecretRow() *sqlmock.Rows {
	cols := append(append([]string{}, scmProvCols...), "auth_mode", "entra_credential_type", "encrypted_entra_certificate")
	return sqlmock.NewRows(cols).AddRow(
		knownUUID, "00000000-0000-0000-0000-000000000000", "azuredevops", "ado",
		"https://dev.azure.com/acme", "tenant-1", "client-1",
		"encrypted-secret", "webhook-secret",
		true, time.Now(), time.Now(),
		"entra_app", "client_secret", nil,
	)
}

func TestSCMUpdate_SwitchToCertificateInOneRequest(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(entraSecretRow())
	stored, matchers := recordAll(scmProviderUpdateArgs)
	mock.ExpectExec("UPDATE scm_providers SET").WithArgs(matchers...).WillReturnResult(sqlmock.NewResult(1, 1))

	bundle := testCertificateBundle(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID, jsonBody(map[string]interface{}{
		"entra_credential_type": "certificate", "entra_certificate": bundle, "client_secret": "",
	})))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if got := storedCredentialType(t, stored); got != scm.EntraCredentialCertificate {
		t.Errorf("stored type = %q, want certificate", got)
	}
	if storedEntraCertificate(t, stored) == "" {
		t.Error("the bundle was not written")
	}
	for _, v := range stored {
		if s, ok := v.(string); ok && s == "encrypted-secret" {
			t.Error("the previous client secret survived the switch to certificate")
		}
	}
}

func TestSCMUpdate_SwitchToCertificateRejections(t *testing.T) {
	bundle := testCertificateBundle(t)
	cases := []struct {
		name string
		body map[string]interface{}
		want string
	}{
		{"secret left in place", map[string]interface{}{"entra_credential_type": "certificate", "entra_certificate": bundle}, "must not carry a client_secret"},
		{"no bundle supplied", map[string]interface{}{"entra_credential_type": "certificate", "client_secret": ""}, "must carry an entra_certificate"},
		{"bad bundle", map[string]interface{}{"entra_credential_type": "certificate", "entra_certificate": "nope", "client_secret": ""}, "entra_certificate:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock, r := newSCMProviderRouter(t)
			mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(entraSecretRow())
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID, jsonBody(tc.body)))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("status = %d body=%s, want 400 saying %q", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

// Leaving certificate: the bundle must be retired in the same request, or the
// row claims client_secret while still carrying a signing key.
func TestSCMUpdate_LeavingCertificateMustRetireTheBundle(t *testing.T) {
	cols := append(append([]string{}, scmProvCols...), "auth_mode", "entra_credential_type", "encrypted_entra_certificate")
	certRow := func() *sqlmock.Rows {
		return sqlmock.NewRows(cols).AddRow(
			knownUUID, "00000000-0000-0000-0000-000000000000", "azuredevops", "ado",
			"https://dev.azure.com/acme", "tenant-1", "client-1", "", "wh",
			true, time.Now(), time.Now(), "entra_app", "certificate", "sealed-bundle")
	}
	t.Run("bundle left in place is refused", func(t *testing.T) {
		mock, r := newSCMProviderRouter(t)
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(certRow())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID, jsonBody(map[string]interface{}{
			"entra_credential_type": "client_secret", "client_secret": "new-secret",
		})))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "must not carry an entra_certificate") {
			t.Fatalf("status = %d body=%s, want 400 refusing the leftover bundle", w.Code, w.Body.String())
		}
	})
	t.Run("clearing it in the same request is accepted", func(t *testing.T) {
		mock, r := newSCMProviderRouter(t)
		mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").WillReturnRows(certRow())
		stored, matchers := recordAll(scmProviderUpdateArgs)
		mock.ExpectExec("UPDATE scm_providers SET").WithArgs(matchers...).WillReturnResult(sqlmock.NewResult(1, 1))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+knownUUID, jsonBody(map[string]interface{}{
			"entra_credential_type": "client_secret", "client_secret": "new-secret", "entra_certificate": "",
		})))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
		}
		if storedEntraCertificate(t, stored) != "" {
			t.Error("the bundle survived the switch away from certificate")
		}
	})
}
