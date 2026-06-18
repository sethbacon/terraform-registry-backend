package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm/appcreds"
)

// testRSAKeyPEM returns a freshly generated PKCS#1 RSA private key PEM.
func testRSAKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// newSCMProviderAppRouter builds a provider router with a wired shared minter and
// the verify route registered.
func newSCMProviderAppRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	orgRepo := repositories.NewOrganizationRepository(db)
	cipher := testTokenCipher(t)
	h := NewSCMProviderHandlers(&config.Config{}, scmRepo, orgRepo, cipher).
		WithMinter(appcreds.NewMinter(cipher, scmRepo))

	r := gin.New()
	r.POST("/scm-providers", h.CreateProvider)
	r.POST("/scm-providers/:id/verify", h.VerifyProvider)
	return mock, r
}

func expectDefaultOrgAndNoDuplicate(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
			AddRow(knownUUID, "default", "Default", nil, nil, time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))
}

// ---------------------------------------------------------------------------
// GitHub App create
// ---------------------------------------------------------------------------

func TestSCMCreate_GitHubApp_Success(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	expectDefaultOrgAndNoDuplicate(mock)
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	keyPEM := testRSAKeyPEM(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type":          "github",
			"name":                   "gh-app",
			"auth_mode":              "github_app",
			"github_app_id":          "12345",
			"github_installation_id": "67890",
			"app_private_key":        keyPEM,
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"auth_mode":"github_app"`) {
		t.Errorf("response missing auth_mode github_app: %s", body)
	}
	if !strings.Contains(body, `"has_app_private_key":true`) {
		t.Errorf("response missing has_app_private_key=true: %s", body)
	}
	// The private key (or any PEM material) must never be echoed.
	if strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, "encrypted_app_private_key") {
		t.Errorf("response leaked private key material: %s", body)
	}
}

func TestSCMCreate_GitHubApp_InvalidKey(t *testing.T) {
	_, r := newSCMProviderAppRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type":          "github",
			"name":                   "gh-app",
			"auth_mode":              "github_app",
			"github_app_id":          "12345",
			"github_installation_id": "67890",
			"app_private_key":        "not-a-real-key",
		})))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_GitHubApp_WrongProviderType(t *testing.T) {
	_, r := newSCMProviderAppRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type":          "azuredevops",
			"name":                   "wrong",
			"auth_mode":              "github_app",
			"github_app_id":          "12345",
			"github_installation_id": "67890",
			"app_private_key":        testRSAKeyPEM(t),
		})))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Entra app create
// ---------------------------------------------------------------------------

func TestSCMCreate_EntraApp_Success(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	expectDefaultOrgAndNoDuplicate(mock)
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "azuredevops",
			"name":          "ado-app",
			"auth_mode":     "entra_app",
			"tenant_id":     "tenant-1",
			"client_id":     "client-1",
			"client_secret": "super-secret",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"auth_mode":"entra_app"`) {
		t.Errorf("response missing auth_mode entra_app: %s", body)
	}
	if !strings.Contains(body, `"has_client_secret":true`) {
		t.Errorf("response missing has_client_secret=true: %s", body)
	}
	if strings.Contains(body, "super-secret") || strings.Contains(body, "client_secret_encrypted") {
		t.Errorf("response leaked client secret: %s", body)
	}
}

func TestSCMCreate_EntraApp_WrongProviderType(t *testing.T) {
	_, r := newSCMProviderAppRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "wrong",
			"auth_mode":     "entra_app",
			"tenant_id":     "t",
			"client_id":     "c",
			"client_secret": "s",
		})))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

func TestSCMVerify_InvalidID(t *testing.T) {
	_, r := newSCMProviderAppRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers/not-a-uuid/verify", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSCMVerify_NotFound(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers/"+knownUUID+"/verify", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMVerify_NotAppMode(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	// sampleSCMProviderRow has an empty auth_mode (oauth_user), so verify is rejected.
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").
		WillReturnRows(sampleSCMProviderRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers/"+knownUUID+"/verify", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}
