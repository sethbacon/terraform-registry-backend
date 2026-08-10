package setup

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// suite-identity #153 — the LDAP service-account bind password is bound to its
// field in the ldap_config blob.
//
// Two things about this one are unlike every other secret in this migration, and
// both are deliberate:
//
// It has no row. ldap_config is a JSON blob on the system_settings singleton, so
// the context names the blob and the field rather than a row id. What that buys
// is the cross-field move: notifications_config sits in the SAME row, so an SMTP
// password and this password would otherwise be interchangeable.
//
// Nothing reads it. GetLDAPConfig has no callers; the runtime LDAP provider is
// built from config.LDAPConfig (environment/file), not from this blob. The field
// is write-only today, so there is no read path to convert and no "the operator
// re-enters it" failure mode — which is exactly why binding it is worth doing
// now rather than later: it costs one call and it means a reader added in future
// inherits a bound value instead of finding an unbound one.

type ldapBlobCapture struct{ into *[]byte }

func (c ldapBlobCapture) Match(v driver.Value) bool {
	switch x := v.(type) {
	case []byte:
		*c.into = append([]byte(nil), x...)
	case string:
		*c.into = []byte(x)
	}
	return true
}

func TestSaveLDAPConfig_BindsTheBindPasswordToItsField(t *testing.T) {
	env := newTestEnv(t)
	const password = "svc-account-bind-password"

	r := gin.New()
	r.POST("/ldap", env.h.SaveLDAPConfig)

	var written []byte
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WithArgs(ldapBlobCapture{into: &written}, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/ldap", jsonBody(map[string]interface{}{
		"host":          "ldap.example.com",
		"port":          636,
		"use_tls":       true,
		"bind_dn":       "cn=svc,dc=example,dc=com",
		"bind_password": password,
		"base_dn":       "dc=example,dc=com",
		"user_filter":   "(uid=%s)",
	})))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	var blob map[string]any
	if err := json.Unmarshal(written, &blob); err != nil {
		t.Fatalf("the stored ldap_config is not valid JSON: %v (%s)", err, written)
	}
	sealed, _ := blob["bind_password_enc"].(string)
	if sealed == "" {
		t.Fatal("no bind_password_enc was stored")
	}
	if sealed == password {
		t.Fatal("the bind password was stored in plaintext")
	}

	got, bound, err := env.cipher.OpenWithContextOrLegacy(sealed,
		models.SystemSettingsLDAPBindPasswordContext())
	if err != nil {
		t.Fatalf("the stored password does not open under its own field context: %v", err)
	}
	if !bound {
		t.Error("the stored password opened only via the LEGACY path, so it was sealed WITHOUT a " +
			"context and is interchangeable with any other unbound secret")
	}
	if got != password {
		t.Errorf("stored password = %q, want %q", got, password)
	}
	// The other secret in the same system_settings row.
	if _, err := env.cipher.OpenWithContext(sealed,
		models.SystemSettingsSMTPPasswordContext()); err == nil {
		t.Error("the stored bind password also opens as the SMTP password; the two fields of " +
			"system_settings are interchangeable")
	}
}
