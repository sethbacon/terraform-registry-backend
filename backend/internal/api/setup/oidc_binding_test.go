package setup

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// suite-identity #153 — the OIDC client secret is bound to its oidc_config row.
//
// oidc_config keeps every configuration ever saved, not only the active one, so
// the row axis is the one that matters: unbound, a secret from a retired row
// could be promoted onto the active row, pointing the service's SSO at an issuer
// of someone else's choosing without touching the setup API at all.
//
// This asserts the value REACHING the database against the id in the same
// INSERT. SaveOIDCConfig seals BEFORE the struct literal that used to mint the
// id, so a test of the seal alone would pass even with the row inserted under a
// different uuid.

// oidcInsertArgs is the positional-parameter count of the identity module's
// oidc_config INSERT, with id as $1. sqlmock needs one matcher per parameter and
// fails with both counts if the module's column list changes.
const oidcInsertArgs = 14

type oidcRecordArg struct {
	into []driver.Value
	idx  int
}

func (r oidcRecordArg) Match(v driver.Value) bool {
	r.into[r.idx] = v
	return true
}

func recordOIDCArgs() ([]driver.Value, []driver.Value) {
	seen := make([]driver.Value, oidcInsertArgs)
	matchers := make([]driver.Value, oidcInsertArgs)
	for i := range matchers {
		matchers[i] = oidcRecordArg{into: seen, idx: i}
	}
	return seen, matchers
}

func TestSaveOIDCConfig_BindsTheClientSecretToTheNewRow(t *testing.T) {
	env := newTestEnv(t)
	const secret = "s3cr3t-oidc-client-secret"

	r := gin.New()
	r.POST("/oidc", env.h.SaveOIDCConfig)

	stored, matchers := recordOIDCArgs()
	env.oidcMock.ExpectBegin()
	env.oidcMock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	env.oidcMock.ExpectExec("INSERT INTO oidc_config").
		WithArgs(matchers...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	env.oidcMock.ExpectCommit()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/oidc", jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"issuer_url":    "https://issuer.example.com",
		"client_id":     "test-client",
		"client_secret": secret,
		"redirect_url":  "https://app/callback",
	})))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	// $1 is the row id. Deriving the context from the value actually INSERTED,
	// rather than from anything the handler reported, is what makes "sealed
	// against one uuid and inserted under another" a failure.
	rowID := argString(t, stored[0])
	ct := argString(t, stored[5])

	got, bound, err := env.cipher.OpenWithContextOrLegacy(ct,
		models.OIDCConfigClientSecretContext(rowID))
	if err != nil {
		t.Fatalf("the stored secret does not open under its own row context: %v", err)
	}
	if !bound {
		t.Error("the stored secret opened only via the LEGACY path, so it was sealed WITHOUT a " +
			"context and can be moved onto another oidc_config row")
	}
	if got != secret {
		t.Errorf("stored secret = %q, want %q", got, secret)
	}
	if _, err := env.cipher.OpenWithContext(ct,
		models.OIDCConfigClientSecretContext(otherOIDCConfigID)); err == nil {
		t.Error("the stored secret opened under another config's context; a retired row's secret " +
			"could be promoted onto the active row")
	}
}

const otherOIDCConfigID = "77777777-7777-7777-7777-777777777777"

// argString renders a recorded driver argument as the text the database would
// store. A uuid.UUID arrives as its own type rather than a string, so the
// comparison has to go through Stringer rather than a type assertion.
func argString(t *testing.T, v driver.Value) string {
	t.Helper()
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case interface{ String() string }:
		return x.String()
	}
	t.Fatalf("unexpected argument type %T", v)
	return ""
}
