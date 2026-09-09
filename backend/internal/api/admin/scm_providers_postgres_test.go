package admin

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm/appcreds"
)

// The SCM provider handlers against a REAL database, because the invariants
// that matter here live in a CHECK constraint sqlmock cannot see.
//
// scm_providers_entra_credential_shape requires client_secret_encrypted to be
// EMPTY for a federated or certificate provider. The create handler used to
// seal req.ClientSecret unconditionally, and sealing "" yields a non-empty
// ciphertext -- so every federated create was refused by the constraint and
// surfaced as a 500. Every sqlmock-backed test passed: a mock accepts any
// value for a column. That shipped in 4.19.0 (#1043) and was found only when
// the certificate work checked a create against the real constraint (#1041).
//
// Set TFR_TEST_DATABASE_URL to run. The database it names is only used to
// CREATE and DROP the scratch database; the migrations run there.

func scmScratchDB(t *testing.T) *sql.DB {
	t.Helper()
	raw := os.Getenv("TFR_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TFR_TEST_DATABASE_URL not set — needs a reachable Postgres")
	}
	base, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(base.Scheme, "postgres") {
		t.Skipf("TFR_TEST_DATABASE_URL is not a postgres:// URL (%q)", raw)
	}
	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("Postgres not reachable at TFR_TEST_DATABASE_URL: %v", err)
	}
	name := "tfr_scm_1041_" + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
		t.Skipf("cannot create a scratch database (needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		drop, err := sql.Open("pgx", raw)
		if err != nil {
			return
		}
		defer drop.Close()
		_, _ = drop.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})
	scratch := *base
	scratch.Path = "/" + name
	conn, err := sql.Open("pgx", scratch.String())
	if err != nil {
		t.Fatalf("sql.Open scratch: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.RunMigrations(conn, "up"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return conn
}

// realSCMRouter is newSCMProviderAppRouter over a real database.
func realSCMRouter(t *testing.T, conn *sql.DB) (*gin.Engine, string) {
	t.Helper()
	sqlxDB := sqlx.NewDb(conn, "pgx")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	orgRepo := repositories.NewOrganizationRepository(conn)
	cipher := testTokenCipher(t)
	h := NewSCMProviderHandlers(&config.Config{}, scmRepo, orgRepo, cipher).
		WithMinter(appcreds.NewMinter(cipher, scmRepo))

	// The first organization is seeded by migration 000001; use it rather than
	// inventing one, so the row satisfies every FK the schema actually has.
	var orgID string
	if err := conn.QueryRow(`SELECT id FROM organizations ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Fatalf("no seeded organization: %v", err)
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Set("user_id", "test-admin")
	})
	r.POST("/scm-providers", h.CreateProvider)
	r.PUT("/scm-providers/:id", h.UpdateProvider)
	return r, orgID
}

type providerRow struct {
	credType string
	secret   string
	cert     sql.NullString
	tenant   sql.NullString
}

func loadRow(t *testing.T, conn *sql.DB, name string) providerRow {
	t.Helper()
	var row providerRow
	err := conn.QueryRow(`SELECT entra_credential_type, client_secret_encrypted, encrypted_entra_certificate, tenant_id
	                        FROM scm_providers WHERE name = $1`, name).
		Scan(&row.credType, &row.secret, &row.cert, &row.tenant)
	if err != nil {
		t.Fatalf("load %q: %v", name, err)
	}
	return row
}

func TestSCMProviders_Postgres_EntraCredentialShapes(t *testing.T) {
	conn := scmScratchDB(t)
	r, orgID := realSCMRouter(t, conn)
	bundle := testCertificateBundle(t)

	post := func(body map[string]interface{}) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(body)), orgID))
		return w
	}
	base := func(name, credType string) map[string]interface{} {
		return map[string]interface{}{
			"provider_type": "azuredevops", "name": name, "base_url": "https://dev.azure.com/acme",
			"auth_mode": "entra_app", "client_id": "client-1", "entra_credential_type": credType,
		}
	}

	t.Run("federated create is accepted by the real constraint", func(t *testing.T) {
		// The 4.19.0 regression: this returned 500 on every real database.
		w := post(base("fed", "federated"))
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
		}
		row := loadRow(t, conn, "fed")
		if row.secret != "" {
			t.Errorf("federated row carries client_secret_encrypted=%q; the constraint requires empty", row.secret)
		}
		if strings.Contains(w.Body.String(), `"has_client_secret":true`) {
			t.Error("federated provider reports a client secret")
		}
	})

	t.Run("certificate create stores exactly its own material", func(t *testing.T) {
		b := base("cert", "certificate")
		b["tenant_id"] = "tenant-1"
		b["entra_certificate"] = bundle
		w := post(b)
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
		}
		row := loadRow(t, conn, "cert")
		if row.credType != "certificate" || row.secret != "" || !row.cert.Valid || row.cert.String == "" {
			t.Errorf("row = %+v, want certificate with an empty secret and a stored bundle", row)
		}
		if row.cert.String == bundle {
			t.Error("the bundle was stored in the clear")
		}
	})

	t.Run("client_secret create still stores a secret", func(t *testing.T) {
		b := base("sec", "client_secret")
		b["tenant_id"] = "tenant-1"
		b["client_secret"] = "s3cr3t"
		w := post(b)
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
		}
		row := loadRow(t, conn, "sec")
		if row.secret == "" || row.secret == "s3cr3t" || row.cert.Valid && row.cert.String != "" {
			t.Errorf("row = %+v, want a sealed secret and no bundle", row)
		}
	})

	t.Run("switching to certificate in one request satisfies the constraint", func(t *testing.T) {
		var id string
		if err := conn.QueryRow(`SELECT id FROM scm_providers WHERE name='sec'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+id, jsonBody(map[string]interface{}{
			"entra_credential_type": "certificate", "entra_certificate": bundle, "client_secret": "",
		})))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
		}
		row := loadRow(t, conn, "sec")
		if row.credType != "certificate" || row.secret != "" || !row.cert.Valid || row.cert.String == "" {
			t.Errorf("after switch row = %+v", row)
		}

		// And back, clearing the bundle in the same request.
		w = httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/scm-providers/"+id, jsonBody(map[string]interface{}{
			"entra_credential_type": "client_secret", "client_secret": "rotated", "entra_certificate": "",
		})))
		if w.Code != http.StatusOK {
			t.Fatalf("switch back: status = %d, want 200: body=%s", w.Code, w.Body.String())
		}
		row = loadRow(t, conn, "sec")
		if row.credType != "client_secret" || row.secret == "" || (row.cert.Valid && row.cert.String != "") {
			t.Errorf("after switch back row = %+v", row)
		}
	})
}
