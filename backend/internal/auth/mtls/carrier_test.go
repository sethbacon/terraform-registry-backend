package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// mTLS was the last credential class outside the platform-admin carrier (#876).
// #874 brought sessions under Carrier.SessionScopes and stripped `admin` from
// API keys with KeyScopes, but a subject→scope mapping still published whatever
// the config file said — so `scopes: ["admin"]` produced a platform
// administrator with no grant record, no audit entry, and no revocation short
// of editing configuration and restarting.
//
// These tests hold the two halves of the fix shut: a mapping cannot reach
// `admin` without naming a user, and a mapping that names one is only as
// administrative as that user's carrier row says, RIGHT NOW.

const (
	testUserID  = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	otherUserID = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
)

func newTestCarrier(t *testing.T) (*platformadmin.Carrier, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	carrier, err := platformadmin.New(db, "platform_admins")
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	return carrier, mock
}

func expectCarrierLookup(mock sqlmock.Sqlmock, userID string, granted bool) {
	mock.ExpectQuery(`SELECT EXISTS.*FROM "platform_admins"`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(granted))
}

func certFor(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

// runRequest drives the middleware with a verified client certificate and
// returns the status and the scopes the RBAC layer would read.
func runRequest(t *testing.T, p *Provider, carrier *platformadmin.Carrier, cn string) (int, []string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	var published []string
	r := gin.New()
	r.Use(AuthMiddleware(p, carrier))
	r.GET("/x", func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			published, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/x", nil)
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certFor(cn)}}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, published
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Startup refusal: `admin` needs a user to resolve against
// ---------------------------------------------------------------------------

func TestNewProvider_RefusesAdminWithoutAUser(t *testing.T) {
	_, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=ci", Scopes: []string{"modules:read", "admin"}},
		},
	})
	if err == nil {
		t.Fatal("a mapping carrying `admin` with no user_id was accepted; the carrier is " +
			"keyed on a user, so such a grant can never be audited or revoked")
	}
	if !strings.Contains(err.Error(), "user_id") {
		t.Errorf("error should tell the operator what to add, got: %v", err)
	}
}

func TestNewProvider_AcceptsAdminWithAUser(t *testing.T) {
	p, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=ci", Scopes: []string{"admin"}, UserID: testUserID},
		},
	})
	if err != nil {
		t.Fatalf("a mapping naming a user should build: %v", err)
	}
	_, _, userID, aerr := p.Authenticate(certFor("ci"))
	if aerr != nil {
		t.Fatalf("Authenticate: %v", aerr)
	}
	if userID != testUserID {
		t.Errorf("user_id = %q, want %q — the binding must survive to the middleware", userID, testUserID)
	}
}

func TestNewProvider_RefusesNonUUIDUser(t *testing.T) {
	_, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=ci", Scopes: []string{"modules:read"}, UserID: "alice@example.com"},
		},
	})
	if err == nil {
		t.Fatal("a non-UUID user_id was accepted; it would never match a carrier row and " +
			"would fail silently as 'not an administrator'")
	}
}

func TestNewProvider_RefusesDuplicateSubjects(t *testing.T) {
	_, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=ci", Scopes: []string{"modules:read"}, UserID: testUserID},
			{Subject: "cn=CI", Scopes: []string{"modules:write"}, UserID: otherUserID},
		},
	})
	if err == nil {
		t.Fatal("a repeated subject was accepted; last-write-wins would bind the certificate " +
			"to a different user than the line the operator is reading")
	}
}

// ---------------------------------------------------------------------------
// Runtime: the carrier, not the config file, decides
// ---------------------------------------------------------------------------

func TestAdminHoldsOnlyWhileTheCarrierRowDoes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		granted   bool
		wantAdmin bool
	}{
		{"carrier row present — admin holds", true, true},
		{"carrier row absent — admin does not hold", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProvider(config.MTLSConfig{
				Enabled:      true,
				ClientCAFile: "/ca.crt",
				Mappings: []config.MTLSSubjectMapping{
					{Subject: "CN=ci", Scopes: []string{"modules:read", "admin"}, UserID: testUserID},
				},
			})
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}
			carrier, mock := newTestCarrier(t)
			expectCarrierLookup(mock, testUserID, tc.granted)

			status, scopes := runRequest(t, p, carrier, "ci")
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			if got := hasScope(scopes, "admin"); got != tc.wantAdmin {
				t.Errorf("admin in published scopes = %v, want %v (scopes=%v)", got, tc.wantAdmin, scopes)
			}
			// The configured non-admin scope is untouched either way.
			if !hasScope(scopes, "modules:read") {
				t.Errorf("modules:read was lost; only `admin` is the carrier's business (scopes=%v)", scopes)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the carrier was not consulted: %v", err)
			}
		})
	}
}

func TestCarrierLookupFailureIsARefusalToAnswer(t *testing.T) {
	p, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=ci", Scopes: []string{"admin"}, UserID: testUserID},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	carrier, mock := newTestCarrier(t)
	mock.ExpectQuery(`SELECT EXISTS.*FROM "platform_admins"`).
		WithArgs(testUserID).
		WillReturnError(errBoom{})

	status, _ := runRequest(t, p, carrier, "ci")
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 — an authority question that did not resolve must not "+
			"be served as a completed 'no'", status)
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "carrier unavailable" }

// A mapping with no user cannot publish `admin` even if one reaches the publish
// path — NewProvider refuses to build one, so this asserts the second lock.
func TestPublishStripsAdminWhenNoUserIsNamed(t *testing.T) {
	p := &Provider{mappings: map[string]subjectMapping{
		"cn=ci": {scopes: []string{"modules:read", "admin"}},
	}}
	carrier, _ := newTestCarrier(t)

	status, scopes := runRequest(t, p, carrier, "ci")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if hasScope(scopes, "admin") {
		t.Errorf("admin published for a mapping naming no user (scopes=%v)", scopes)
	}
	if !hasScope(scopes, "modules:read") {
		t.Errorf("modules:read was lost (scopes=%v)", scopes)
	}
}

// A nil carrier is a deployment that never built one. It must degrade to
// stripping, not to trusting the config file.
func TestNilCarrierStripsRatherThanTrusts(t *testing.T) {
	p := &Provider{mappings: map[string]subjectMapping{
		"cn=ci": {scopes: []string{"modules:read", "admin"}, userID: testUserID},
	}}

	status, scopes := runRequest(t, p, nil, "ci")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if hasScope(scopes, "admin") {
		t.Errorf("admin published with no carrier to confirm it (scopes=%v)", scopes)
	}
}

// An ordinary machine credential needs no user and is not charged a carrier
// lookup.
func TestNonAdminMappingNeedsNoUserAndNoLookup(t *testing.T) {
	p, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=ci", Scopes: []string{"modules:read", "providers:read"}},
		},
	})
	if err != nil {
		t.Fatalf("an ordinary mapping should need no user_id: %v", err)
	}
	carrier, mock := newTestCarrier(t)

	status, scopes := runRequest(t, p, carrier, "ci")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(scopes) != 2 || !hasScope(scopes, "modules:read") || !hasScope(scopes, "providers:read") {
		t.Errorf("scopes = %v, want the two configured ones unchanged", scopes)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected carrier traffic for a mapping with no user: %v", err)
	}
}
