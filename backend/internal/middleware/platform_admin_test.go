package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// The platform-admin carrier (issue #766, migration 000051).
//
// Authority for the `admin` wildcard is resolved ONCE, in the auth
// middleware, from a grant table that is not an organization membership. The
// twelve auth.HasScope(scopes, auth.ScopeAdmin) sites are untouched: they keep
// asking the same question and the answer starts coming from the carrier.
//
// PR 1 is non-breaking because the transition semantics are OR — effective
// admin is `carrier OR the existing scope union` — so all four combinations
// of the two sources are asserted here explicitly, plus the case the design
// is most worried about: an API key must NEVER inherit its owner's
// platform-admin status.
// ---------------------------------------------------------------------------

func newPlatformAdminRepo(t *testing.T) (*repositories.PlatformAdminRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (platform_admins): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewPlatformAdminRepository(db), mock
}

// expectCarrierLookup queues the one indexed read the middleware makes per
// user-session request.
func expectCarrierLookup(mock sqlmock.Sqlmock, userID string, granted bool) {
	mock.ExpectQuery("SELECT EXISTS.*FROM platform_admins").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(granted))
}

func generateScopedJWT(t *testing.T, userID string, scopes []string) string {
	t.Helper()
	token, err := auth.GenerateJWT(userID, "carrier@example.com", scopes, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	return token
}

// carrierJWTRouter wires AuthMiddleware over a mocked user repository and the
// carrier repository, and captures the effective scopes the handler sees.
func carrierJWTRouter(t *testing.T, userID string, paRepo *repositories.PlatformAdminRepository, got *[]string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	userRepo, userMock := newUserRepo(t)
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow(userID, "carrier@example.com", "Carrier", nil, time.Now(), time.Now()))

	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, nil, nil, nil, paRepo))
	r.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			*got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})
	return r
}

func doJWTRequest(r *gin.Engine, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	return w
}

func hasAdmin(scopes []string) bool {
	for _, s := range scopes {
		if s == string(auth.ScopeAdmin) {
			return true
		}
	}
	return false
}

// State 1 of 4 — CARRIER ONLY. The session token carries no admin scope at
// all; the grant row is the entire source of authority. This is the state PR 3
// makes the only one, so it must work now.
func TestAuthMiddleware_PlatformAdminCarrier_ElevatesSessionWithoutAdminScope(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	expectCarrierLookup(paMock, "user-carrier", true)

	var got []string
	r := carrierJWTRouter(t, "user-carrier", paRepo, &got)

	if w := doJWTRequest(r, generateScopedJWT(t, "user-carrier", []string{"modules:read"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if !hasAdmin(got) {
		t.Errorf("scopes = %v, want %q present: a carrier grant is the whole point of #766", got, auth.ScopeAdmin)
	}
	// The elevation ADDS; it does not replace what the session already held.
	if len(got) != 2 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want [modules:read admin]", got)
	}
	if err := paMock.ExpectationsWereMet(); err != nil {
		t.Errorf("the carrier was not consulted: %v", err)
	}
}

// State 2 of 4 — TEMPLATE ONLY. The pre-#766 path: authority arrives in the
// scope union from an admin-bearing role template, and there is no carrier
// row. This is the case that makes PR 1 non-breaking, and the assertion is on
// the EXACT scope set — an elevation that duplicated `admin` would still
// "contain admin" and pass a weaker check.
func TestAuthMiddleware_PlatformAdminCarrier_TemplateOnlyStillAdmin(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	expectCarrierLookup(paMock, "user-template", false)

	var got []string
	r := carrierJWTRouter(t, "user-template", paRepo, &got)

	if w := doJWTRequest(r, generateScopedJWT(t, "user-template", []string{"admin"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != string(auth.ScopeAdmin) {
		t.Errorf("scopes = %v, want exactly [admin]: the union side must still answer, and must not be duplicated", got)
	}
}

// State 3 of 4 — BOTH. The day-one state for every administrator the
// migration backfilled: a carrier row AND an admin-bearing role template.
// Asserting the EXACT set is what makes this different from the two above —
// the elevation must notice the caller already holds `admin` and add nothing,
// or every backfilled administrator carries a duplicated scope for the whole
// transition. Deleting the dedupe leaves all the other cases passing.
func TestAuthMiddleware_PlatformAdminCarrier_BothSourcesDoNotDuplicateAdmin(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	expectCarrierLookup(paMock, "user-both", true)

	var got []string
	r := carrierJWTRouter(t, "user-both", paRepo, &got)

	if w := doJWTRequest(r, generateScopedJWT(t, "user-both", []string{"admin"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != string(auth.ScopeAdmin) {
		t.Errorf("scopes = %v, want exactly [admin]: carrier AND template must not stack", got)
	}
}

// State 4 of 4 — NEITHER. No carrier row, no admin scope. The negative
// control: without it, a middleware that unconditionally appended `admin`
// would pass every test above.
func TestAuthMiddleware_PlatformAdminCarrier_NeitherSourceGrantsAdmin(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	expectCarrierLookup(paMock, "user-plain", false)

	var got []string
	r := carrierJWTRouter(t, "user-plain", paRepo, &got)

	if w := doJWTRequest(r, generateScopedJWT(t, "user-plain", []string{"modules:read"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want exactly [modules:read]", got)
	}
}

// A carrier lookup that does not resolve is a 500, not a silent "not an
// admin". Serving the downgrade would strip a platform administrator of the
// admin surface with a 403 and nothing saying why, during exactly the
// database incident in which they need it. Matches how this middleware treats
// the two revocation lookups above it.
func TestAuthMiddleware_PlatformAdminCarrier_LookupFailureAborts(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	paMock.ExpectQuery("SELECT EXISTS.*FROM platform_admins").
		WillReturnError(errors.New("carrier unavailable"))

	var got []string
	reached := false
	gin.SetMode(gin.TestMode)
	userRepo, userMock := newUserRepo(t)
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-err", "carrier@example.com", "Carrier", nil, time.Now(), time.Now()))
	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, nil, nil, nil, paRepo))
	r.GET("/", func(c *gin.Context) {
		reached = true
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	if w := doJWTRequest(r, generateScopedJWT(t, "user-err", []string{"modules:read"})); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (carrier lookup failed): body=%s", w.Code, w.Body.String())
	}
	if reached {
		t.Errorf("the handler ran with unresolved platform-admin authority; scopes = %v", got)
	}
}

// A nil carrier repository means the subsystem is not wired (unit tests), the
// same convention tokenRepo/userRevocations/orgRepo already use on this
// middleware. It must pass through, not panic or deny.
func TestAuthMiddleware_PlatformAdminCarrier_NilRepoPassesThrough(t *testing.T) {
	var got []string
	r := carrierJWTRouter(t, "user-nil", nil, &got)

	if w := doJWTRequest(r, generateScopedJWT(t, "user-nil", []string{"modules:read"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want exactly [modules:read]", got)
	}
}

// ---------------------------------------------------------------------------
// THE CONSTRAINT THE DESIGN CALLS OUT: an API key must NEVER inherit its
// owner's platform-admin status.
//
// Five of the twelve admin checks are in apikeys.go. Keys are already
// org-bound (#732) and already have their scopes re-derived per request from
// the owner's current membership; a long-lived credential silently carrying
// the highest privilege in the product is the shape of the original problem.
//
// The carrier mock is primed to answer TRUE — the owner really is a platform
// administrator — so a middleware that applied the carrier on this path would
// produce a CLEAN elevation and fail on the value, not trip over an
// incidental "unexpected query" error that a bare err != nil check would
// mistake for a passing test.
// ---------------------------------------------------------------------------
func TestAuthMiddleware_APIKey_DoesNotInheritOwnersPlatformAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	apiKeyDB, keyMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (apikey): %v", err)
	}
	t.Cleanup(func() { apiKeyDB.Close() })
	userDB, userMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (user): %v", err)
	}
	t.Cleanup(func() { userDB.Close() })
	orgRepo, orgMock := newOrgRepo(t)
	paRepo, paMock := newPlatformAdminRepo(t)

	token := "tfr_keyadmn_1"
	userID := "user-1"

	// The key's owner IS a platform administrator.
	expectCarrierLookup(paMock, userID, true)
	// The key itself is an ordinary org-bound publish credential.
	expectAPIKeyLookup(keyMock, token, &userID, []byte(`["modules:write"]`))
	expectKeyOwnerMembership(orgMock, "org-1", userID, []byte(`["modules:write"]`))
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow(userID, "owner@example.com", "Owner", nil, time.Now(), time.Now()))

	var got []string
	r := gin.New()
	r.Use(AuthMiddleware(nil, repositories.NewUserRepository(userDB),
		repositories.NewAPIKeyRepository(apiKeyDB), orgRepo, nil, nil, paRepo))
	r.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	if w := doKeyRequest(r, token); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if hasAdmin(got) {
		t.Errorf("scopes = %v: an API key inherited its owner's platform-admin grant", got)
	}
	if len(got) != 1 || got[0] != "modules:write" {
		t.Errorf("scopes = %v, want exactly [modules:write]", got)
	}
	// Structural half of the same claim: the carrier is not merely ignored on
	// this path, it is never read. An unmet expectation here is the pass.
	if err := paMock.ExpectationsWereMet(); err == nil {
		t.Error("the carrier was queried on the API-key path; it must be consulted only for user sessions")
	}
}

// The same key, presented to the optionally-authenticated public routes.
func TestOptionalAuthMiddleware_APIKey_DoesNotInheritOwnersPlatformAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	apiKeyDB, keyMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (apikey): %v", err)
	}
	t.Cleanup(func() { apiKeyDB.Close() })
	orgRepo, orgMock := newOrgRepo(t)
	paRepo, paMock := newPlatformAdminRepo(t)
	userRepo, userMock := newUserRepo(t)

	token := "tfr_optadmn_1"
	userID := "user-1"
	expectCarrierLookup(paMock, userID, true)
	expectAPIKeyLookup(keyMock, token, &userID, []byte(`["modules:read"]`))
	expectKeyOwnerMembership(orgMock, "org-1", userID, []byte(`["modules:read"]`))
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow(userID, "owner@example.com", "Owner", nil, time.Now(), time.Now()))

	var got []string
	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, repositories.NewAPIKeyRepository(apiKeyDB), orgRepo, nil, nil, paRepo))
	r.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	if w := doKeyRequest(r, token); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if hasAdmin(got) {
		t.Errorf("scopes = %v: an API key inherited its owner's platform-admin grant", got)
	}
	if err := paMock.ExpectationsWereMet(); err == nil {
		t.Error("the carrier was queried on the API-key path; it must be consulted only for user sessions")
	}
}

// ---------------------------------------------------------------------------
// OptionalAuthMiddleware — the SAME context shape as AuthMiddleware.
//
// No route mounted under it consults ScopeAdmin today. Publishing a different
// effective scope set anyway is how a check comes to behave differently
// depending on which group a route sits in — the divergence already recorded
// in this file's jwt_claims comment, and tracked as #665.
// ---------------------------------------------------------------------------

func TestOptionalAuthMiddleware_PlatformAdminCarrier_ElevatesSession(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	expectCarrierLookup(paMock, "user-opt", true)

	gin.SetMode(gin.TestMode)
	userRepo, userMock := newUserRepo(t)
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-opt", "carrier@example.com", "Carrier", nil, time.Now(), time.Now()))

	var got []string
	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, nil, nil, nil, paRepo))
	r.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	if w := doJWTRequest(r, generateScopedJWT(t, "user-opt", []string{"modules:read"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 2 || got[0] != "modules:read" || got[1] != string(auth.ScopeAdmin) {
		t.Errorf("scopes = %v, want [modules:read admin]", got)
	}
}

// A carrier lookup failure here leaves the caller UNELEVATED and the request
// authenticated, matching how this middleware already swallows its revocation
// lookups. Fail-closed by construction: the carrier can only add authority.
func TestOptionalAuthMiddleware_PlatformAdminCarrier_LookupFailureLeavesUnelevated(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	paMock.ExpectQuery("SELECT EXISTS.*FROM platform_admins").
		WillReturnError(errors.New("carrier unavailable"))

	gin.SetMode(gin.TestMode)
	userRepo, userMock := newUserRepo(t)
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-opterr", "carrier@example.com", "Carrier", nil, time.Now(), time.Now()))

	var got []string
	var userWasSet bool
	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, nil, nil, nil, paRepo))
	r.GET("/", func(c *gin.Context) {
		_, userWasSet = c.Get("user")
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	if w := doJWTRequest(r, generateScopedJWT(t, "user-opterr", []string{"modules:read"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (optional auth always passes through): body=%s", w.Code, w.Body.String())
	}
	if !userWasSet {
		t.Error("a carrier lookup failure must not un-authenticate the request")
	}
	if len(got) != 1 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want exactly [modules:read]: an unresolved carrier must not elevate", got)
	}
}
