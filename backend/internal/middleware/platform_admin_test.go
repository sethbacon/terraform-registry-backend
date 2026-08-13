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
// The platform-admin carrier (issue #766, migrations 000051 and 000054).
//
// Authority for the `admin` wildcard is resolved ONCE, in the auth
// middleware, from a grant table that is not an organization membership. The
// twelve auth.HasScope(scopes, auth.ScopeAdmin) sites are untouched: they keep
// asking the same question and the answer comes from the carrier.
//
// THE CARRIER IS NOW THE ONLY SOURCE (migration 000054). Until this release
// effective admin was `carrier OR the session's scope union`, and a session
// that carried `admin` from an admin-bearing role template was a platform
// administrator. It is not any more: the elevation strips `admin` from the
// union before it does anything else. All four combinations of the two sources
// are asserted here explicitly — state 2 in particular, which is the one that
// changed and the one an operator will notice — plus the case the design is
// most worried about: an API key must NEVER carry platform-admin authority.
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
// all; the grant row is the entire source of authority. This is the only state
// that confers it.
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

// State 2 of 4 — TEMPLATE ONLY, AND THIS IS THE BREAKING CHANGE. The pre-#766
// path: authority arrives in the scope union from an admin-bearing role
// template and there is no carrier row. Until migration 000054 that principal
// was a platform administrator everywhere. Now the `admin` the token carries is
// stripped and nothing replaces it.
//
// The assertion is on the EXACT scope set rather than on "admin is absent": the
// stripping must remove the wildcard and NOTHING ELSE, or a session loses the
// modules and providers scopes it legitimately holds along with it.
func TestAuthMiddleware_PlatformAdminCarrier_TemplateOnlyIsNoLongerAdmin(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	expectCarrierLookup(paMock, "user-template", false)

	var got []string
	r := carrierJWTRouter(t, "user-template", paRepo, &got)

	token := generateScopedJWT(t, "user-template", []string{"modules:read", "admin", "providers:read"})
	if w := doJWTRequest(r, token); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if hasAdmin(got) {
		t.Errorf("scopes = %v: an admin-bearing role template still confers platform-admin authority. "+
			"Removing `admin` from the seeded templates is data and data can be re-added; this strip is "+
			"the half that makes it enforcement (#766)", got)
	}
	if len(got) != 2 || got[0] != "modules:read" || got[1] != "providers:read" {
		t.Errorf("scopes = %v, want exactly [modules:read providers:read]: the strip must remove the "+
			"wildcard and nothing else", got)
	}
}

// The claims the token was minted with must survive the strip untouched.
// jwt_claims is published on the context beside `scopes`, and any handler
// reading it would see a scope list the middleware had quietly rewritten if the
// filter worked in place on the shared backing array.
func TestAuthMiddleware_PlatformAdminCarrier_StripDoesNotRewriteTheClaims(t *testing.T) {
	paRepo, paMock := newPlatformAdminRepo(t)
	expectCarrierLookup(paMock, "user-claims", false)

	gin.SetMode(gin.TestMode)
	userRepo, userMock := newUserRepo(t)
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-claims", "carrier@example.com", "Carrier", nil, time.Now(), time.Now()))

	var claimScopes []string
	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, nil, nil, nil, paRepo))
	r.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("jwt_claims"); ok {
			if claims, ok := v.(*auth.Claims); ok {
				claimScopes = claims.Scopes
			}
		}
		c.Status(http.StatusOK)
	})

	if w := doJWTRequest(r, generateScopedJWT(t, "user-claims", []string{"modules:read", "admin"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(claimScopes) != 2 || claimScopes[1] != string(auth.ScopeAdmin) {
		t.Errorf("jwt_claims.Scopes = %v, want the token's own [modules:read admin] — the strip must not "+
			"write through the claims' backing array", claimScopes)
	}
}

// State 3 of 4 — BOTH. A carrier row AND a token that still claims `admin`,
// which is every backfilled administrator holding a session minted before the
// upgrade. Asserting the EXACT set is what makes this different from the two
// above: strip-then-add must leave one `admin`, not two, or every such
// administrator carries a duplicated scope until their token expires.
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
// middleware. It must pass the request through, not panic or deny — and it must
// still strip. An unwired carrier cannot answer the authority question, and
// serving the union's `admin` instead would answer it from the source this
// release stopped trusting: a mis-wiring would silently restore the whole
// pre-#766 behaviour with every test still green.
func TestAuthMiddleware_PlatformAdminCarrier_NilRepoPassesThroughUnelevated(t *testing.T) {
	var got []string
	r := carrierJWTRouter(t, "user-nil", nil, &got)

	if w := doJWTRequest(r, generateScopedJWT(t, "user-nil", []string{"modules:read", "admin"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want exactly [modules:read]: an unwired carrier must not leave the union's "+
			"`admin` standing", got)
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
// lookups.
//
// The token deliberately CLAIMS `admin`. While the carrier could only add
// authority, ignoring the failed lookup and keeping the caller's own scopes was
// fail-closed; now that the carrier is the only source, doing so would serve
// the union's wildcard on exactly the requests where authority could not be
// established. The strip has to survive the error path.
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

	if w := doJWTRequest(r, generateScopedJWT(t, "user-opterr", []string{"modules:read", "admin"})); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (optional auth always passes through): body=%s", w.Code, w.Body.String())
	}
	if !userWasSet {
		t.Error("a carrier lookup failure must not un-authenticate the request")
	}
	if len(got) != 1 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want exactly [modules:read]: an unresolved carrier must neither elevate "+
			"nor leave the token's own `admin` claim standing", got)
	}
}

// An API key whose FROZEN scope list contains `admin` must not present it,
// whether or not the per-request re-derivation runs. This exercises the branch
// that SKIPS currentKeyScopes and publishes the api_keys snapshot verbatim —
// the one place a wildcard frozen on the row would otherwise reach a handler.
func TestAuthMiddleware_APIKey_AdminScopeInTheSnapshotIsStripped(t *testing.T) {
	gin.SetMode(gin.TestMode)

	apiKeyDB, keyMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (apikey): %v", err)
	}
	t.Cleanup(func() { apiKeyDB.Close() })
	userRepo, userMock := newUserRepo(t)

	token := "tfr_frozenad"
	userID := "user-1"
	expectAPIKeyLookup(keyMock, token, &userID, []byte(`["admin","modules:read"]`))
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow(userID, "owner@example.com", "Owner", nil, time.Now(), time.Now()))

	var got []string
	r := gin.New()
	// orgRepo is nil, so the re-derivation is skipped: this is the snapshot path.
	r.Use(AuthMiddleware(nil, userRepo, repositories.NewAPIKeyRepository(apiKeyDB), nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	if w := doKeyRequest(r, token); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want exactly [modules:read]: an api_keys row carrying the `admin` wildcard "+
			"presented it to a handler, and a key never consults the carrier (#766)", got)
	}
}
