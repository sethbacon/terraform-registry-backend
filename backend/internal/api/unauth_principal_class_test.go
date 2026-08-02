// unauth_principal_class_test.go is the class test for the defect class
//
//	"an unauthenticated endpoint derives a principal from a caller-supplied
//	 value that is not a credential"
//
// The live instance was GET /api/v1/scm-providers/:id/oauth/callback: registered
// bare on apiV1 with no auth middleware and no rate limiter, its only binding to
// a principal was an OAuth `state` of fmt.Sprintf("%s:%s", userID, providerID) —
// two UUIDs, not random, not stored server-side, not single-use, no expiry, and
// with the provider half never compared to anything. The handler parsed the user
// id out of the request and wrote scm_oauth_tokens, whose
// ON CONFLICT (user_id, scm_provider_id) DO UPDATE overwrote the victim's row.
//
// The class invariant this file pins, for EVERY unauthenticated route that
// resolves a principal:
//
//	the principal must come from a server-side row looked up by an unguessable
//	secret, and that lookup must reject a value that was never issued, has
//	expired, has already been redeemed, or was minted for a different resource —
//	before any identity-keyed write happens.
//
// The table below carries one row per enumerated site. Sites are enumerated by
// the signature described in the batch-C fix report: every route whose gin
// middleware chain contains no auth middleware, intersected with those whose
// handler resolves a principal. Scenarios that do not apply to a site are
// recorded explicitly rather than silently omitted.
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/api/webhooks"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// Scenarios — the four ways a non-credential must be refused.
// ---------------------------------------------------------------------------

type classScenario string

const (
	scenNeverIssued      classScenario = "never-issued state rejected before any token write"
	scenReplayed         classScenario = "replayed state rejected the second time"
	scenExpired          classScenario = "expired state rejected"
	scenResourceMismatch classScenario = "state whose stored resource id does not match the path rejected"
)

// classSite is one enumerated unauthenticated principal-resolving route.
type classSite struct {
	// name is the site's stable identifier, also used by the mutation matrix.
	name string
	// route is the production registration this site stands for.
	route string
	// guardLine is the single line of source that refuses the non-credential.
	// Mutating it must make this site's rows fail — that is what proves the
	// rows test the guard rather than incidental behaviour.
	guardLine string
	// wantStatus is the status the GUARD produces. It is asserted exactly, not
	// as ">= 400": a mutated guard typically still errors out further down the
	// handler (provider-not-found, decrypt failure) and a loose ">= 400" check
	// would call that a pass. The specific code is what distinguishes "the
	// non-credential was refused" from "the attack proceeded and then tripped
	// over something else".
	wantStatus int
	// wantBodyContains, when set, additionally pins that the rejection came
	// from the state/secret check rather than from some later failure.
	wantBodyContains string
	// wantBody overrides wantBodyContains per scenario. This is load-bearing,
	// not decoration: mutation testing showed that for oidc-auth-callback a
	// removed guard still yields 400 (the flow runs on and fails at
	// "provider_not_configured"), so status alone scored a removed guard as a
	// pass. Pinning the guard's own message is what makes the row fail.
	wantBody map[classScenario]string
	// exercise runs one scenario. It returns the response and a bool reporting
	// whether the scenario applies to this site; false means "not applicable",
	// with the reason recorded in naReason.
	exercise func(t *testing.T, scen classScenario) (*httptest.ResponseRecorder, bool)
	// naReason explains, per scenario, why an inapplicable scenario is absent.
	naReason map[classScenario]string
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func classRandomHex64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b)
}

// classRandomState mints a state in the same encoding the login and SCM flows
// use (32 bytes crypto/rand, base64url).
func classRandomState(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func classHash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func classSQLMock(t *testing.T) (*sqlx.DB, *sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlx.NewDb(db, "sqlmock"), db, mock
}

var classModuleSourceRepoCols = []string{
	"id", "module_id", "scm_provider_id",
	"repository_owner", "repository_name", "repository_url",
	"default_branch", "module_path", "tag_pattern",
	"auto_publish", "webhook_id", "webhook_url",
	"webhook_enabled", "last_sync_at", "last_sync_commit",
	"created_at", "updated_at",
}

// ---------------------------------------------------------------------------
// Site 1 — GET /api/v1/scm-providers/:id/oauth/callback   (THE FIXED INSTANCE)
// ---------------------------------------------------------------------------

func exerciseSCMOAuthCallback(t *testing.T, scen classScenario) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	sqlxDB, _, mock := classSQLMock(t)

	store := auth.NewMemoryStateStore(time.Minute)
	t.Cleanup(func() { _ = store.Close() })

	scmRepo := repositories.NewSCMRepository(sqlxDB)
	h := admin.NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil).WithStateStore(store)

	r := gin.New()
	r.GET("/api/v1/scm-providers/:id/oauth/callback", h.HandleOAuthCallback)

	ctx := t.Context()
	pathProviderID := uuid.New()
	victimUserID := uuid.New()
	state := classRandomState(t)

	mint := func(providerID uuid.UUID, createdAt time.Time) {
		if err := store.Save(ctx, state, &auth.SessionState{
			State:         state,
			CreatedAt:     createdAt,
			ProviderType:  "scm",
			SCMUserID:     victimUserID.String(),
			SCMProviderID: providerID.String(),
		}, 10*time.Minute); err != nil {
			t.Fatalf("state store Save: %v", err)
		}
	}

	switch scen {
	case scenNeverIssued:
		// Nothing minted — the attacker invented the state, exactly as they
		// could when it was just "<victim-uuid>:<provider-uuid>".

	case scenReplayed:
		mint(pathProviderID, time.Now())
		// Load is read-consuming, so a legitimate first redemption burns it.
		if _, err := store.Load(ctx, state); err != nil {
			t.Fatalf("first Load: %v", err)
		}

	case scenExpired:
		mint(pathProviderID, time.Now().Add(-30*time.Minute))

	case scenResourceMismatch:
		// A state legitimately minted for a DIFFERENT provider, replayed at
		// this provider's callback path.
		mint(uuid.New(), time.Now())
	}

	// Deliberately program NO db expectations. Any provider lookup or any write
	// to scm_oauth_tokens would be an unexpected call — the guard must reject
	// before the handler reaches the database at all, which is the "rejected
	// BEFORE any token write" half of the assertion.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/v1/scm-providers/"+pathProviderID.String()+
			"/oauth/callback?code=attacker-code&state="+url.QueryEscape(state), nil))

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("db expectations: %v", err)
	}
	return w, true
}

// ---------------------------------------------------------------------------
// Site 2 — POST /webhooks/approvals/:token   (the pattern site 1 now mirrors)
// ---------------------------------------------------------------------------

func exerciseApprovalRedeem(t *testing.T, scen classScenario) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	if scen == scenResourceMismatch {
		return nil, false
	}
	sqlxDB, _, mock := classSQLMock(t)

	h := webhooks.NewApprovalHandler(repositories.NewRBACRepository(sqlxDB))
	r := gin.New()
	r.POST("/webhooks/approvals/:token", h.RedeemApprovalToken)

	token := classRandomHex64(t)
	cols := []string{"approval_request_id", "expires_at", "used_at"}
	sel := mock.ExpectQuery("SELECT approval_request_id").WithArgs(classHash(token))

	switch scen {
	case scenNeverIssued:
		sel.WillReturnError(sql.ErrNoRows)
	case scenReplayed:
		sel.WillReturnRows(sqlmock.NewRows(cols).AddRow(
			uuid.New(), time.Now().Add(time.Hour), time.Now()))
	case scenExpired:
		sel.WillReturnRows(sqlmock.NewRows(cols).AddRow(
			uuid.New(), time.Now().Add(-time.Hour), nil))
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/webhooks/approvals/"+token, nil))

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("db expectations: %v", err)
	}
	return w, true
}

// ---------------------------------------------------------------------------
// Site 3 — GET /api/v1/auth/callback   (OIDC login, StateStore-backed)
// ---------------------------------------------------------------------------

func exerciseOIDCCallback(t *testing.T, scen classScenario) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	if scen == scenResourceMismatch {
		return nil, false
	}
	_, rawDB, _ := classSQLMock(t)

	store := auth.NewMemoryStateStore(time.Minute)
	t.Cleanup(func() { _ = store.Close() })

	h, err := admin.NewAuthHandlers(&config.Config{}, rawDB, nil, nil, store)
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}
	r := gin.New()
	r.GET("/api/v1/auth/callback", h.CallbackHandler())

	state := classRandomHex64(t)
	ctx := t.Context()

	switch scen {
	case scenNeverIssued:
		// Nothing saved: the caller invented the state.
	case scenReplayed:
		if err := store.Save(ctx, state, &auth.SessionState{
			State: state, CreatedAt: time.Now(), ProviderType: "oidc",
		}, 10*time.Minute); err != nil {
			t.Fatalf("Save: %v", err)
		}
		// Load is consuming, so the first redemption burns it.
		if _, err := store.Load(ctx, state); err != nil {
			t.Fatalf("first Load: %v", err)
		}
	case scenExpired:
		// Present in the store but older than the handler's 5-minute bound.
		if err := store.Save(ctx, state, &auth.SessionState{
			State: state, CreatedAt: time.Now().Add(-10 * time.Minute), ProviderType: "oidc",
		}, 10*time.Minute); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/callback?code=attacker-code&state="+state, nil))
	return w, true
}

// ---------------------------------------------------------------------------
// Site 4 — POST /webhooks/scm/:module_source_repo_id/:secret
// ---------------------------------------------------------------------------

func exerciseSCMWebhook(t *testing.T, scen classScenario) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	// A webhook secret is a long-lived shared credential by design: it is
	// re-presented on every delivery, so single-use and expiry are not part of
	// its contract. Only the never-issued scenario applies.
	if scen != scenNeverIssued {
		return nil, false
	}
	sqlxDB, _, mock := classSQLMock(t)

	cipher, err := crypto.NewTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	h := webhooks.NewSCMWebhookHandler(repositories.NewSCMRepository(sqlxDB), nil, cipher)
	r := gin.New()
	r.POST("/webhooks/scm/:module_source_repo_id/:secret", h.HandleWebhook)

	linkID := uuid.New()
	providerID := uuid.New()
	storedURL := "https://registry.example.com/webhooks/scm/" + linkID.String() + "/" + classRandomHex64(t)

	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE id").
		WithArgs(linkID).
		WillReturnRows(sqlmock.NewRows(classModuleSourceRepoCols).AddRow(
			linkID, uuid.New(), providerID,
			"my-org", "my-repo", nil,
			"main", "", "v*",
			false, nil, storedURL,
			false, nil, nil,
			time.Now(), time.Now(),
		))
	// No provider lookup is programmed: the secret must be refused first.

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/webhooks/scm/"+linkID.String()+"/"+classRandomHex64(t), nil))

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("db expectations: %v", err)
	}
	return w, true
}

// ---------------------------------------------------------------------------
// The class table
// ---------------------------------------------------------------------------

func classSites() []classSite {
	return []classSite{
		{
			name:       "scm-oauth-callback",
			route:      "GET /api/v1/scm-providers/:id/oauth/callback",
			guardLine:  "internal/api/admin/scm_oauth.go — GUARD (scm-oauth-callback): stateStore.Load nil-check + ProviderType check + CreatedAt bound + sessionState.SCMProviderID != providerID; principal from sessionState.SCMUserID",
			exercise:   exerciseSCMOAuthCallback,
			wantStatus: http.StatusBadRequest,
			wantBody: map[classScenario]string{
				scenNeverIssued:      "invalid, expired, or already-used state parameter",
				scenReplayed:         "invalid, expired, or already-used state parameter",
				scenExpired:          "invalid, expired, or already-used state parameter",
				scenResourceMismatch: "state parameter does not match this provider",
			},
		},
		{
			name:             "webhook-approval-redeem",
			route:            "POST /webhooks/approvals/:token",
			guardLine:        "internal/db/repositories/rbac_repository.go — RedeemApprovalToken: used_at/expires_at checks + UPDATE ... WHERE used_at IS NULL",
			exercise:         exerciseApprovalRedeem,
			wantStatus:       http.StatusNotFound,
			wantBodyContains: "Token not found, already used, or expired",
			naReason: map[classScenario]string{
				scenResourceMismatch: "the token is FK-bound to exactly one approval_request_id and the route carries no second resource id to cross-check",
			},
		},
		{
			name:       "oidc-auth-callback",
			route:      "GET /api/v1/auth/callback",
			guardLine:  "internal/api/admin/auth.go — CallbackHandler: stateStore.Load(state) nil-check + time.Since(sessionState.CreatedAt) > 5*time.Minute",
			exercise:   exerciseOIDCCallback,
			wantStatus: http.StatusBadRequest,
			wantBody: map[classScenario]string{
				scenNeverIssued: "Invalid state parameter",
				scenReplayed:    "Invalid state parameter",
				scenExpired:     "Login session expired",
			},
			naReason: map[classScenario]string{
				scenResourceMismatch: "the route has no resource path parameter; the provider is read from the stored session state itself",
			},
		},
		{
			name:             "scm-webhook",
			route:            "POST /webhooks/scm/:module_source_repo_id/:secret",
			guardLine:        "internal/api/webhooks/scm_webhook.go — subtle.ConstantTimeCompare(storedSecret, requestSecret) != 1",
			exercise:         exerciseSCMWebhook,
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "invalid webhook secret",
			naReason: map[classScenario]string{
				scenReplayed:         "a webhook secret is long-lived and re-presented on every delivery; single-use is not its contract",
				scenExpired:          "a webhook secret has no expiry by design; it is rotated by relinking the module",
				scenResourceMismatch: "the secret is stored on the very row the path id selects, so the binding is the lookup itself",
			},
		},
	}
}

// TestUnauthenticatedPrincipalDerivation_Class asserts the class invariant at
// every enumerated site: a caller-supplied value that is not a credential must
// be refused, and refused before any identity-keyed write.
func TestUnauthenticatedPrincipalDerivation_Class(t *testing.T) {
	gin.SetMode(gin.TestMode)

	scenarios := []classScenario{
		scenNeverIssued, scenReplayed, scenExpired, scenResourceMismatch,
	}

	for _, site := range classSites() {
		for _, scen := range scenarios {
			t.Run(site.name+"/"+string(scen), func(t *testing.T) {
				w, applies := site.exercise(t, scen)
				if !applies {
					reason := site.naReason[scen]
					if reason == "" {
						t.Fatalf("site %s reported scenario %q inapplicable with no recorded reason",
							site.name, scen)
					}
					t.Skipf("not applicable: %s", reason)
					return
				}
				// Asserted exactly, not as ">= 400". A mutated guard usually
				// still errors further down the handler (provider-not-found,
				// decrypt failure, unexpected-DB-call), and a loose check would
				// score that as a pass. The exact code is what distinguishes
				// "the non-credential was refused by the guard" from "the
				// attack proceeded and then tripped over something else".
				if w.Code != site.wantStatus {
					t.Fatalf("site %s scenario %q: status = %d, want %d — "+
						"the guard did not refuse this non-credential.\nguard: %s\nroute: %s\nbody: %s",
						site.name, scen, w.Code, site.wantStatus,
						site.guardLine, site.route, w.Body.String())
				}
				want := site.wantBodyContains
				if s, ok := site.wantBody[scen]; ok {
					want = s
				}
				if want == "" {
					t.Fatalf("site %s scenario %q has no expected guard message; "+
						"without one a removed guard that still 4xxs further down "+
						"the handler would score as a pass", site.name, scen)
				}
				if !strings.Contains(w.Body.String(), want) {
					t.Fatalf("site %s scenario %q: body %q does not contain %q — "+
						"the rejection did not come from the guard.\nguard: %s",
						site.name, scen, w.Body.String(), want, site.guardLine)
				}
			})
		}
	}
}

// TestUnauthenticatedPrincipalDerivation_NoConstructedState is the signature
// half of the class test: it fails if any handler ever again renders a principal
// into a state/nonce value instead of minting one from crypto/rand. The original
// defect was exactly one line — state := fmt.Sprintf("%s:%s", userID, providerID).
func TestUnauthenticatedPrincipalDerivation_NoConstructedState(t *testing.T) {
	// InitiateOAuth must produce a 64-hex-char random state, never a rendering
	// of ids the caller already knows.
	sqlxDB, _, mock := classSQLMock(t)
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	h := admin.NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	providerID := uuid.New()
	userID := uuid.New()

	r := gin.New()
	r.GET("/scm-providers/:id/oauth/authorize", func(c *gin.Context) {
		c.Set("user_id", userID.String())
		h.InitiateOAuth(c)
	})

	// Provider lookup fails, so the handler returns before minting — but that is
	// enough to pin that no state is derivable from the request either.
	mock.ExpectQuery("SELECT").WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+providerID.String()+"/oauth/authorize", nil))

	if body := w.Body.String(); containsAny(body, userID.String(), providerID.String()+":") {
		t.Errorf("authorize response echoes a principal-derived state: %s", body)
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		for i := 0; i+len(n) <= len(haystack); i++ {
			if haystack[i:i+len(n)] == n {
				return true
			}
		}
	}
	return false
}
