package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// tfMirrorCfgID is an arbitrary well-formed UUID: the routes under test must
// decide on the caller's authority before the row is ever looked up, so no
// mirror config needs to exist for the gate to be observable.
const tfMirrorCfgID = "5b0f2c9a-6d3e-4a1b-9c8d-2e7f4a6b1c30"

// platformRouteCase drives one route through the real registerAPIV1Routes
// wiring with a principal holding exactly scopes, and returns the status code.
//
// Handlers are left nil deliberately, the same way crossOrgRouteCase does it:
// a route whose gate rejects the caller aborts in middleware and never reaches
// one, so a caller who IS authorized falls through to a nil handler and
// gin.Recovery turns that into a 500 (or the handler's own 400 when it binds
// JSON before touching its repository). Either way the pass/fail signal is
// "403 or not", which is exactly the authority decision under test.
func platformRouteCase(t *testing.T, method, path string, scopes []string) int {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	token, err := auth.GenerateJWT(mirrorUserID, "mallory@example.com", scopes, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	mock.ExpectQuery("(?s)FROM users WHERE id").WillReturnRows(userRowsFor(mirrorUserID))

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerMinute: 600, BurstSize: 100, CleanupInterval: time.Minute,
	})
	defer limiter.Stop()

	r := gin.New()
	r.Use(gin.Recovery())
	registerAPIV1Routes(r, &apiV1RouteDeps{
		cfg:                &config.Config{},
		userRepo:           repositories.NewUserRepository(db),
		generalRateLimiter: limiter,
		orgRateLimiter:     limiter,
		nsAuthz: middleware.NewNamespaceAuthorizer(
			repositories.NewOrganizationRepository(db),
			repositories.NewNamespaceClaimRepository(db),
			repositories.NewModuleRepository(db),
			repositories.NewProviderRepository(db),
		),
		mirrorRepo:       repositories.NewMirrorRepository(sqlxDB),
		rbacRepo:         repositories.NewRBACRepositoryWithIdentity(sqlxDB, sqlxDB),
		auditLogHandlers: admin.NewAuditLogHandlers(db),
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	return w.Code
}

// platformMirrorRoute is one row of the /admin/terraform-mirrors route table.
type platformMirrorRoute struct {
	name    string
	method  string
	path    string
	mutates bool
}

// platformMirrorRoutes is the complete /admin/terraform-mirrors family. Every
// table it reaches — terraform_mirror_configs, terraform_versions,
// terraform_version_platforms, terraform_sync_history, releases_gpg_keys — is
// platform-global: none of them has an organization_id column, so no per-org
// guard can apply and the authority has to come from the scope itself.
var platformMirrorRoutes = []platformMirrorRoute{
	// Mutations: repointing the upstream, lowering gpg_verify /
	// verify_github_attestation / requires_approval, triggering a sync, and
	// deleting or deprecating configs and versions all change what binaries
	// EVERY tenant receives from /terraform/binaries (issue #734).
	{"create config", http.MethodPost, "/api/v1/admin/terraform-mirrors", true},
	{"update config", http.MethodPut, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID, true},
	{"delete config", http.MethodDelete, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID, true},
	{"trigger sync", http.MethodPost, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/sync", true},
	{"delete version", http.MethodDelete, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/versions/1.9.5", true},
	{"deprecate version", http.MethodPost, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/versions/1.9.5/deprecate", true},
	{"undeprecate version", http.MethodDelete, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/versions/1.9.5/deprecate", true},

	// Reads: deliberately left on mirrors:read. These tables hold no tenant
	// data and no credentials, and the binary mirror is a shared service whose
	// catalogue and health tenant operators legitimately need to see.
	{"releases gpg keys", http.MethodGet, "/api/v1/admin/terraform-mirrors/releases-gpg-keys", false},
	{"list configs", http.MethodGet, "/api/v1/admin/terraform-mirrors", false},
	{"get config", http.MethodGet, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID, false},
	{"get status", http.MethodGet, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/status", false},
	{"list versions", http.MethodGet, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/versions", false},
	{"get version", http.MethodGet, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/versions/1.9.5", false},
	{"list platforms", http.MethodGet, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/versions/1.9.5/platforms", false},
	{"sync history", http.MethodGet, "/api/v1/admin/terraform-mirrors/" + tfMirrorCfgID + "/history", false},
}

// Issue #734: terraform_mirror_configs has no organization_id column — one
// config is the Terraform/OpenTofu binary supply chain for every tenant — yet
// the whole family was gated on mirrors:manage, which the seeded devops and
// org_owner role templates grant through membership in a SINGLE organization.
//
// The table runs each route against three principal classes so a regression
// that denies EVERYONE is as visible as one that allows everyone: the org-level
// principals must be refused on the mutations, and the platform admin must
// still get through.
func TestPlatformTerraformMirrorRoutes_Authority(t *testing.T) {
	gin.SetMode(gin.TestMode)
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	principals := []struct {
		name   string
		scopes []string
		// allowedOnMutations is the authority claim under test.
		allowedOnMutations bool
		// allowedOnReads records the deliberate read/write split.
		allowedOnReads bool
	}{
		{
			// The seeded "devops" / "org_owner" principal: mirrors:manage (which
			// implies mirrors:read) held via membership in one organization.
			name:               "org user with mirrors:manage",
			scopes:             []string{string(auth.ScopeMirrorsRead), string(auth.ScopeMirrorsManage)},
			allowedOnMutations: false,
			allowedOnReads:     true,
		},
		{
			// The seeded "viewer" principal: no mirror management at all.
			name:               "org user without mirrors:manage",
			scopes:             []string{string(auth.ScopeModulesRead), string(auth.ScopeProvidersRead)},
			allowedOnMutations: false,
			allowedOnReads:     false,
		},
		{
			name:               "platform admin",
			scopes:             []string{string(auth.ScopeAdmin)},
			allowedOnMutations: true,
			allowedOnReads:     true,
		},
	}

	for _, p := range principals {
		for _, rt := range platformMirrorRoutes {
			wantAllowed := p.allowedOnReads
			if rt.mutates {
				wantAllowed = p.allowedOnMutations
			}

			t.Run(p.name+"/"+rt.name, func(t *testing.T) {
				code := platformRouteCase(t, rt.method, rt.path, p.scopes)

				if code == http.StatusNotFound {
					t.Fatalf("%s %s: 404 — route not registered, the table is stale", rt.method, rt.path)
				}

				gotAllowed := code != http.StatusForbidden
				if gotAllowed != wantAllowed {
					verb := "allowed"
					if !wantAllowed {
						verb = "denied"
					}
					t.Errorf("%s %s as %s: status = %d, want %s (mutates=%t; terraform mirror config is platform-global, issue #734)",
						rt.method, rt.path, p.name, code, verb, rt.mutates)
				}
			})
		}
	}
}
