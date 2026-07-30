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

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

const (
	mirrorCfgID   = "66666666-6666-6666-6666-666666666666"
	approvalReqID = "77777777-7777-7777-7777-777777777777"
	foreignOrgID  = "88888888-8888-8888-8888-888888888888"
	mirrorUserID  = "user-mirror-cross-org"
)

var memberRoleColsAPI = []string{
	"organization_id", "user_id", "role_template_id", "joined_at",
	"name", "email", "role_name", "role_display_name", "role_scopes",
}

func userRowsFor(userID string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
		AddRow(userID, "mallory@example.com", "Mallory", nil, time.Now(), time.Now())
}

// crossOrgRouteCase drives one route through the real registerAPIV1Routes with
// the target row owned by foreignOrgID and the caller not a member of it.
// Handlers are left nil deliberately: a guarded route rejects in middleware and
// never reaches one, so gin.Recovery turning the unguarded case into a 500
// makes the failure legible rather than crashing the binary.
func crossOrgRouteCase(t *testing.T, method, path string, scopes []string, seed func(sqlmock.Sqlmock)) int {
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
	seed(mock)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(memberRoleColsAPI))

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
		mirrorRepo: repositories.NewMirrorRepository(sqlxDB),
		rbacRepo:   repositories.NewRBACRepositoryWithIdentity(sqlxDB, sqlxDB),
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	return w.Code
}

func seedForeignMirrorConfig(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "description", "upstream_registry_url", "organization_id",
			"namespace_filter", "provider_filter", "version_filter", "platform_filter",
			"enabled", "sync_interval_hours", "requires_approval", "auto_approve_rules",
			"pull_through_enabled", "pull_through_cache_ttl_hours", "last_sync_at",
			"last_sync_status", "last_sync_error", "created_at", "updated_at", "created_by",
		}).AddRow(
			mirrorCfgID, "upstream", nil, "https://registry.terraform.io", foreignOrgID,
			nil, nil, nil, nil, true, 24, false, nil, false, 24, nil, nil, nil,
			time.Now(), time.Now(), nil,
		))
}

func seedForeignApprovalRequest(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("FROM mirror_approval_requests").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "mirror_config_id", "organization_id", "requested_by",
			"provider_namespace", "provider_name", "reason", "status",
			"reviewed_by", "reviewed_at", "review_notes", "auto_approved",
			"created_at", "updated_at", "expires_at",
		}).AddRow(
			approvalReqID, mirrorCfgID, foreignOrgID, nil,
			"hashicorp", "aws", "needed upstream", "pending", nil, nil, nil, false,
			time.Now(), time.Now(), nil,
		))
}

// Issue #719: /admin/mirrors/:id operates on org-scoped mirror_configurations
// rows but was authorized only against the flat org-less scope union.
func TestMirrorConfigRoutes_CrossOrg_Denied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	scopes := []string{string(auth.ScopeMirrorsRead), string(auth.ScopeMirrorsManage)}
	for _, tc := range []struct{ name, method, path string }{
		{"read config", http.MethodGet, "/api/v1/admin/mirrors/" + mirrorCfgID},
		{"read status", http.MethodGet, "/api/v1/admin/mirrors/" + mirrorCfgID + "/status"},
		{"list mirrored providers", http.MethodGet, "/api/v1/admin/mirrors/" + mirrorCfgID + "/providers"},
		{"delete config", http.MethodDelete, "/api/v1/admin/mirrors/" + mirrorCfgID},
		{"trigger sync", http.MethodPost, "/api/v1/admin/mirrors/" + mirrorCfgID + "/sync"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := crossOrgRouteCase(t, tc.method, tc.path, scopes, seedForeignMirrorConfig); code != http.StatusForbidden {
				t.Errorf("%s %s: status = %d, want 403 (mirror config owned by another organization)",
					tc.method, tc.path, code)
			}
		})
	}
}

// Issue #719: POST /admin/approvals/:id/token mints a single-use token whose
// redemption endpoint is unauthenticated, so minting one for another
// organization's request hands over a working credential.
func TestApprovalRoutes_CrossOrg_Denied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	scopes := []string{string(auth.ScopeMirrorsRead), string(auth.ScopeMirrorsManage)}
	for _, tc := range []struct{ name, method, path string }{
		{"read approval", http.MethodGet, "/api/v1/admin/approvals/" + approvalReqID},
		{"mint approval token", http.MethodPost, "/api/v1/admin/approvals/" + approvalReqID + "/token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := crossOrgRouteCase(t, tc.method, tc.path, scopes, seedForeignApprovalRequest); code != http.StatusForbidden {
				t.Errorf("%s %s: status = %d, want 403 (approval request belongs to another organization)",
					tc.method, tc.path, code)
			}
		})
	}
}
