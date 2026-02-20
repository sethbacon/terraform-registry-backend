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

var orgMWErrDB = errors.New("db error")

const orgMWUserID = "user-111"
const orgMWOrgID = "org-222"

// memberCols is for GetMember (4 cols)
var memberCols = []string{"organization_id", "user_id", "role_template_id", "created_at"}

// memberRoleColsMW is for GetMemberWithRole (9 cols) - used in RequireOrgScope
var memberRoleColsMW = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email", "role_template_name", "role_template_display_name", "role_template_scopes",
}

// ---------------------------------------------------------------------------
// Helper: build a gin router that injects context values then runs middleware
// ---------------------------------------------------------------------------

func orgRouter(mid gin.HandlerFunc, userID, orgID string) *gin.Engine {
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		if userID != "" {
			c.Set("user_id", userID)
		}
		if orgID != "" {
			c.Set("organization_id", orgID)
		}
	}, mid, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func doGet(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	return w
}

// ---------------------------------------------------------------------------
// RequireOrgMembership tests
// ---------------------------------------------------------------------------

func TestRequireOrgMembership_NoUserID(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgMembership(orgRepo)

	// No user_id in context
	w := doGet(orgRouter(mid, "", orgMWOrgID))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgMembership_NoOrgID(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgMembership(orgRepo)

	// No organization_id in context
	w := doGet(orgRouter(mid, orgMWUserID, ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgMembership_DBError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgMembership(orgRepo)

	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnError(orgMWErrDB)

	w := doGet(orgRouter(mid, orgMWUserID, orgMWOrgID))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestRequireOrgMembership_NotMember(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgMembership(orgRepo)

	// GetMember returns no rows → member is nil → 403
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(memberCols))

	w := doGet(orgRouter(mid, orgMWUserID, orgMWOrgID))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgMembership_IsMember(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgMembership(orgRepo)

	// GetMember returns a row → member found → allow
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(memberCols).
			AddRow(orgMWOrgID, orgMWUserID, "role-1", time.Now()))

	w := doGet(orgRouter(mid, orgMWUserID, orgMWOrgID))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RequireOrgScope tests
// ---------------------------------------------------------------------------

func TestRequireOrgScope_NoUserID(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScope(auth.ScopeAdmin, orgRepo)

	w := doGet(orgRouter(mid, "", orgMWOrgID))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgScope_NoOrgID(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScope(auth.ScopeAdmin, orgRepo)

	w := doGet(orgRouter(mid, orgMWUserID, ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgScope_DBError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScope(auth.ScopeAdmin, orgRepo)

	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnError(orgMWErrDB)

	w := doGet(orgRouter(mid, orgMWUserID, orgMWOrgID))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestRequireOrgScope_NotMember(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScope(auth.ScopeAdmin, orgRepo)

	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW))

	w := doGet(orgRouter(mid, orgMWUserID, orgMWOrgID))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgScope_InsufficientScope(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScope(auth.ScopeAdmin, orgRepo)

	// Member found but scope is "modules:read" which doesn't include "admin"
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			orgMWOrgID, orgMWUserID, "role-1", time.Now(),
			"User Name", "user@test.com", "member", "Member", []byte(`["modules:read"]`),
		))

	w := doGet(orgRouter(mid, orgMWUserID, orgMWOrgID))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgScope_HasScope(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScope(auth.ScopeAdmin, orgRepo)

	// Member found with admin scope
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			orgMWOrgID, orgMWUserID, "role-1", time.Now(),
			"User Name", "user@test.com", "admin", "Admin", []byte(`["admin"]`),
		))

	w := doGet(orgRouter(mid, orgMWUserID, orgMWOrgID))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}
