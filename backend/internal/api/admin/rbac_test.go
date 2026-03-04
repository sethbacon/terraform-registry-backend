package admin

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var rtCols = []string{
	"id", "name", "display_name", "description", "scopes", "is_system", "created_at", "updated_at",
}

var approvalCols = []string{
	"id", "mirror_config_id", "organization_id", "requested_by",
	"provider_namespace", "provider_name", "reason", "status",
	"reviewed_by", "reviewed_at", "review_notes", "auto_approved",
	"created_at", "updated_at", "expires_at",
}

var approvalListCols = []string{
	"id", "mirror_config_id", "organization_id", "requested_by",
	"provider_namespace", "provider_name", "reason", "status",
	"reviewed_by", "reviewed_at", "review_notes", "auto_approved",
	"created_at", "updated_at", "expires_at",
	"requested_by_name", "reviewed_by_name", "mirror_name",
}

var mpCols = []string{
	"id", "organization_id", "name", "description", "policy_type",
	"upstream_registry", "namespace_pattern", "provider_pattern",
	"priority", "is_active", "requires_approval", "created_at", "updated_at", "created_by",
}

var mpListCols = []string{
	"id", "organization_id", "name", "description", "policy_type",
	"upstream_registry", "namespace_pattern", "provider_pattern",
	"priority", "is_active", "requires_approval", "created_at", "updated_at", "created_by",
	"organization_name", "created_by_name",
}

var testRTScopes = []byte(`["modules:read","providers:write"]`)

// knownUUID is a constant valid UUID for use in test paths.
const knownUUID = "11111111-1111-1111-1111-111111111111"
const knownUserUUID = "22222222-2222-2222-2222-222222222222"

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleRTRow() *sqlmock.Rows {
	return sqlmock.NewRows(rtCols).
		AddRow(knownUUID, "reader", "Reader", nil, testRTScopes, false, time.Now(), time.Now())
}

func sampleRTSystemRow() *sqlmock.Rows {
	return sqlmock.NewRows(rtCols).
		AddRow(knownUUID, "admin", "Admin", nil, testRTScopes, true, time.Now(), time.Now())
}

func emptyRTRows() *sqlmock.Rows {
	return sqlmock.NewRows(rtCols)
}

func sampleApprovalRow() *sqlmock.Rows {
	return sqlmock.NewRows(approvalCols).
		AddRow(
			knownUUID, knownUUID, nil, nil,
			"hashicorp", nil, "need it", "pending",
			nil, nil, nil, false,
			time.Now(), time.Now(), nil,
		)
}

func emptyApprovalRows() *sqlmock.Rows {
	return sqlmock.NewRows(approvalCols)
}

func emptyApprovalListRows() *sqlmock.Rows {
	return sqlmock.NewRows(approvalListCols)
}

func emptyMPListRows() *sqlmock.Rows {
	return sqlmock.NewRows(mpListCols)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newRBACRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	rbacRepo := repositories.NewRBACRepository(sqlxDB)
	h := NewRBACHandlers(rbacRepo)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", knownUserUUID)
		c.Next()
	})

	r.GET("/role-templates", h.ListRoleTemplates)
	r.GET("/role-templates/:id", h.GetRoleTemplate)
	r.POST("/role-templates", h.CreateRoleTemplate)
	r.PUT("/role-templates/:id", h.UpdateRoleTemplate)
	r.DELETE("/role-templates/:id", h.DeleteRoleTemplate)

	r.GET("/approvals", h.ListApprovalRequests)
	r.GET("/approvals/:id", h.GetApprovalRequest)
	r.POST("/approvals", h.CreateApprovalRequest)
	r.PUT("/approvals/:id/review", h.ReviewApproval)

	r.GET("/policies", h.ListMirrorPolicies)
	r.GET("/policies/:id", h.GetMirrorPolicy)
	r.POST("/policies", h.CreateMirrorPolicy)
	r.PUT("/policies/:id", h.UpdateMirrorPolicy)
	r.DELETE("/policies/:id", h.DeleteMirrorPolicy)
	r.POST("/policies/evaluate", h.EvaluatePolicy)

	return mock, r
}

// ---------------------------------------------------------------------------
// ListRoleTemplates
// ---------------------------------------------------------------------------

func TestRBACListRoleTemplates_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates.*ORDER BY").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACListRoleTemplates_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACGetRoleTemplate_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACGetRoleTemplate_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(emptyRTRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRBACGetRoleTemplate_Found(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACCreateRoleTemplate_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACCreateRoleTemplate_Conflict(t *testing.T) {
	mock, r := newRBACRouter(t)
	// GetRoleTemplateByName finds existing
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE name").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateRoleTemplate_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE name").
		WillReturnRows(emptyRTRows())
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{
			"name":         "new-role",
			"display_name": "New Role",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACUpdateRoleTemplate_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(emptyRTRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRBACUpdateRoleTemplate_SystemTemplate(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(sampleRTSystemRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "admin",
			"display_name": "Admin",
			"scopes":       []string{"admin"},
		})))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateRoleTemplate_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACDeleteRoleTemplate_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(emptyRTRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRBACDeleteRoleTemplate_SystemTemplate(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(sampleRTSystemRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACDeleteRoleTemplate_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("DELETE FROM role_templates WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListApprovalRequests
// ---------------------------------------------------------------------------

func TestRBACListApprovals_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests.*WHERE 1").
		WillReturnRows(emptyApprovalListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACListApprovals_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals?organization_id=not-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetApprovalRequest
// ---------------------------------------------------------------------------

func TestRBACGetApproval_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACGetApproval_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnRows(emptyApprovalRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateApprovalRequest
// ---------------------------------------------------------------------------

func TestRBACCreateApproval_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACCreateApproval_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
			"reason":             "need it",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ReviewApproval
// ---------------------------------------------------------------------------

func TestRBACReviewApproval_InvalidStatus(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "invalid-status"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACReviewApproval_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnRows(sampleApprovalRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "approved", "notes": "looks good"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListMirrorPolicies
// ---------------------------------------------------------------------------

func TestRBACListMirrorPolicies_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(emptyMPListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACListMirrorPolicies_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies?organization_id=not-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACGetMirrorPolicy_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sqlmock.NewRows(mpCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACCreateMirrorPolicy_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACCreateMirrorPolicy_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "allow-all",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACUpdateMirrorPolicy_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sqlmock.NewRows(mpCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":        "updated",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACDeleteMirrorPolicy_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/policies/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACDeleteMirrorPolicy_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("DELETE FROM mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicy
// ---------------------------------------------------------------------------

func TestRBACEvaluatePolicy_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACEvaluatePolicy_NoPolicies(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(emptyMPListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["allowed"] != false {
		t.Errorf("expected allowed=false when no policies, got %v", resp["allowed"])
	}
}

// unused import guard
var _ = sql.ErrNoRows

// ---------------------------------------------------------------------------
// UpdateMirrorPolicy — additional paths
// ---------------------------------------------------------------------------

func sampleMPRow() *sqlmock.Rows {
	return sqlmock.NewRows(mpCols).AddRow(
		knownUUID, nil, "allow-all", nil, "allow",
		nil, nil, nil,
		10, true, false, time.Now(), time.Now(), nil,
	)
}

func TestRBACUpdateMirrorPolicy_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/not-a-uuid",
		jsonBody(map[string]interface{}{"name": "x", "policy_type": "allow"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACUpdateMirrorPolicy_GetDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "x", "policy_type": "allow"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateMirrorPolicy_InvalidPolicyType(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "x", "policy_type": "invalid"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateMirrorPolicy_UpdateDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())
	mock.ExpectExec("UPDATE mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "updated", "policy_type": "deny"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateMirrorPolicy_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())
	mock.ExpectExec("UPDATE mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "updated", "policy_type": "allow"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicy — additional branches
// ---------------------------------------------------------------------------

func TestRBACEvaluatePolicy_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate?organization_id=not-a-uuid",
		jsonBody(map[string]interface{}{"registry": "registry.terraform.io", "namespace": "hashicorp", "provider": "aws"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACEvaluatePolicy_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{"registry": "registry.terraform.io", "namespace": "hashicorp", "provider": "aws"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetMirrorPolicy — additional branches
// ---------------------------------------------------------------------------

func TestRBACGetMirrorPolicy_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorPolicy — additional branches
// ---------------------------------------------------------------------------

func TestRBACCreateMirrorPolicy_InvalidPolicyType(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "bad-type",
			"policy_type": "invalid",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateMirrorPolicy_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":            "test",
			"policy_type":     "allow",
			"organization_id": "not-a-uuid",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateMirrorPolicy_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "test",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListMirrorPolicies — additional branches
// ---------------------------------------------------------------------------

func TestRBACListMirrorPolicies_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteRoleTemplate — additional branches
// ---------------------------------------------------------------------------

func TestRBACDeleteRoleTemplate_GetDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACDeleteRoleTemplate_DeleteDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("DELETE FROM role_templates WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListApprovalRequests — additional branches
// ---------------------------------------------------------------------------

func TestRBACListApprovals_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateApprovalRequest — additional branches
// ---------------------------------------------------------------------------

func TestRBACCreateApproval_InvalidMirrorConfigID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   "not-a-uuid",
			"provider_namespace": "hashicorp",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateApproval_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ReviewApproval — additional branches
// ---------------------------------------------------------------------------

func TestRBACReviewApproval_UpdateDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "approved", "notes": "ok"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACReviewApproval_GetDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "rejected", "notes": "no"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}
