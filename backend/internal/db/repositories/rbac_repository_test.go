package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var roleTemplateCols = []string{
	"id", "name", "display_name", "description", "scopes", "is_system", "created_at", "updated_at",
}

var approvalReqCols = []string{
	"id", "mirror_config_id", "organization_id", "requested_by",
	"provider_namespace", "provider_name", "reason", "status",
	"reviewed_by", "reviewed_at", "review_notes", "auto_approved",
	"created_at", "updated_at", "expires_at",
}

var approvalReqListCols = []string{
	"id", "mirror_config_id", "organization_id", "requested_by",
	"provider_namespace", "provider_name", "reason", "status",
	"reviewed_by", "reviewed_at", "review_notes", "auto_approved",
	"created_at", "updated_at", "expires_at",
	"requested_by_name", "reviewed_by_name", "mirror_name",
}

var mirrorPolicyCols = []string{
	"id", "organization_id", "name", "description",
	"policy_type", "upstream_registry", "namespace_pattern", "provider_pattern",
	"priority", "is_active", "requires_approval",
	"created_at", "updated_at", "created_by",
}

var mirrorPolicyListCols = []string{
	"id", "organization_id", "name", "description",
	"policy_type", "upstream_registry", "namespace_pattern", "provider_pattern",
	"priority", "is_active", "requires_approval",
	"created_at", "updated_at", "created_by",
	"organization_name", "created_by_name",
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var sampleScopes2 = []byte(`["modules:read","providers:write"]`)

func newRBACRepo(t *testing.T) (*RBACRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRBACRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func sampleRoleTemplateRow() *sqlmock.Rows {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	return sqlmock.NewRows(roleTemplateCols).
		AddRow(id, "admin", "Admin", nil, sampleScopes2, false, time.Now(), time.Now())
}

func sampleApprovalRow() *sqlmock.Rows {
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	cfgID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	return sqlmock.NewRows(approvalReqCols).
		AddRow(id, cfgID, nil, nil, "hashicorp", nil, "need it", "pending",
			nil, nil, nil, false, time.Now(), time.Now(), nil)
}

func sampleApprovalListRow() *sqlmock.Rows {
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	cfgID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	return sqlmock.NewRows(approvalReqListCols).
		AddRow(id, cfgID, nil, nil, "hashicorp", nil, "need it", "pending",
			nil, nil, nil, false, time.Now(), time.Now(), nil,
			"Alice", "", "my-mirror")
}

func samplePolicyRow() *sqlmock.Rows {
	id := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	return sqlmock.NewRows(mirrorPolicyCols).
		AddRow(id, nil, "allow-all", nil, "allow", nil, nil, nil,
			10, true, false, time.Now(), time.Now(), nil)
}

func samplePolicyListRow() *sqlmock.Rows {
	id := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	return sqlmock.NewRows(mirrorPolicyListCols).
		AddRow(id, nil, "allow-all", nil, "allow", nil, nil, nil,
			10, true, false, time.Now(), time.Now(), nil,
			"Global", "")
}

// ---------------------------------------------------------------------------
// ListRoleTemplates
// ---------------------------------------------------------------------------

func TestListRoleTemplates_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates").
		WillReturnRows(sampleRoleTemplateRow())

	templates, err := repo.ListRoleTemplates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 1 {
		t.Errorf("len = %d, want 1", len(templates))
	}
}

func TestListRoleTemplates_Empty(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates").
		WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	templates, err := repo.ListRoleTemplates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 0 {
		t.Errorf("len = %d, want 0", len(templates))
	}
}

func TestListRoleTemplates_Error(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates").
		WillReturnError(errDB)

	_, err := repo.ListRoleTemplates(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetRoleTemplate
// ---------------------------------------------------------------------------

func TestGetRoleTemplate_Found(t *testing.T) {
	repo, mock := newRBACRepo(t)
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").
		WillReturnRows(sampleRoleTemplateRow())

	tpl, err := repo.GetRoleTemplate(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tpl == nil {
		t.Fatal("expected template, got nil")
	}
}

func TestGetRoleTemplate_NotFound(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").
		WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	tpl, err := repo.GetRoleTemplate(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tpl != nil {
		t.Errorf("expected nil, got %v", tpl)
	}
}

func TestGetRoleTemplate_Error(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").
		WillReturnError(errDB)

	_, err := repo.GetRoleTemplate(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetRoleTemplateByName
// ---------------------------------------------------------------------------

func TestGetRoleTemplateByName_Found(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE name").
		WillReturnRows(sampleRoleTemplateRow())

	tpl, err := repo.GetRoleTemplateByName(context.Background(), "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tpl == nil {
		t.Fatal("expected template, got nil")
	}
}

func TestGetRoleTemplateByName_NotFound(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE name").
		WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	tpl, err := repo.GetRoleTemplateByName(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tpl != nil {
		t.Errorf("expected nil, got %v", tpl)
	}
}

// ---------------------------------------------------------------------------
// CreateRoleTemplate
// ---------------------------------------------------------------------------

func TestCreateRoleTemplate_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tpl := &models.RoleTemplate{
		ID:          uuid.New(),
		Name:        "custom",
		DisplayName: "Custom Role",
		Scopes:      []string{"modules:read"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := repo.CreateRoleTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateRoleTemplate_Error(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnError(errDB)

	tpl := &models.RoleTemplate{ID: uuid.New(), Name: "x", Scopes: []string{}}
	if err := repo.CreateRoleTemplate(context.Background(), tpl); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateRoleTemplate
// ---------------------------------------------------------------------------

func TestUpdateRoleTemplate_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("UPDATE role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tpl := &models.RoleTemplate{
		ID:          uuid.New(),
		DisplayName: "Updated",
		Scopes:      []string{"providers:read"},
	}
	if err := repo.UpdateRoleTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteRoleTemplate
// ---------------------------------------------------------------------------

func TestDeleteRoleTemplate_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("DELETE FROM role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteRoleTemplate(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CreateApprovalRequest
// ---------------------------------------------------------------------------

func TestCreateApprovalRequest_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := &models.MirrorApprovalRequest{
		ID:                uuid.New(),
		MirrorConfigID:    uuid.New(),
		ProviderNamespace: "hashicorp",
		Reason:            "testing",
		Status:            models.ApprovalStatusPending,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	if err := repo.CreateApprovalRequest(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetApprovalRequest
// ---------------------------------------------------------------------------

func TestGetApprovalRequest_Found(t *testing.T) {
	repo, mock := newRBACRepo(t)
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	mock.ExpectQuery("SELECT id.*FROM mirror_approval_requests.*WHERE id").
		WillReturnRows(sampleApprovalRow())

	req, err := repo.GetApprovalRequest(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("expected request, got nil")
	}
}

func TestGetApprovalRequest_NotFound(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_approval_requests.*WHERE id").
		WillReturnRows(sqlmock.NewRows(approvalReqCols))

	req, err := repo.GetApprovalRequest(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req != nil {
		t.Errorf("expected nil, got %v", req)
	}
}

// ---------------------------------------------------------------------------
// ListApprovalRequests
// ---------------------------------------------------------------------------

func TestListApprovalRequests_NoFilter(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT mar.id.*FROM mirror_approval_requests").
		WillReturnRows(sampleApprovalListRow())

	reqs, err := repo.ListApprovalRequests(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reqs) != 1 {
		t.Errorf("len = %d, want 1", len(reqs))
	}
}

func TestListApprovalRequests_Error(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT mar.id.*FROM mirror_approval_requests").
		WillReturnError(errDB)

	_, err := repo.ListApprovalRequests(context.Background(), nil, nil)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateApprovalStatus
// ---------------------------------------------------------------------------

func TestUpdateApprovalStatus_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("UPDATE mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateApprovalStatus(context.Background(),
		uuid.New(), models.ApprovalStatusApproved, uuid.New(), "looks good"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CheckApproval
// ---------------------------------------------------------------------------

func TestCheckApproval_Found(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_approval_requests.*WHERE mirror_config_id").
		WillReturnRows(sampleApprovalRow())

	req, err := repo.CheckApproval(context.Background(), uuid.New(), "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("expected request, got nil")
	}
}

func TestCheckApproval_NotFound(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_approval_requests.*WHERE mirror_config_id").
		WillReturnRows(sqlmock.NewRows(approvalReqCols))

	req, err := repo.CheckApproval(context.Background(), uuid.New(), "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req != nil {
		t.Errorf("expected nil, got %v", req)
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorPolicy
// ---------------------------------------------------------------------------

func TestCreateMirrorPolicy_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	policy := &models.MirrorPolicy{
		ID:         uuid.New(),
		Name:       "allow-all",
		PolicyType: models.PolicyTypeAllow,
		Priority:   10,
		IsActive:   true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := repo.CreateMirrorPolicy(context.Background(), policy); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetMirrorPolicy
// ---------------------------------------------------------------------------

func TestGetMirrorPolicy_Found(t *testing.T) {
	repo, mock := newRBACRepo(t)
	id := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	mock.ExpectQuery("SELECT id.*FROM mirror_policies.*WHERE id").
		WillReturnRows(samplePolicyRow())

	policy, err := repo.GetMirrorPolicy(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected policy, got nil")
	}
}

func TestGetMirrorPolicy_NotFound(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_policies.*WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorPolicyCols))

	policy, err := repo.GetMirrorPolicy(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy != nil {
		t.Errorf("expected nil, got %v", policy)
	}
}

// ---------------------------------------------------------------------------
// ListMirrorPolicies
// ---------------------------------------------------------------------------

func TestListMirrorPolicies_GlobalOnly(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT mp.id.*FROM mirror_policies").
		WillReturnRows(samplePolicyListRow())

	policies, err := repo.ListMirrorPolicies(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("len = %d, want 1", len(policies))
	}
}

func TestListMirrorPolicies_WithOrg(t *testing.T) {
	repo, mock := newRBACRepo(t)
	orgID := uuid.New()
	mock.ExpectQuery("SELECT mp.id.*FROM mirror_policies").
		WillReturnRows(sqlmock.NewRows(mirrorPolicyListCols))

	policies, err := repo.ListMirrorPolicies(context.Background(), &orgID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("len = %d, want 0", len(policies))
	}
}

// ---------------------------------------------------------------------------
// UpdateMirrorPolicy
// ---------------------------------------------------------------------------

func TestUpdateMirrorPolicy_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("UPDATE mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	policy := &models.MirrorPolicy{
		ID:         uuid.New(),
		Name:       "updated",
		PolicyType: models.PolicyTypeDeny,
		Priority:   5,
	}
	if err := repo.UpdateMirrorPolicy(context.Background(), policy); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteMirrorPolicy
// ---------------------------------------------------------------------------

func TestDeleteMirrorPolicy_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectExec("DELETE FROM mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteMirrorPolicy(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicies
// ---------------------------------------------------------------------------

func TestEvaluatePolicies_NoMatchingPolicies(t *testing.T) {
	repo, mock := newRBACRepo(t)
	// EvaluatePolicies calls ListMirrorPolicies internally
	mock.ExpectQuery("SELECT mp.id.*FROM mirror_policies").
		WillReturnRows(sqlmock.NewRows(mirrorPolicyListCols))

	result, err := repo.EvaluatePolicies(context.Background(), nil, "registry.terraform.io", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Allowed {
		t.Error("expected not allowed when no policies match")
	}
}

func TestEvaluatePolicies_AllowPolicy(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT mp.id.*FROM mirror_policies").
		WillReturnRows(samplePolicyListRow()) // allow-all policy with wildcards

	result, err := repo.EvaluatePolicies(context.Background(), nil, "registry.terraform.io", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	// Policy has nil patterns so it matches anything
	if !result.Allowed {
		t.Error("expected allowed by allow policy")
	}
}

// ---------------------------------------------------------------------------
// ListPendingApprovals (alias for ListApprovalRequests with pending status)
// ---------------------------------------------------------------------------

func TestListPendingApprovals_Success(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests").
		WillReturnRows(sampleApprovalListRow())

	requests, err := repo.ListPendingApprovals(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requests) == 0 {
		t.Error("expected at least one request")
	}
}

func TestListPendingApprovals_DBError(t *testing.T) {
	repo, mock := newRBACRepo(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests").
		WillReturnError(errDB)

	_, err := repo.ListPendingApprovals(context.Background(), nil)
	if err == nil {
		t.Error("expected error")
	}
}
