package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

func newVersionApprovalRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	repo := repositories.NewVersionApprovalRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewVersionApprovalHandler(repo)

	r := gin.New()
	g := r.Group("/admin/version-approvals")
	g.GET("", h.List)
	g.GET("/pending-count", h.PendingCount)
	g.GET("/:id/events", h.Events)
	g.PUT("/:id/approve", h.Approve)
	g.PUT("/:id/reject", h.Reject)
	g.POST("/bulk-approve", h.BulkApprove)
	g.POST("/bulk-reject", h.BulkReject)
	return r, mock
}

var vaCols = []string{
	"id", "type", "version", "approval_status",
	"provider_namespace", "provider_name",
	"mirror_config_name", "mirror_config_id",
	"gpg_verified", "shasum_verified", "synced_at",
}

func TestVAHandler_List(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT \* FROM`).
		WillReturnRows(sqlmock.NewRows(vaCols).AddRow(
			uuid.New(), "provider", "5.0.0", "pending_approval",
			"hashicorp", "aws", "prod", uuid.New(), true, true, time.Now(),
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/version-approvals?status=pending_approval", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body models.VersionApprovalListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 1 || len(body.Items) != 1 {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestVAHandler_List_DBError(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM`).WillReturnError(sqlmock.ErrCancelled)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/version-approvals", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestVAHandler_PendingCount_DBError(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	mock.ExpectQuery(`SELECT`).WillReturnError(sqlmock.ErrCancelled)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/version-approvals/pending-count", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestVAHandler_Events_InvalidID(t *testing.T) {
	r, _ := newVersionApprovalRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/version-approvals/not-a-uuid/events", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestVAHandler_Events_DBError(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	id := uuid.New()
	mock.ExpectQuery(`FROM version_approval_events`).WithArgs(id).WillReturnError(sqlmock.ErrCancelled)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/version-approvals/"+id.String()+"/events", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestVAHandler_PendingCount(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs(models.VersionApprovalStatusPending).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/version-approvals/pending-count", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Count != 3 {
		t.Fatalf("expected count 3, got %d", body.Count)
	}
}

func TestVAHandler_Approve_Provider(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	id := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
		WithArgs(id, "approved").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO version_approval_events`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	body := bytes.NewBufferString(`{"notes":"looks good"}`)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/admin/version-approvals/"+id.String()+"/approve", body))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVAHandler_Approve_InvalidID(t *testing.T) {
	r, _ := newVersionApprovalRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/admin/version-approvals/not-a-uuid/approve", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestVAHandler_Reject_NotFound(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	id := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE terraform_versions SET approval_status`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/admin/version-approvals/"+id.String()+"/reject", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVAHandler_BulkApprove(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	id1, id2 := uuid.New(), uuid.New()

	for _, id := range []uuid.UUID{id1, id2} {
		mock.ExpectBegin()
		mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
			WithArgs(id, "approved").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(`INSERT INTO version_approval_events`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
	}

	payload, _ := json.Marshal(map[string]interface{}{"ids": []string{id1.String(), id2.String()}})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin/version-approvals/bulk-approve", bytes.NewReader(payload)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp models.VersionApprovalBulkResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Approved != 2 || len(resp.Failures) != 0 {
		t.Fatalf("unexpected bulk response: %+v", resp)
	}
}

func TestVAHandler_BulkReject(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	id := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
		WithArgs(id, "rejected").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO version_approval_events`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	payload, _ := json.Marshal(map[string]interface{}{"ids": []string{id.String()}, "notes": "superseded"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin/version-approvals/bulk-reject", bytes.NewReader(payload)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp models.VersionApprovalBulkResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Rejected != 1 || len(resp.Failures) != 0 {
		t.Fatalf("unexpected bulk reject response: %+v", resp)
	}
}

func TestVAHandler_BulkApprove_MissingIDs(t *testing.T) {
	r, _ := newVersionApprovalRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin/version-approvals/bulk-approve", bytes.NewBufferString(`{}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestVAHandler_BulkApprove_InvalidID(t *testing.T) {
	r, _ := newVersionApprovalRouter(t)
	payload := `{"ids":["not-a-uuid"]}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin/version-approvals/bulk-approve", bytes.NewBufferString(payload)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp models.VersionApprovalBulkResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Approved != 0 || len(resp.Failures) != 1 {
		t.Fatalf("expected 1 failure, got %+v", resp)
	}
}

func TestVAHandler_Events(t *testing.T) {
	r, mock := newVersionApprovalRouter(t)
	id := uuid.New()
	name := "alice"

	cols := []string{
		"id", "mirrored_provider_version_id", "terraform_version_id",
		"action", "performed_by", "performed_by_name", "notes", "auto_approve_rule", "created_at",
	}
	mock.ExpectQuery(`FROM version_approval_events`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows(cols).AddRow(
			uuid.New(), id, nil, "approved", uuid.New(), name, nil, nil, time.Now(),
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/version-approvals/"+id.String()+"/events", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var events []models.VersionApprovalEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 1 || events[0].Action != "approved" {
		t.Fatalf("unexpected events: %+v", events)
	}
}
