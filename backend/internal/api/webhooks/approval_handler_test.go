package webhooks

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

func newApprovalRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	rbacRepo := repositories.NewRBACRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewApprovalHandler(rbacRepo)

	r := gin.New()
	r.POST("/webhooks/approvals/:token", h.RedeemApprovalToken)
	return mock, r
}

func randomHex64() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// TestRedeemApprovalToken_InvalidLength — token shorter than 64 chars → 400
func TestRedeemApprovalToken_InvalidLength(t *testing.T) {
	_, r := newApprovalRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/approvals/tooshort", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// TestRedeemApprovalToken_NotFound — DB returns no rows → 404
func TestRedeemApprovalToken_NotFound(t *testing.T) {
	mock, r := newApprovalRouter(t)
	plain := randomHex64()

	mock.ExpectQuery("SELECT approval_request_id").
		WithArgs(hashToken(plain)).
		WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/approvals/"+plain, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// TestRedeemApprovalToken_DBError — unexpected DB error → 500
func TestRedeemApprovalToken_DBError(t *testing.T) {
	mock, r := newApprovalRouter(t)
	plain := randomHex64()

	mock.ExpectQuery("SELECT approval_request_id").
		WithArgs(hashToken(plain)).
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/approvals/"+plain, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// TestRedeemApprovalToken_Success — valid token → marks used, approves, returns 200
func TestRedeemApprovalToken_Success(t *testing.T) {
	mock, r := newApprovalRouter(t)
	plain := randomHex64()
	approvalID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	// Step 1: SELECT to look up token
	rows := sqlmock.NewRows([]string{"approval_request_id", "expires_at", "used_at"}).
		AddRow(approvalID, expiresAt, nil)
	mock.ExpectQuery("SELECT approval_request_id").
		WithArgs(hashToken(plain)).
		WillReturnRows(rows)

	// Step 2: UPDATE to mark used
	mock.ExpectExec("UPDATE webhook_approval_tokens").
		WithArgs(hashToken(plain)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Step 3: UPDATE approval status
	mock.ExpectExec("UPDATE mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/approvals/"+plain, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}
