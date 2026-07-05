// scanning_auto_update_test.go tests ScanningAutoUpdateHandler.Put: the merge
// with existing persisted scanning config, in-place cfg mutation, interval
// default, and auto_approve_rules validation. Mirrors notifications_test.go's
// sqlmock harness.
package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// newScanningAutoUpdateHandler builds a ScanningAutoUpdateHandler backed by
// sqlmock, mirroring newNotificationsHandler in notifications_test.go.
// updateJob is intentionally nil: the handler's `if h.updateJob != nil` guard
// skips the restart, keeping this test hermetic.
func newScanningAutoUpdateHandler(t *testing.T) (*ScanningAutoUpdateHandler, *config.ScanningConfig, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo := repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock"))
	cfg := &config.ScanningConfig{Tool: "trivy", InstallDir: "/opt/scanners"}
	return NewScanningAutoUpdateHandler(cfg, repo, nil), cfg, mock
}

func TestScanningAutoUpdateHandler_Put_Success(t *testing.T) {
	h, cfg, mock := newScanningAutoUpdateHandler(t)

	existingRow := `{"enabled":true,"tool":"trivy","binary_path":"/opt/scanners/trivy","expected_version":"0.53.0","install_dir":"/opt/scanners"}`
	mock.ExpectQuery("SELECT scanning_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_config"}).AddRow([]byte(existingRow)))
	mock.ExpectExec("UPDATE system_settings").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/auto-update", h.Put)
	body := `{"enabled":true,"interval_hours":12,"requires_approval":false,"auto_approve_rules":""}`
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/auto-update", jsonBodyAdmin(json.RawMessage(body))))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp ScanningAutoUpdateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Enabled || resp.IntervalHours != 12 || resp.RequiresApproval {
		t.Errorf("unexpected response: %+v", resp)
	}

	if !cfg.AutoUpdate.Enabled || cfg.AutoUpdate.IntervalHours != 12 || cfg.AutoUpdate.RequiresApproval {
		t.Errorf("cfg.AutoUpdate not mutated in place: %+v", cfg.AutoUpdate)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestScanningAutoUpdateHandler_Put_InvalidAutoApproveRules(t *testing.T) {
	h, _, _ := newScanningAutoUpdateHandler(t)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/auto-update", h.Put)
	body := `{"enabled":true,"interval_hours":12,"auto_approve_rules":"not json"}`
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/auto-update", jsonBodyAdmin(json.RawMessage(body))))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestScanningAutoUpdateHandler_Put_MalformedJSON(t *testing.T) {
	h, _, _ := newScanningAutoUpdateHandler(t)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/auto-update", h.Put)
	req := httptest.NewRequest(http.MethodPut, "/auto-update", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestScanningAutoUpdateHandler_Put_SetScanningConfigError(t *testing.T) {
	h, _, mock := newScanningAutoUpdateHandler(t)

	mock.ExpectQuery("SELECT scanning_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_config"}).AddRow(nil))
	mock.ExpectExec("UPDATE system_settings").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/auto-update", h.Put)
	body := `{"enabled":true,"interval_hours":12}`
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/auto-update", jsonBodyAdmin(json.RawMessage(body))))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", w.Code, w.Body.String())
	}
}

func TestScanningAutoUpdateHandler_Put_IntervalDefaultsTo24(t *testing.T) {
	h, cfg, mock := newScanningAutoUpdateHandler(t)

	mock.ExpectQuery("SELECT scanning_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_config"}).AddRow(nil))
	mock.ExpectExec("UPDATE system_settings").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/auto-update", h.Put)
	body := `{"enabled":true,"interval_hours":0}`
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/auto-update", jsonBodyAdmin(json.RawMessage(body))))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp ScanningAutoUpdateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.IntervalHours != 24 {
		t.Errorf("IntervalHours = %d, want 24 (default)", resp.IntervalHours)
	}
	if cfg.AutoUpdate.IntervalHours != 24 {
		t.Errorf("cfg.AutoUpdate.IntervalHours = %d, want 24", cfg.AutoUpdate.IntervalHours)
	}
}
