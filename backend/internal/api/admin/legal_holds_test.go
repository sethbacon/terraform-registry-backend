package admin

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/audit"
)

// The handlers are the WRITE side of legal hold. That a held row actually
// survives a sweep is proved against real PostgreSQL in terraform-suite-identity,
// where the predicate lives; what is checkable here is that a hold is recorded,
// that releasing one reports honestly, and — the case #872 is really about —
// that a deployment which CANNOT honour holds says so instead of accepting one.

var holdCols = []string{
	"id", "name", "reason", "start_date", "end_date", "active",
	"placed_by", "placed_at", "released_by", "released_at",
}

func newHoldRouter(t *testing.T, h *LegalHoldHandlers) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/legal-holds", h.ListLegalHolds)
	r.POST("/legal-holds", h.PlaceLegalHold)
	r.POST("/legal-holds/:id/release", h.ReleaseLegalHold)
	return r
}

func newAvailableHoldHandlers(t *testing.T) (*LegalHoldHandlers, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// auditRepo nil: the audit write is asynchronous and separately covered;
	// nil makes recordHoldAction a no-op rather than racing the assertions.
	return NewLegalHoldHandlers(audit.NewLegalHoldStore(db), nil), mock
}

// ---------------------------------------------------------------------------
// The unavailable deployment — the state #872 exists to prevent
// ---------------------------------------------------------------------------

func TestUnavailableDeploymentRefusesEveryRoute(t *testing.T) {
	h := NewUnavailableLegalHoldHandlers("the legal_holds table is not readable on the sweep's connection")
	r := newHoldRouter(t, h)

	body, _ := json.Marshal(PlaceLegalHoldRequest{
		Name: "investigation", StartDate: time.Now(), EndDate: time.Now().AddDate(0, 0, 1),
	})
	for _, tc := range []struct {
		method, path string
		body         []byte
	}{
		{"POST", "/legal-holds", body},
		{"POST", "/legal-holds/some-id/release", nil},
		{"GET", "/legal-holds", nil},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503 — accepting a hold this deployment cannot honour is "+
					"the exact failure #872 describes: body=%s", w.Code, w.Body.String())
			}
			if !bytes.Contains(w.Body.Bytes(), []byte("not readable")) {
				t.Errorf("the response does not say WHY: %s", w.Body.String())
			}
		})
	}
}

// Listing refuses too, deliberately: an empty list from a deployment that
// cannot read the table is indistinguishable from "nothing is held".
func TestUnavailableListDoesNotReportAnEmptyList(t *testing.T) {
	h := NewUnavailableLegalHoldHandlers("unreadable")
	w := httptest.NewRecorder()
	newHoldRouter(t, h).ServeHTTP(w, httptest.NewRequest("GET", "/legal-holds", nil))

	if w.Code == http.StatusOK {
		t.Fatal("an unavailable deployment answered 200; an empty list reads as 'nothing is held', " +
			"which is a worse answer than an error")
	}
}

// ---------------------------------------------------------------------------
// The working deployment
// ---------------------------------------------------------------------------

func TestPlaceRecordsAHoldAndReturns201(t *testing.T) {
	h, mock := newAvailableHoldHandlers(t)
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 3)

	mock.ExpectQuery(`INSERT INTO legal_holds`).
		WillReturnRows(sqlmock.NewRows([]string{"placed_at", "active"}).AddRow(start, true))

	body, _ := json.Marshal(PlaceLegalHoldRequest{Name: "investigation", Reason: "subpoena", StartDate: start, EndDate: end})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/legal-holds", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	newHoldRouter(t, h).ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}
	var got audit.LegalHold
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID == "" {
		t.Error("the response carries no id, so the caller cannot release the hold it just placed")
	}
	if !got.Active {
		t.Error("a freshly placed hold is not active")
	}
}

func TestPlaceRejectsAnEndBeforeStart(t *testing.T) {
	h, _ := newAvailableHoldHandlers(t)
	start := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)

	body, _ := json.Marshal(PlaceLegalHoldRequest{Name: "backwards", StartDate: start, EndDate: start.AddDate(0, 0, -2)})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/legal-holds", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	newHoldRouter(t, h).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — a window that cannot hold anything is the caller's "+
			"mistake, not a server error: %s", w.Code, w.Body.String())
	}
}

func TestReleaseReports404ForAHoldThatIsNotHolding(t *testing.T) {
	h, mock := newAvailableHoldHandlers(t)
	mock.ExpectQuery(`UPDATE legal_holds`).WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	newHoldRouter(t, h).ServeHTTP(w, httptest.NewRequest("POST", "/legal-holds/unknown/release", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestListReturnsAnEmptyArrayNotNull(t *testing.T) {
	h, mock := newAvailableHoldHandlers(t)
	mock.ExpectQuery(`SELECT .* FROM legal_holds`).WillReturnRows(sqlmock.NewRows(holdCols))

	w := httptest.NewRecorder()
	newHoldRouter(t, h).ServeHTTP(w, httptest.NewRequest("GET", "/legal-holds", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"legal_holds":[]`)) {
		t.Errorf("empty list should marshal as [], got %s", w.Body.String())
	}
}
