package admin

// version_approvals_pagination_test.go covers the version-approval axis of
// issue #893.
//
// This one is not in pagination_clamp_class_test.go's table because its clamp
// does not live in the handler: the `limit` query parameter travels into
// VersionApprovalFilter and is clamped by the REPOSITORY
// (internal/db/repositories/version_approval_repository.go). The defect was
// identical — "max 500" in the swagger, with anything above 500 served as the
// default of 100 — and it is asserted here, through the handler, because that
// is the path a caller actually takes.
//
// The repository interpolates LIMIT into the statement text rather than binding
// it, so the assertion is on the SQL itself.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func TestVAHandler_List_LimitClampsToMaximumNotDefault(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		// ISSUE #893: each of these served 100 before the fix, so an operator
		// draining a large approval queue asked for 1000 and was handed the
		// default page, with nothing to say it had been clamped.
		{"above the maximum is served as the maximum", "limit=5000", 500},
		{"one above the maximum is served as the maximum", "limit=501", 500},

		{"the maximum itself is served whole", "limit=500", 500},
		{"an in-range limit is served unchanged", "limit=42", 42},
		{"no limit takes the default", "", 100},
		{"zero takes the default", "limit=0", 100},
		{"a negative limit takes the default", "limit=-1", 100},
		{"an unparseable limit takes the default", "limit=all", 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, mock := newVersionApprovalRouter(t)

			mock.ExpectQuery(`SELECT COUNT\(\*\) FROM`).
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(137))
			// The LIMIT is interpolated into the statement, so matching the
			// statement text is what pins the clamp end to end.
			mock.ExpectQuery(`LIMIT ` + strconv.Itoa(tc.want) + ` OFFSET 0`).
				WillReturnRows(sqlmock.NewRows(vaCols).AddRow(
					uuid.New(), "provider", "5.0.0", "pending_approval", nil,
					"hashicorp", "aws", "prod", uuid.New(), true, true, time.Now(),
				))

			url := "/admin/version-approvals"
			if tc.raw != "" {
				url += "?" + tc.raw
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
			}
			var body models.VersionApprovalListResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if body.Total != 137 {
				t.Errorf("total = %d, want 137 — the count a caller pages against", body.Total)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("?%s did not query LIMIT %d: %v", tc.raw, tc.want, err)
			}
		})
	}
}
