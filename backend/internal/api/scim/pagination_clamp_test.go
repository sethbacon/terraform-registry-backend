package scim

// pagination_clamp_test.go covers the SCIM half of issue #893.
//
// GET /scim/v2/Users advertises "count, max 200" and used to serve 100 for any
// count above 200 — so an IdP syncing a directory with `?count=1000` was handed
// 100 users. RFC 7644 gives the client nothing to distinguish that from a
// directory with 100 users in it except totalResults, which is asserted here
// alongside the clamp for exactly that reason.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// scimListRouter mounts the SCIM user list behind a platform administrator, the
// principal for whom the whole-directory view is the intended behaviour. Tenant
// scoping on this family is asserted separately by tenant_scope_class_test.go.
func scimListRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h := NewHandlers(&config.Config{}, db)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Set("user_id", scimCallerID)
	})
	r.GET("/scim/v2/Users", h.ListUsers())
	return r, mock
}

func TestSCIMListUsers_CountClampsToMaximumNotDefault(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		// ISSUE #893: each of these served 100 before the fix, so an IdP asking
		// for a bigger page than the maximum got the default one instead.
		{"above the maximum is served as the maximum", "1000", 200},
		{"one above the maximum is served as the maximum", "201", 200},

		{"the maximum itself is served whole", "200", 200},
		{"an in-range count is served unchanged", "150", 150},
		{"no count takes the default", "", 100},
		{"zero takes the default", "0", 100},
		{"a negative count takes the default", "-1", 100},
		{"an unparseable count takes the default", "everyone", 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, mock := scimListRouter(t)
			// ListUsers counts, then pages. The page query's LIMIT is the
			// clamped count, pinned here so a handler that REPORTED the right
			// itemsPerPage while querying another cannot pass.
			mock.ExpectQuery("SELECT COUNT").
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(137))
			mock.ExpectQuery("SELECT").WithArgs(tc.want, 0).
				WillReturnRows(sqlmock.NewRows(scimUserCols).
					AddRow(scimTargetID, "jane@example.com", "Jane", nil, time.Now(), time.Now()))

			url := "/scim/v2/Users"
			if tc.raw != "" {
				url += "?count=" + tc.raw
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
			}

			var resp SCIMListResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
			}
			if resp.ItemsPerPage != tc.want {
				t.Errorf("?count=%s served itemsPerPage = %d, want %d",
					tc.raw, resp.ItemsPerPage, tc.want)
			}
			// totalResults is a SCIM client's only completeness signal, and it
			// has to survive the clamp change.
			if resp.TotalResults != 137 {
				t.Errorf("totalResults = %d, want 137", resp.TotalResults)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the store was not asked for LIMIT "+strconv.Itoa(tc.want)+": %v", err)
			}
		})
	}
}
