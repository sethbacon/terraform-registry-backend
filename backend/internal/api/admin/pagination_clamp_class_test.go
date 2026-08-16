package admin

// pagination_clamp_class_test.go drives EVERY paginated axis in this package
// through the same table, because issue #893 was reported against exactly one
// of them.
//
// The reported defect — `?per_page=200` on GET /api/v1/organizations serving 20
// rows — was one instance of a clamp copy-pasted into five handlers here (and
// four more elsewhere in the module; internal/pagination/clamp_sweep_test.go is
// the signature that covers those). A test written against the organization
// list alone would have gone green while /users, /users/search and
// /admin/audit-logs stayed broken, which is how a closed issue reopens next to
// its patched sibling.
//
// Each axis is asserted at two levels, which is what makes the test hard to
// satisfy accidentally:
//
//  1. The `per_page` the response REPORTS.
//  2. The LIMIT the STORE was asked for, pinned through sqlmock's WithArgs. A
//     handler that reported 100 and queried 20 would pass on (1) alone, and
//     that divergence is exactly what a caller cannot see from outside.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/pagination"
)

// paginationAxis is one paginated endpoint, described by everything the clamp
// table needs in order to drive it.
type paginationAxis struct {
	name string
	// newRouter builds the axis's router over a fresh mocked connection.
	newRouter func(*testing.T) (sqlmock.Sqlmock, *gin.Engine)
	// url renders the request for a raw per_page parameter; the empty string
	// means "send no per_page at all".
	url func(perPage string) string
	// def and max are what the endpoint's swagger annotation promises.
	def, max int
	// storeLimit maps the page size the caller is served to the LIMIT the store
	// is asked for. Identity on the counted axes; Probe on the two search axes,
	// which fetch one extra row to answer has_more without a count query.
	storeLimit func(perPage int) int
	// queue seeds the mocked store for exactly one request, pinning that LIMIT.
	queue func(mock sqlmock.Sqlmock, limit int)
}

func countRows(total int) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"count"}).AddRow(total)
}

// orgRows returns n organization rows, so a probe axis can be given the extra
// row that means "more follow".
func orgRows(n int) *sqlmock.Rows {
	rows := sqlmock.NewRows(orgCols)
	for i := 0; i < n; i++ {
		rows.AddRow(fmt.Sprintf("org-%d", i), fmt.Sprintf("org%d", i), "Org", nil, nil, time.Now(), time.Now())
	}
	return rows
}

func identityLimit(perPage int) int { return perPage }

func paginationAxes() []paginationAxis {
	return []paginationAxis{
		{
			// The axis issue #893 was filed against.
			name:       "GET /organizations",
			newRouter:  newOrgRouter,
			url:        func(p string) string { return "/organizations" + perPageQuery(p, "?") },
			def:        orgPerPageDefault,
			max:        orgPerPageMax,
			storeLimit: identityLimit,
			queue: func(mock sqlmock.Sqlmock, limit int) {
				mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").WithArgs(limit, 0).
					WillReturnRows(orgRows(1))
				mock.ExpectQuery("SELECT COUNT.*FROM organizations").WillReturnRows(countRows(137))
			},
		},
		{
			name:       "GET /organizations/search",
			newRouter:  newOrgRouter,
			url:        func(p string) string { return "/organizations/search?q=acme" + perPageQuery(p, "&") },
			def:        orgPerPageDefault,
			max:        orgPerPageMax,
			storeLimit: pagination.Probe,
			queue: func(mock sqlmock.Sqlmock, limit int) {
				mock.ExpectQuery("SELECT.*FROM organizations").WithArgs("%acme%", limit, 0).
					WillReturnRows(orgRows(1))
			},
		},
		{
			name:       "GET /users",
			newRouter:  newUserRouter,
			url:        func(p string) string { return "/users" + perPageQuery(p, "?") },
			def:        userPerPageDefault,
			max:        userPerPageMax,
			storeLimit: identityLimit,
			queue: func(mock sqlmock.Sqlmock, limit int) {
				mock.ExpectQuery("SELECT COUNT").WillReturnRows(countRows(137))
				mock.ExpectQuery("SELECT").WithArgs(limit, 0).WillReturnRows(sampleUserRow())
				mock.ExpectQuery("ANY").WillReturnRows(emptyBulkMembershipRows())
			},
		},
		{
			name:       "GET /users/search",
			newRouter:  newUserRouter,
			url:        func(p string) string { return "/users/search?q=alice" + perPageQuery(p, "&") },
			def:        userPerPageDefault,
			max:        userPerPageMax,
			storeLimit: pagination.Probe,
			queue: func(mock sqlmock.Sqlmock, limit int) {
				mock.ExpectQuery("SELECT").WithArgs("%alice%", limit, 0).WillReturnRows(sampleUserRow())
				mock.ExpectQuery("ANY").WillReturnRows(emptyBulkMembershipRows())
			},
		},
		{
			name:       "GET /admin/audit-logs",
			newRouter:  newAuditLogRouter,
			url:        func(p string) string { return "/audit-logs" + perPageQuery(p, "?") },
			def:        auditPerPageDefault,
			max:        auditPerPageMax,
			storeLimit: identityLimit,
			queue: func(mock sqlmock.Sqlmock, limit int) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM audit_logs`).WillReturnRows(countRows(137))
				mock.ExpectQuery(`SELECT al\.id`).WithArgs(limit, 0).WillReturnRows(sampleAuditLogListRows())
			},
		},
	}
}

// perPageQuery renders the per_page parameter, or nothing at all for the
// "caller expressed no preference" case.
func perPageQuery(raw, sep string) string {
	if raw == "" {
		return ""
	}
	return sep + "per_page=" + raw
}

// metaOf pulls the pagination block out of a list response. Every axis emits it
// under the same key, whichever list key sits beside it.
func metaOf(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v (body=%s)", err, w.Body.String())
	}
	meta, ok := body["pagination"].(map[string]interface{})
	if !ok {
		t.Fatalf("response has no 'pagination' object: %s", w.Body.String())
	}
	return meta
}

func metaInt(t *testing.T, meta map[string]interface{}, key string) int {
	t.Helper()
	n, ok := meta[key].(float64)
	if !ok {
		t.Fatalf("pagination.%s is %#v, want a number", key, meta[key])
	}
	return int(n)
}

func TestPaginationClampClass_OverMaximumClampsToMaximum(t *testing.T) {
	for _, axis := range paginationAxes() {
		// Each case is (raw per_page, the size that must be served). The names
		// are the promise the endpoint's swagger makes, restated as behaviour.
		cases := []struct {
			name string
			raw  string
			want int
		}{
			// ISSUE #893. Every one of these returned `def` before the fix, so
			// asking for more than the maximum returned fewer rows than asking
			// for anything in range.
			{"twice the maximum is served as the maximum", strconv.Itoa(axis.max * 2), axis.max},
			{"one over the maximum is served as the maximum", strconv.Itoa(axis.max + 1), axis.max},
			{"a size that overflows an int is served as the maximum", "99999999999999999999", axis.max},

			// Unchanged behaviour, kept under test so the fix cannot be
			// mistaken for "the clamp was deleted".
			{"the maximum itself is served whole", strconv.Itoa(axis.max), axis.max},
			{"an in-range size is served unchanged", strconv.Itoa(axis.max - 1), axis.max - 1},
			{"no per_page takes the default", "", axis.def},
			{"zero takes the default", "0", axis.def},
			{"a negative size takes the default", "-5", axis.def},
			{"an unparseable size takes the default", "lots", axis.def},
		}

		for _, tc := range cases {
			t.Run(axis.name+"/"+tc.name, func(t *testing.T) {
				mock, r := axis.newRouter(t)
				axis.queue(mock, axis.storeLimit(tc.want))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("GET", axis.url(tc.raw), nil))

				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
				if got := metaInt(t, metaOf(t, w), "per_page"); got != tc.want {
					t.Errorf("per_page=%q served %d rows per page, want %d",
						tc.raw, got, tc.want)
				}
				// The store half of the assertion: WithArgs above pins the
				// LIMIT, and an unmet expectation here means the handler
				// reported one page size and queried another.
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("the store was not asked for LIMIT %d: %v",
						axis.storeLimit(tc.want), err)
				}
			})
		}
	}
}

// TestPaginationClampClass_CompletenessSignal is the other half of #893: a
// clamp that is now honest still leaves an administrator looking at a list with
// no way to know it ends there.
//
// has_more answers that directly on every axis — including the two search axes,
// which have no total at all because the identity store has no counting query
// for them.
func TestPaginationClampClass_CompletenessSignal(t *testing.T) {
	t.Run("a counted axis reports has_more and the total", func(t *testing.T) {
		mock, r := newOrgRouter(t)
		mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").WithArgs(100, 0).
			WillReturnRows(orgRows(100))
		mock.ExpectQuery("SELECT COUNT.*FROM organizations").WillReturnRows(countRows(137))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations?per_page=200", nil))

		meta := metaOf(t, w)
		if meta["has_more"] != true {
			t.Errorf("has_more = %#v, want true — 100 of 137 organizations were served, "+
				"and a picker showing them has no other way to know 37 are missing", meta["has_more"])
		}
		if got := metaInt(t, meta, "total"); got != 137 {
			t.Errorf("total = %d, want 137", got)
		}
	})

	t.Run("a counted axis whose page is the whole list reports has_more false", func(t *testing.T) {
		mock, r := newOrgRouter(t)
		mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").WithArgs(20, 0).
			WillReturnRows(orgRows(3))
		mock.ExpectQuery("SELECT COUNT.*FROM organizations").WillReturnRows(countRows(3))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations", nil))

		if meta := metaOf(t, w); meta["has_more"] != false {
			t.Errorf("has_more = %#v, want false — all 3 organizations were served", meta["has_more"])
		}
	})

	t.Run("an uncounted axis reports has_more and a null total", func(t *testing.T) {
		// The probe row (21 rows for a page of 20) is what makes has_more exact
		// here, and it must not be served: a caller asked for 20.
		mock, r := newOrgRouter(t)
		mock.ExpectQuery("SELECT.*FROM organizations").WithArgs("%acme%", 21, 0).
			WillReturnRows(orgRows(21))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/search?q=acme", nil))

		var body struct {
			Organizations []map[string]interface{} `json:"organizations"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(body.Organizations) != 20 {
			t.Errorf("served %d organizations, want 20 — the probe row is a question, not a result",
				len(body.Organizations))
		}

		meta := metaOf(t, w)
		if meta["has_more"] != true {
			t.Errorf("has_more = %#v, want true — a 21st row came back", meta["has_more"])
		}
		if total, present := meta["total"]; !present || total != nil {
			t.Errorf("total = %#v, want an explicit null — this axis has no counting query, "+
				"and reporting 0 would be a count nobody performed", total)
		}
	})

	t.Run("an uncounted axis whose page is exactly full still reports has_more false", func(t *testing.T) {
		// The case a "did the page come back full?" heuristic gets wrong, and
		// the reason the probe row exists.
		mock, r := newOrgRouter(t)
		mock.ExpectQuery("SELECT.*FROM organizations").WithArgs("%acme%", 21, 0).
			WillReturnRows(orgRows(20))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/search?q=acme", nil))

		if meta := metaOf(t, w); meta["has_more"] != false {
			t.Errorf("has_more = %#v, want false — exactly 20 rows matched, so this full page "+
				"is the end of the list", meta["has_more"])
		}
	})

	t.Run("every axis emits has_more", func(t *testing.T) {
		// The field is only useful if a client can rely on it being there. An
		// axis that omits it sends a consumer straight back to comparing counts
		// by hand, which is the state #893 was filed about.
		for _, axis := range paginationAxes() {
			t.Run(axis.name, func(t *testing.T) {
				mock, r := axis.newRouter(t)
				axis.queue(mock, axis.storeLimit(axis.def))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("GET", axis.url(""), nil))

				if _, present := metaOf(t, w)["has_more"]; !present {
					t.Errorf("pagination has no has_more field: %s", w.Body.String())
				}
			})
		}
	})
}
