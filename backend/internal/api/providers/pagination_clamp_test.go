package providers

// pagination_clamp_test.go covers this package's share of issue #893.
//
// GET /api/v1/providers/search carried the module search axis's clamp verbatim:
// "default 20, max 100", with any limit above 100 served as 20. The class
// signature that keeps the shape from returning lives in
// internal/pagination/clamp_sweep_test.go; this is the behaviour half.

import (
	"encoding/json"
	"net/http"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

func searchMetaLimit(t *testing.T, body []byte) int {
	t.Helper()
	var resp struct {
		Meta struct {
			Limit int `json:"limit"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	return resp.Meta.Limit
}

func TestSearchHandler_LimitClampsToMaximumNotDefault(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		// ISSUE #893: each of these served 20 before the fix.
		{"above the maximum is served as the maximum", "limit=500", 100},
		{"one above the maximum is served as the maximum", "limit=101", 100},

		{"the maximum itself is served whole", "limit=100", 100},
		{"an in-range limit is served unchanged", "limit=42", 42},
		{"no limit takes the default", "", 20},
		{"zero takes the default", "limit=0", 20},
		{"a negative limit takes the default", "limit=-1", 20},
		{"an unparseable limit takes the default", "limit=all", 20},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock, r := newSearchRouter(t, &config.Config{})
			mock.ExpectQuery("SELECT COUNT.*FROM providers").
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			mock.ExpectQuery("SELECT.*FROM providers.*ORDER BY").
				WillReturnRows(sampleProviderSearchRowFTS())

			url := "/v1/providers/search?q=aws"
			if tc.raw != "" {
				url += "&" + tc.raw
			}
			w := doGET(r, url)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			if got := searchMetaLimit(t, w.Body.Bytes()); got != tc.want {
				t.Errorf("?%s served meta.limit = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}
