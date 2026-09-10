package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// Issue #687 -- the payoff of the narrowed dependency, demonstrated.
//
// AdvisoryHandlers uses exactly one method of the 8-method CVERepository. With
// the concrete type it could only be exercised through a sqlmock script that
// encodes the repository's SQL; that test would fail on an unrelated change to
// the query and pass whether or not the handler shaped its response correctly.
// Against cveAdvisoryLister the test says what it means.

type fakeAdvisoryLister struct {
	advisories []models.CVEAdvisory
	err        error
	kindSeen   string
	calls      int
}

func (f *fakeAdvisoryLister) ListAll(_ context.Context, kindFilter string) ([]models.CVEAdvisory, error) {
	f.calls++
	f.kindSeen = kindFilter
	return f.advisories, f.err
}

func advisoryRouter(t *testing.T, repo cveAdvisoryLister) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/advisories", newAdvisoryHandlers(repo, nil).ListAdvisories())
	return r
}

func TestListAdvisories_PassesTheKindFilterThrough(t *testing.T) {
	fake := &fakeAdvisoryLister{}
	r := advisoryRouter(t, fake)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/advisories?kind=provider", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if fake.calls != 1 {
		t.Fatalf("repository called %d times, want 1", fake.calls)
	}
	// The filter reaching the repository is the whole behaviour of this
	// endpoint's query parameter; a sqlmock test would assert on the SQL text
	// instead and break the first time the query is reformatted.
	if fake.kindSeen != "provider" {
		t.Errorf("kind filter = %q, want provider", fake.kindSeen)
	}
}

func TestListAdvisories_EmptyResultIsAnArrayNotNull(t *testing.T) {
	// A JSON `null` here breaks a client that iterates the response, and it is
	// exactly what a `var x []T` returns when marshalled. The handler
	// pre-allocates to avoid it; this pins that.
	r := advisoryRouter(t, &fakeAdvisoryLister{advisories: nil})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/advisories", nil))

	// The list must be [] and not null: a JSON null breaks a client that
	// iterates it, and `var x []T` marshals to exactly that.
	var env struct {
		Advisories []map[string]any `json:"advisories"`
		Total      int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not the documented envelope: %v (%s)", err, w.Body.String())
	}
	if env.Advisories == nil {
		t.Errorf("advisories rendered as null, want []: %s", w.Body.String())
	}
	if env.Total != 0 {
		t.Errorf("total = %d, want 0", env.Total)
	}
}

func TestListAdvisories_RepositoryFailureIs500AndLeaksNothing(t *testing.T) {
	r := advisoryRouter(t, &fakeAdvisoryLister{err: errors.New("pq: relation \"cve_advisories\" does not exist")})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/advisories", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	// The database error names a table and a driver; neither belongs in an
	// HTTP response.
	if body := w.Body.String(); len(body) > 0 && (strings.Contains(body, "cve_advisories") || strings.Contains(body, "pq:")) {
		t.Errorf("the repository error leaked into the response: %s", body)
	}
}

func TestListAdvisories_ShapesEachAdvisory(t *testing.T) {
	withdrawn := time.Now()
	fake := &fakeAdvisoryLister{advisories: []models.CVEAdvisory{{
		SourceID: "GHSA-xxxx", Severity: models.CVESeverity("HIGH"), Summary: "a summary",
		References: []string{"https://example.test/a"}, WithdrawnAt: &withdrawn,
	}}}
	r := advisoryRouter(t, fake)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/advisories", nil))

	var env struct {
		Advisories []map[string]any `json:"advisories"`
		Total      int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not the documented envelope: %v (%s)", err, w.Body.String())
	}
	if len(env.Advisories) != 1 || env.Total != 1 {
		t.Fatalf("got %d advisories (total %d), want 1", len(env.Advisories), env.Total)
	}
	got := env.Advisories
	if got[0]["source_id"] != "GHSA-xxxx" || got[0]["severity"] != "HIGH" {
		t.Errorf("advisory not shaped as expected: %v", got[0])
	}
	// Withdrawn advisories are included on the ADMIN endpoint by design -- that
	// is what distinguishes it from the public one -- and the handler derives
	// the flag from a nullable timestamp, which is the kind of mapping a
	// sqlmock test states twice and therefore never checks.
	if got[0]["withdrawn"] != true {
		t.Errorf("withdrawn flag lost: %v", got[0])
	}
}
