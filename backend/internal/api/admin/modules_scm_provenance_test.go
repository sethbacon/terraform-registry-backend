package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// GetModule selected commit_sha and tag_name from the day the columns were
// added, scanned them into the model, and then dropped them when assembling
// the response. An automated publisher could not ask "which version is this
// commit?" and had to match on the version string it had just constructed
// (issue #879, terraform-module-publish#23).
//
// The fixture below carries real values in those two columns, which the
// existing sampleModVersionListRow does not — with nils there, emitting the
// fields and dropping them look identical.
func scmPublishedVersionRow() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionListCols).
		AddRow("ver-1", "mod-1", "1.0.0", "modules/hashicorp/vpc/aws/vpc-1.0.0.tar.gz", "default",
			int64(1024), "abc123", nil, nil, nil, int64(5), false, nil, nil, nil, time.Now(),
			"9f2c1ab4e5d6", "v1.0.0", "repo-1", false)
}

func getModuleVersions(t *testing.T, rows *sqlmock.Rows) []map[string]any {
	t.Helper()
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions").WillReturnRows(rows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/hashicorp/vpc/aws", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	var body struct {
		Versions []map[string]any `json:"versions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v — body=%s", err, w.Body.String())
	}
	if len(body.Versions) != 1 {
		t.Fatalf("got %d versions, want 1: body=%s", len(body.Versions), w.Body.String())
	}
	return body.Versions
}

func TestGetModule_EmitsSCMProvenance(t *testing.T) {
	version := getModuleVersions(t, scmPublishedVersionRow())[0]

	if got := version["commit_sha"]; got != "9f2c1ab4e5d6" {
		t.Errorf("commit_sha = %v, want 9f2c1ab4e5d6 — the column is selected and "+
			"scanned, so an absent key means the handler dropped it", got)
	}
	if got := version["tag_name"]; got != "v1.0.0" {
		t.Errorf("tag_name = %v, want v1.0.0", got)
	}
}

// A version uploaded by hand has no commit to report. The key is omitted
// rather than emitted as null, matching the deprecation fields beside it and
// the model's own omitempty tags: an explicit null would claim the publish was
// SCM-tracked and the SHA lost, which is a different statement from "this was
// not published from a repository".
func TestGetModule_OmitsSCMProvenanceWhenAbsent(t *testing.T) {
	version := getModuleVersions(t, sampleModVersionListRow())[0]

	for _, key := range []string{"commit_sha", "tag_name"} {
		if _, present := version[key]; present {
			t.Errorf("%q is present (%v) for a version with no SCM provenance; "+
				"it should be omitted", key, version[key])
		}
	}
}
