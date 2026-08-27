package modules

// scm_sync_ref_handler_test.go covers the request half of #879: reading an
// optional ref, and mapping a resolution failure to a status a publisher can
// act on.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

func ctxWithQuery(t *testing.T, q string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/modules/x/scm/sync?"+q, nil)
	return c, w
}

func TestParseSyncRef(t *testing.T) {
	for _, tc := range []struct {
		name       string
		query      string
		wantOK     bool
		wantTag    string
		wantCommit string
		wantStatus int
	}{
		{
			name:   "no ref at all is the existing behaviour",
			query:  "",
			wantOK: true,
		},
		{
			name:    "tag alone",
			query:   "tag=v1.2.3",
			wantOK:  true,
			wantTag: "v1.2.3",
		},
		{
			name:       "tag and commit",
			query:      "tag=v1.2.3&commit_sha=1a2b3c4d5e6f",
			wantOK:     true,
			wantTag:    "v1.2.3",
			wantCommit: "1a2b3c4d5e6f",
		},
		{
			name:    "whitespace is trimmed",
			query:   "tag=%20v1.2.3%20",
			wantOK:  true,
			wantTag: "v1.2.3",
		},
		{
			// A bare SHA names no tag to import, and the sync walks tags. If
			// this were ignored rather than refused, a caller would believe it
			// had pinned something and get an unpinned sync.
			name:       "commit without a tag is refused",
			query:      "commit_sha=1a2b3c4d5e6f",
			wantOK:     false,
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, w := ctxWithQuery(t, tc.query)
			ref, ok := parseSyncRef(c)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (body %s)", ok, tc.wantOK, w.Body.String())
			}
			if !ok {
				if w.Code != tc.wantStatus {
					t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
				}
				return
			}
			if ref.TagName != tc.wantTag {
				t.Errorf("TagName = %q, want %q", ref.TagName, tc.wantTag)
			}
			if ref.CommitSHA != tc.wantCommit {
				t.Errorf("CommitSHA = %q, want %q", ref.CommitSHA, tc.wantCommit)
			}
		})
	}
}

// TestStatusForRefError pins the distinctions a publisher acts on.
func TestStatusForRefError(t *testing.T) {
	moved := fmt.Errorf("%w: v1.2.3 points at aaa, not bbb", services.ErrRefMoved)
	missing := fmt.Errorf("%w: v9.9.9", services.ErrRefNotFound)

	if got, msg := statusForRefError(missing); got != http.StatusNotFound {
		t.Errorf("missing ref -> %d (%s), want 404", got, msg)
	}
	if got, _ := statusForRefError(moved); got != http.StatusConflict {
		t.Errorf("moved ref -> %d, want 409. A force-moved tag is not a malformed request: the "+
			"caller sent something valid and the repository changed underneath it.", got)
	}
	if got, _ := statusForRefError(errors.New("dial tcp: connection refused")); got != http.StatusBadGateway {
		t.Errorf("transport failure -> %d, want 502. Nothing about the request is wrong and it is "+
			"worth retrying, unlike the other two.", got)
	}
}

// TestStatusForRefErrorDoesNotLeakTransportDetail.
//
// An SCM client error can carry an instance URL or a token fragment. The two
// ref errors are this service's own text and name only the tag and commits, so
// they pass through; anything else is generalised.
func TestStatusForRefErrorDoesNotLeakTransportDetail(t *testing.T) {
	_, msg := statusForRefError(errors.New("Get \"https://ghe.internal.example.com/api/v3/repos?token=ghp_secret\": dial tcp"))
	for _, leak := range []string{"ghe.internal", "ghp_secret", "token="} {
		if contains(msg, leak) {
			t.Errorf("the 502 message leaks %q: %s", leak, msg)
		}
	}
	// And the two that DO pass through must still say which tag, or a publisher
	// cannot tell which of several syncs failed.
	_, movedMsg := statusForRefError(fmt.Errorf("%w: v1.2.3 points at aaa, not bbb", services.ErrRefMoved))
	if !contains(movedMsg, "v1.2.3") {
		t.Errorf("the 409 message does not name the tag: %s", movedMsg)
	}
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
