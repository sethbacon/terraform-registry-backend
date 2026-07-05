// scanning_check_test.go tests TriggerScannerCheckHandler: a thin, pure handler
// that just signals ScannerUpdateJob.TriggerCheck() (a non-blocking buffered
// channel send) and returns 202. No live DB/network dependency.
package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
)

func TestTriggerScannerCheckHandler(t *testing.T) {
	job := jobs.NewScannerUpdateJob(
		&config.ScanningConfig{},
		&config.NotificationsConfig{},
		&config.CVEConfig{},
		nil, // sbvRepo
		nil, // approvalRepo
		nil, // oidcCfgRepo
		nil, // scannerJob
		nil, // check
		nil, // download
	)

	r := gin.New()
	r.POST("/check", TriggerScannerCheckHandler(job))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/check", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, http.StatusAccepted, w.Body.String())
	}
	if want := `"message":"scanner update check triggered"`; !strings.Contains(w.Body.String(), want) {
		t.Errorf("body = %s, want to contain %q", w.Body.String(), want)
	}
}
