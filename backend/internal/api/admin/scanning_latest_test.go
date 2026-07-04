package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

func TestGetScannerLatestHandler_UnsupportedTool(t *testing.T) {
	cfg := &config.ScanningConfig{Tool: "trivy"}
	r := gin.New()
	r.GET("/latest", GetScannerLatestHandler(cfg))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/latest?tool=snyk", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestGetScannerLatestHandler_UpdateAvailable(t *testing.T) {
	archiveName := "trivy_0.60.0_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.60.0_checksums.txt"

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	type ghAssetJSON struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}
	release := struct {
		TagName string        `json:"tag_name"`
		Assets  []ghAssetJSON `json:"assets"`
	}{
		TagName: "v0.60.0",
		Assets: []ghAssetJSON{
			{Name: archiveName, BrowserDownloadURL: server.URL + "/assets/" + archiveName},
			{Name: checksumsName, BrowserDownloadURL: server.URL + "/assets/" + checksumsName},
		},
	}

	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	})

	spec := installer.AssetSpec{
		LatestReleaseAPI: server.URL + "/releases/latest",
		VersionedAPI:     server.URL + "/releases/tags/v%s",
		AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_Linux-64bit\.tar\.gz$`),
		ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
		BinaryInArchive:  "trivy",
		ArchiveFormat:    "tar.gz",
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := installer.Catalog["trivy"]
	installer.Catalog["trivy"] = map[string]installer.AssetSpec{platform: spec}
	t.Cleanup(func() { installer.Catalog["trivy"] = origCatalog })

	// GetScannerLatestHandler has no HTTPClient injection point, so it uses
	// http.DefaultTransport internally; point it at the httptest TLS server's
	// certificate for the duration of this test.
	origTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = origTransport })

	cfg := &config.ScanningConfig{Tool: "trivy", ExpectedVersion: "0.50.0"}
	r := gin.New()
	r.GET("/latest", GetScannerLatestHandler(cfg))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/latest", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp ScannerLatestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.LatestVersion != "0.60.0" {
		t.Errorf("LatestVersion = %q, want 0.60.0", resp.LatestVersion)
	}
	if resp.CurrentVersion != "0.50.0" {
		t.Errorf("CurrentVersion = %q, want 0.50.0", resp.CurrentVersion)
	}
	if !resp.UpdateAvailable {
		t.Error("expected UpdateAvailable = true (0.60.0 > 0.50.0)")
	}
}
