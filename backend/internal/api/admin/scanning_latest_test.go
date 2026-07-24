package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

// scanningLatestLoopbackGuard allow-lists the httptest.Server addresses used
// throughout this file (127.0.0.1) so tests exercise GetScannerLatestHandler's
// installer.CheckLatest call (routed through httpsafe.NewClient via
// installer.InstallConfig.EgressGuard, issue #676) without the strict default
// egress policy rejecting the test server itself as an internal target.
var scanningLatestLoopbackGuard = httpsafe.MustGuard("127.0.0.1")

func TestGetScannerLatestHandler_UnsupportedTool(t *testing.T) {
	cfg := &config.ScanningConfig{Tool: "trivy"}
	r := gin.New()
	r.GET("/latest", GetScannerLatestHandler(cfg, scanningLatestLoopbackGuard))

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
	server := httptest.NewServer(mux)
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

	cfg := &config.ScanningConfig{Tool: "trivy", ExpectedVersion: "0.50.0"}
	r := gin.New()
	r.GET("/latest", GetScannerLatestHandler(cfg, scanningLatestLoopbackGuard))

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

func TestGetScannerLatestHandler_CheckLatestError(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// No handler registered for /releases/latest -> the httptest server
	// returns 404, which CheckLatest surfaces as an error.
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

	cfg := &config.ScanningConfig{Tool: "trivy"}
	r := gin.New()
	r.GET("/latest", GetScannerLatestHandler(cfg, scanningLatestLoopbackGuard))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/latest", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body = %s", w.Code, w.Body.String())
	}
}

// TestGetScannerLatestHandler_StrictGuardRejectsLoopback is the negative
// counterpart to TestGetScannerLatestHandler_CheckLatestError: it proves the
// EgressGuard plumbed into installer.InstallConfig (issue #676) actually
// blocks a loopback target under the strict default policy (nil guard),
// rather than the handler silently reaching it. LatestReleaseAPI itself is
// server-config-controlled in production, but the point of routing through
// httpsafe is defense-in-depth against exactly this class of target.
func TestGetScannerLatestHandler_StrictGuardRejectsLoopback(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.60.0"})
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

	cfg := &config.ScanningConfig{Tool: "trivy"}
	r := gin.New()
	r.GET("/latest", GetScannerLatestHandler(cfg, nil)) // nil guard == strict default

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/latest", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (loopback target blocked), body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "blocked") {
		t.Errorf("body = %s, want it to mention the egress guard blocking the target", w.Body.String())
	}
}

func TestGetScannerLatestHandler_NoCurrentVersion(t *testing.T) {
	archiveName := "trivy_0.60.0_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.60.0_checksums.txt"

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
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

	// Enabled=false so the handler never attempts to resolve a live scanner
	// binary/version, and ExpectedVersion is empty -> currentVersion stays ""
	// -> UpdateAvailable is unconditionally true.
	cfg := &config.ScanningConfig{Tool: "trivy", Enabled: false}
	r := gin.New()
	r.GET("/latest", GetScannerLatestHandler(cfg, scanningLatestLoopbackGuard))

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
	if resp.CurrentVersion != "" {
		t.Errorf("CurrentVersion = %q, want empty", resp.CurrentVersion)
	}
	if !resp.UpdateAvailable {
		t.Error("expected UpdateAvailable = true when no current version is known")
	}
}
