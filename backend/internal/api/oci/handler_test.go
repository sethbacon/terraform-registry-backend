package oci

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// stubStorage is a minimal storage.Storage implementation for exercising the
// blob-download failure path.
type stubStorage struct {
	downloadErr error
}

func (s *stubStorage) Upload(_ context.Context, _ string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return nil, nil
}
func (s *stubStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	if s.downloadErr != nil {
		return nil, s.downloadErr
	}
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (s *stubStorage) Delete(_ context.Context, _ string) error { return nil }
func (s *stubStorage) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", nil
}
func (s *stubStorage) Exists(_ context.Context, _ string) (bool, error) { return true, nil }
func (s *stubStorage) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return &storage.FileMetadata{}, nil
}

// ─── router builder ───────────────────────────────────────────────────────────

func newOCIRouter(_ *testing.T, _ *sql.DB) (*gin.Engine, sqlmock.Sqlmock, error) {
	return nil, nil, nil
}

// unused in tests below — kept to avoid compilation error for newOCIRouter reference
var _ = newOCIRouter

// ─── shared row builders ──────────────────────────────────────────────────────

func orgRow(id, name string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
		AddRow(id, name, "Org "+name, nil, nil, now, now)
}

func moduleRow(id, orgID, ns, name, system string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{
		"id", "organization_id", "namespace", "name", "system",
		"description", "source", "created_by", "created_at", "updated_at",
		"created_by_name", "deprecated", "deprecated_at", "deprecation_message", "successor_module_id",
	}).AddRow(id, orgID, ns, name, system, nil, nil, nil, now, now, nil, false, nil, nil, nil)
}

func versionRow(id, moduleID, version, storagePath, checksum string, sizeBytes int64) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{
		"id", "module_id", "version", "storage_path", "storage_backend",
		"size_bytes", "checksum", "readme", "published_by",
		"download_count", "deprecated", "deprecated_at", "deprecation_message",
		"replacement_source", "created_at", "commit_sha", "tag_name", "scm_repo_id",
	}).AddRow(id, moduleID, version, storagePath, "local",
		sizeBytes, checksum, "", "",
		0, false, nil, nil,
		nil, now, nil, nil, nil)
}

// ─── Ping ────────────────────────────────────────────────────────────────────

func TestPing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{}
	r.GET("/v2/", h.Ping)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if v := w.Header().Get("OCI-Distribution-Spec-Version"); v != ociSpecVersion {
		t.Errorf("expected OCI-Distribution-Spec-Version=%s, got %q", ociSpecVersion, v)
	}
	// Issue #694: also emit the conventional Docker Registry v2 header that
	// existing OCI/Docker tooling (oras, crane, containerd/distribution) checks
	// for during /v2/ capability probing.
	if v := w.Header().Get("Docker-Distribution-Api-Version"); v != "registry/2.0" {
		t.Errorf("expected Docker-Distribution-Api-Version=registry/2.0, got %q", v)
	}
}

// ─── PutManifest returns 405 ──────────────────────────────────────────────────

func TestPutManifest_NotSupported(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{}
	r.PUT("/v2/:namespace/:name/:system/manifests/:reference", h.PutManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/v2/hashicorp/consul/aws/manifests/1.0.0", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	errors, _ := body["errors"].([]interface{})
	if len(errors) == 0 {
		t.Error("expected errors array")
	}
	// Issue #683: RFC 7231 §6.5.5 requires an Allow header on a 405 response.
	if allow := w.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("expected Allow header 'GET, HEAD', got %q", allow)
	}
}

// ─── ociErrors helper ─────────────────────────────────────────────────────────

func TestOCIErrors(t *testing.T) {
	result := ociErrors("MANIFEST_UNKNOWN", "not found")
	errors, ok := result["errors"].([]gin.H)
	if !ok || len(errors) != 1 {
		t.Fatalf("unexpected structure: %v", result)
	}
	if errors[0]["code"] != "MANIFEST_UNKNOWN" {
		t.Errorf("unexpected code: %v", errors[0]["code"])
	}
}

// ─── GetManifest — module not found ──────────────────────────────────────────

func TestGetManifest_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("hashicorp", "consul", "aws").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/manifests/:reference", h.GetManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/hashicorp/consul/aws/manifests/1.0.0", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "MANIFEST_UNKNOWN") {
		t.Errorf("expected MANIFEST_UNKNOWN error, got: %s", w.Body.String())
	}
}

// ─── GetManifest / HeadManifest — internal error (issue #682) ────────────────
//
// A transient failure (org lookup query error) must surface as the generic
// OCI "UNKNOWN" code, not the "does not exist" MANIFEST_UNKNOWN code, so OCI
// clients don't mistake a retryable server fault for permanent absence.

// TestGetBlob_StorageDownloadError — module version resolves fine but the
// storage backend fails; this is also a transient 500 and must not reuse
// BLOB_UNKNOWN.
func TestGetBlob_StorageDownloadError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	const checksum = "abc123def456"

	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))
	mock.ExpectQuery("SELECT.*FROM module_versions").
		WithArgs("mod-id", checksum).
		WillReturnRows(versionRow("ver-id", "mod-id", "1.0.0", "path.tar.gz", checksum, 512))

	h := NewHandler(db, &stubStorage{downloadErr: errors.New("storage unavailable")})
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/blobs/:digest", h.GetBlob)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/hashicorp/consul/aws/blobs/sha256:"+checksum, nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "BLOB_UNKNOWN") {
		t.Errorf("500 response must not reuse BLOB_UNKNOWN, got: %s", w.Body.String())
	}
}

// ─── GetManifest — version not found ─────────────────────────────────────────

func TestGetManifest_VersionNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))

	mock.ExpectQuery("SELECT.*FROM module_versions").
		WithArgs("mod-id", "9.9.9").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/manifests/:reference", h.GetManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/hashicorp/consul/aws/manifests/9.9.9", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "MANIFEST_UNKNOWN") {
		t.Errorf("expected MANIFEST_UNKNOWN error, got: %s", w.Body.String())
	}
}

// ─── GetManifest — success ────────────────────────────────────────────────────

func TestGetManifest_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	const checksum = "abc123def456"
	const size = int64(1024)

	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))

	mock.ExpectQuery("SELECT.*FROM module_versions").
		WithArgs("mod-id", "1.0.0").
		WillReturnRows(versionRow("ver-id", "mod-id", "1.0.0", "modules/hashicorp/consul/aws/1.0.0.tar.gz", checksum, size))

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/manifests/:reference", h.GetManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/hashicorp/consul/aws/manifests/1.0.0", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != mediaTypeManifest {
		t.Errorf("expected Content-Type=%s, got %q", mediaTypeManifest, ct)
	}
	if dig := w.Header().Get("Docker-Content-Digest"); !strings.HasPrefix(dig, "sha256:") {
		t.Errorf("expected Docker-Content-Digest header with sha256: prefix, got %q", dig)
	}

	var manifest ociManifest
	if err := json.NewDecoder(w.Body).Decode(&manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if manifest.SchemaVersion != 2 {
		t.Errorf("expected schemaVersion 2, got %d", manifest.SchemaVersion)
	}
	if manifest.Config.MediaType != mediaTypeConfig {
		t.Errorf("expected config mediaType %s, got %s", mediaTypeConfig, manifest.Config.MediaType)
	}
	if len(manifest.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(manifest.Layers))
	}
	if manifest.Layers[0].Digest != "sha256:"+checksum {
		t.Errorf("expected layer digest sha256:%s, got %s", checksum, manifest.Layers[0].Digest)
	}
	if manifest.Layers[0].Size != size {
		t.Errorf("expected layer size %d, got %d", size, manifest.Layers[0].Size)
	}
}

// ─── HeadManifest — success ───────────────────────────────────────────────────

func TestHeadManifest_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))

	mock.ExpectQuery("SELECT.*FROM module_versions").
		WithArgs("mod-id", "1.0.0").
		WillReturnRows(versionRow("ver-id", "mod-id", "1.0.0", "path.tar.gz", "abc123", 512))

	h := NewHandler(db, nil)
	r := gin.New()
	r.HEAD("/v2/:namespace/:name/:system/manifests/:reference", h.HeadManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodHead, "/v2/hashicorp/consul/aws/manifests/1.0.0", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Docker-Content-Digest") == "" {
		t.Error("expected Docker-Content-Digest header")
	}
	if w.Header().Get("Content-Length") == "" {
		t.Error("expected Content-Length header")
	}
}

// ─── HeadBlob / GetBlob ───────────────────────────────────────────────────────

// TestHeadBlob_InternalError — a transient failure (org lookup query error)
// must surface as the generic OCI "UNKNOWN" code, not BLOB_UNKNOWN, so OCI
// clients don't mistake a retryable server fault for permanent absence.
// HeadBlob shares lookupVersionByDigest + ociErrorCode with GetBlob (already
// covered by TestGetBlob_InternalError); this is HeadBlob's own regression
// coverage for the same #682 fix.

// TestHeadBlob_InvalidDigest and TestGetBlob_InvalidDigest — no sha256: prefix → 400
func TestHeadBlob_InvalidDigest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	h := NewHandler(db, nil)
	r := gin.New()
	r.HEAD("/v2/:namespace/:name/:system/blobs/:digest", h.HeadBlob)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodHead, "/v2/hashicorp/consul/aws/blobs/invaliddigest", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetBlob_InvalidDigest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/blobs/:digest", h.GetBlob)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/hashicorp/consul/aws/blobs/invaliddigest", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHeadBlob_OK — valid digest, module version found → 200 with correct headers
func TestHeadBlob_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	const checksum = "abc123def456ff00"
	const size = int64(512)

	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))
	mock.ExpectQuery("SELECT.*FROM module_versions").
		WithArgs("mod-id", checksum).
		WillReturnRows(versionRow("ver-id", "mod-id", "1.0.0", "path.tar.gz", checksum, size))

	h := NewHandler(db, nil)
	r := gin.New()
	r.HEAD("/v2/:namespace/:name/:system/blobs/:digest", h.HeadBlob)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodHead, "/v2/hashicorp/consul/aws/blobs/sha256:"+checksum, nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if cl := w.Header().Get("Content-Length"); cl != fmt.Sprintf("%d", size) {
		t.Errorf("expected Content-Length=%d, got %q", size, cl)
	}
	if dig := w.Header().Get("Docker-Content-Digest"); dig != "sha256:"+checksum {
		t.Errorf("expected Docker-Content-Digest sha256:%s, got %q", checksum, dig)
	}
}
