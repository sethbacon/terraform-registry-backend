package oci

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// Issue #755 — a manifest was fetchable only by tag, never by its own digest.
//
// The OCI Distribution Spec requires both, and standard tooling relies on the
// digest form for pinned and verified pulls. Every reference went to
// GetVersion, whose query is `WHERE version = $2` against the semver column, so
// a "sha256:..." reference could never match a row — including the exact digest
// this server had just returned in Docker-Content-Digest.
//
// A second, related gap: the manifest advertises a config descriptor whose
// digest is sha256("{}"), but blob resolution matches the module ARCHIVE
// checksum, so that descriptor was permanently BLOB_UNKNOWN. A client pulling
// the config this server named got a 404 for it.

const (
	testChecksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	testSize     = int64(4096)
)

// expectedManifestDigest computes what the server will advertise, the same way
// the server does — via the production marshaller, so a change to the manifest
// shape moves both together rather than making this test lie.
func expectedManifestDigest(t *testing.T) string {
	t.Helper()
	data, err := marshalManifest(&models.ModuleVersion{
		Checksum: testChecksum, SizeBytes: testSize,
	})
	if err != nil {
		t.Fatalf("marshalManifest: %v", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

// listVersionRow matches ListVersions' projection, which is WIDER than the
// shared versionRow helper: it LEFT JOINs users for published_by_name and
// module_version_docs for has_docs. Using versionRow here produces a scan error
// that surfaces as a 500, which reads like a handler bug and is a fixture bug.
func listVersionRow(id, moduleID, version, storagePath, checksum string, sizeBytes int64) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{
		"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes", "checksum", "readme",
		"published_by", "published_by_name", "download_count",
		"deprecated", "deprecated_at", "deprecation_message", "replacement_source", "created_at",
		"commit_sha", "tag_name", "scm_repo_id", "has_docs",
	}).AddRow(id, moduleID, version, storagePath, "local", sizeBytes, checksum, "",
		nil, nil, 0,
		false, nil, nil, nil, now,
		nil, nil, nil, false)
}

// TestGetManifest_ByDigest is the regression: the digest the server advertises
// must resolve.
func TestGetManifest_ByDigest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	digest := expectedManifestDigest(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").WillReturnRows(orgRow("org-id", "default"))
	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("org-id", "hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))
	// A digest reference lists the module's versions and recomputes; it must NOT
	// query by version string, which is what always 404'd.
	mock.ExpectQuery("SELECT.*FROM module_versions").
		WithArgs("mod-id").
		WillReturnRows(listVersionRow("ver-id", "mod-id", "1.0.0", "modules/x.tar.gz", testChecksum, testSize))

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/manifests/:reference", h.GetManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/hashicorp/consul/aws/manifests/"+digest, nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("pull by digest = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// And the digest it returns must be the one that was asked for, or the
	// round trip a verified pull performs does not close.
	if got := w.Header().Get("Docker-Content-Digest"); got != digest {
		t.Errorf("Docker-Content-Digest = %q, want %q", got, digest)
	}
}

// TestGetManifest_ByUnknownDigestIs404 — a digest that matches no version must
// still be MANIFEST_UNKNOWN, not a match on some other version.
func TestGetManifest_ByUnknownDigestIs404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").WillReturnRows(orgRow("org-id", "default"))
	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("org-id", "hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))
	mock.ExpectQuery("SELECT.*FROM module_versions").
		WithArgs("mod-id").
		WillReturnRows(listVersionRow("ver-id", "mod-id", "1.0.0", "modules/x.tar.gz", testChecksum, testSize))

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/manifests/:reference", h.GetManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet,
		"/v2/hashicorp/consul/aws/manifests/sha256:"+strings.Repeat("00", 32), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown digest = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

// TestGetManifest_ByTagStillWorks — the digest path must not have displaced the
// tag path, which is how every existing client pulls.
func TestGetManifest_ByTagStillWorks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").WillReturnRows(orgRow("org-id", "default"))
	mock.ExpectQuery("SELECT.*FROM modules").
		WithArgs("org-id", "hashicorp", "consul", "aws").
		WillReturnRows(moduleRow("mod-id", "org-id", "hashicorp", "consul", "aws"))
	// By TAG: an exact-version query, not a list.
	mock.ExpectQuery("SELECT.*FROM module_versions.*version = ").
		WithArgs("mod-id", "1.0.0").
		WillReturnRows(versionRow("ver-id", "mod-id", "1.0.0", "modules/x.tar.gz", testChecksum, testSize))

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/manifests/:reference", h.GetManifest)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v2/hashicorp/consul/aws/manifests/1.0.0", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("pull by tag = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Docker-Content-Digest"); got != expectedManifestDigest(t) {
		t.Errorf("Docker-Content-Digest = %q, want the manifest digest", got)
	}
}

// TestGetBlob_ServesTheAdvertisedConfig — the manifest names a config
// descriptor; pulling it must work.
//
// It is a constant, so it never appears in module_versions.checksum and the
// archive lookup could never find it. No database query should be issued at
// all, which is asserted by registering no expectations.
func TestGetBlob_ServesTheAdvertisedConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	h := NewHandler(db, nil)
	r := gin.New()
	r.GET("/v2/:namespace/:name/:system/blobs/:digest", h.GetBlob)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet,
		"/v2/hashicorp/consul/aws/blobs/"+ociConfigDigest(), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("config blob = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != string(ociConfigBlob) {
		t.Errorf("config blob body = %q, want %q", body, string(ociConfigBlob))
	}
	// The digest the client asked for must be what it got, or verification fails.
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256(w.Body.Bytes())); got != ociConfigDigest() {
		t.Errorf("served config hashes to %q, but it is advertised as %q", got, ociConfigDigest())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the constant config blob should need no database query: %v", err)
	}
}

// TestHeadBlob_ServesTheAdvertisedConfig — OCI clients HEAD before pulling, so
// a HEAD that 404s on an object GET serves is its own inconsistency.
func TestHeadBlob_ServesTheAdvertisedConfig(t *testing.T) {
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
	req, _ := http.NewRequest(http.MethodHead,
		"/v2/hashicorp/consul/aws/blobs/"+ociConfigDigest(), nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HEAD config blob = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Docker-Content-Digest"); got != ociConfigDigest() {
		t.Errorf("Docker-Content-Digest = %q, want %q", got, ociConfigDigest())
	}
}

// TestOCIConfigDigest_IsTheKnownConstant pins the value. If the config object
// ever changes, the manifest's advertised digest and the blob route must move
// together — this fails loudly rather than letting them drift apart.
func TestOCIConfigDigest_IsTheKnownConstant(t *testing.T) {
	const known = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if got := ociConfigDigest(); got != known {
		t.Errorf("ociConfigDigest() = %q, want sha256(\"{}\") = %q", got, known)
	}
}
