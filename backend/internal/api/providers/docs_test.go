package providers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// Column definitions for docs handler tests
// ---------------------------------------------------------------------------

// GetProviderByNamespaceType (single-tenant / empty orgID): 8 columns
var docsProviderCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_at", "updated_at",
}

// provider version row (GetVersion): id, provider_id, version, protocols, gpg_key, shasums_url, shasums_sig_url, published_by, deprecated, deprecated_at, deprecation_message, created_at
var docsVersionCols = []string{
	"id", "provider_id", "version", "protocols", "gpg_public_key",
	"shasums_url", "shasums_signature_url", "published_by",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
}

// doc entry row: id, provider_version_id, upstream_doc_id, title, slug, category, subcategory, path, language
var docsDocCols = []string{
	"id", "provider_version_id", "upstream_doc_id",
	"title", "slug", "category", "subcategory", "path", "language",
}

// ---------------------------------------------------------------------------
// ListProviderDocsHandler
// ---------------------------------------------------------------------------

func TestListProviderDocsHandler_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// GetProviderByNamespaceType
	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("hashicorp", "random").
		WillReturnRows(sqlmock.NewRows(docsProviderCols).
			AddRow("prov-1", nil, "hashicorp", "random", nil, "https://registry.terraform.io/hashicorp/random", time.Now(), time.Now()))

	// GetVersion
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WithArgs("prov-1", "3.6.0").
		WillReturnRows(sqlmock.NewRows(docsVersionCols).
			AddRow("ver-1", "prov-1", "3.6.0", []byte(`["5.0"]`), "", "", "", nil, false, nil, nil, time.Now()))

	// ListProviderVersionDocsPaginated — COUNT query
	mock.ExpectQuery("SELECT COUNT.*FROM provider_version_docs").
		WithArgs("ver-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// ListProviderVersionDocsPaginated — data query with LIMIT/OFFSET
	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", 100, 0).
		WillReturnRows(sqlmock.NewRows(docsDocCols).
			AddRow("d1", "ver-1", "101", "overview", "index", "overview", nil, "docs/index.md", "hcl").
			AddRow("d2", "ver-1", "102", "random_id", "random_id", "resources", nil, "docs/resources/random_id.md", "hcl"))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{
		{Key: "namespace", Value: "hashicorp"},
		{Key: "type", Value: "random"},
		{Key: "version", Value: "3.6.0"},
	}
	c.Request = httptest.NewRequest("GET", "/api/v1/providers/hashicorp/random/versions/3.6.0/docs", nil)

	handler := ListProviderDocsHandler(db)
	handler(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp ProviderDocsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Docs) != 2 {
		t.Errorf("docs count = %d, want 2", len(resp.Docs))
	}
	if len(resp.Categories) != 2 {
		t.Errorf("categories count = %d, want 2", len(resp.Categories))
	}
}

func TestListProviderDocsHandler_ProviderNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// GetProviderByNamespaceType returns no rows
	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("acme", "nonexistent").
		WillReturnRows(sqlmock.NewRows(docsProviderCols))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{
		{Key: "namespace", Value: "acme"},
		{Key: "type", Value: "nonexistent"},
		{Key: "version", Value: "1.0.0"},
	}
	c.Request = httptest.NewRequest("GET", "/api/v1/providers/acme/nonexistent/versions/1.0.0/docs", nil)

	handler := ListProviderDocsHandler(db)
	handler(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListProviderDocsHandler_VersionNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// Provider found
	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("hashicorp", "random").
		WillReturnRows(sqlmock.NewRows(docsProviderCols).
			AddRow("prov-1", nil, "hashicorp", "random", nil, nil, time.Now(), time.Now()))

	// Version not found
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WithArgs("prov-1", "99.0.0").
		WillReturnRows(sqlmock.NewRows(docsVersionCols))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{
		{Key: "namespace", Value: "hashicorp"},
		{Key: "type", Value: "random"},
		{Key: "version", Value: "99.0.0"},
	}
	c.Request = httptest.NewRequest("GET", "/api/v1/providers/hashicorp/random/versions/99.0.0/docs", nil)

	handler := ListProviderDocsHandler(db)
	handler(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListProviderDocsHandler_EmptyDocs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("hashicorp", "random").
		WillReturnRows(sqlmock.NewRows(docsProviderCols).
			AddRow("prov-1", nil, "hashicorp", "random", nil, nil, time.Now(), time.Now()))

	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WithArgs("prov-1", "3.6.0").
		WillReturnRows(sqlmock.NewRows(docsVersionCols).
			AddRow("ver-1", "prov-1", "3.6.0", []byte(`["5.0"]`), "", "", "", nil, false, nil, nil, time.Now()))

	// ListProviderVersionDocsPaginated — COUNT query
	mock.ExpectQuery("SELECT COUNT.*FROM provider_version_docs").
		WithArgs("ver-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// ListProviderVersionDocsPaginated — data query with LIMIT/OFFSET
	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", 100, 0).
		WillReturnRows(sqlmock.NewRows(docsDocCols))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{
		{Key: "namespace", Value: "hashicorp"},
		{Key: "type", Value: "random"},
		{Key: "version", Value: "3.6.0"},
	}
	c.Request = httptest.NewRequest("GET", "/api/v1/providers/hashicorp/random/versions/3.6.0/docs", nil)

	handler := ListProviderDocsHandler(db)
	handler(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp ProviderDocsListResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Docs) != 0 {
		t.Errorf("docs count = %d, want 0", len(resp.Docs))
	}
}

// ---------------------------------------------------------------------------
// GetProviderDocContentHandler
// ---------------------------------------------------------------------------

func TestGetProviderDocContentHandler_ProviderNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("acme", "nonexistent").
		WillReturnRows(sqlmock.NewRows(docsProviderCols))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{
		{Key: "namespace", Value: "acme"},
		{Key: "type", Value: "nonexistent"},
		{Key: "version", Value: "1.0.0"},
		{Key: "category", Value: "overview"},
		{Key: "slug", Value: "index"},
	}
	c.Request = httptest.NewRequest("GET", "/api/v1/providers/acme/nonexistent/versions/1.0.0/docs/overview/index", nil)

	cfg := &config.Config{}
	handler := GetProviderDocContentHandler(db, cfg)
	handler(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetProviderDocContentHandler_DocNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// Provider found
	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("hashicorp", "random").
		WillReturnRows(sqlmock.NewRows(docsProviderCols).
			AddRow("prov-1", nil, "hashicorp", "random", nil, nil, time.Now(), time.Now()))

	// Version found
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WithArgs("prov-1", "3.6.0").
		WillReturnRows(sqlmock.NewRows(docsVersionCols).
			AddRow("ver-1", "prov-1", "3.6.0", []byte(`["5.0"]`), "", "", "", nil, false, nil, nil, time.Now()))

	// Doc slug not found
	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", "overview", "nonexistent").
		WillReturnRows(sqlmock.NewRows(docsDocCols))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{
		{Key: "namespace", Value: "hashicorp"},
		{Key: "type", Value: "random"},
		{Key: "version", Value: "3.6.0"},
		{Key: "category", Value: "overview"},
		{Key: "slug", Value: "nonexistent"},
	}
	c.Request = httptest.NewRequest("GET", "/api/v1/providers/hashicorp/random/versions/3.6.0/docs/overview/nonexistent", nil)

	cfg := &config.Config{}
	handler := GetProviderDocContentHandler(db, cfg)
	handler(c)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// docContentCache
// ---------------------------------------------------------------------------

func TestDocContentCache_SetAndGet(t *testing.T) {
	cache := newDocContentCache(10, 15*time.Minute)

	cache.set("key1", "content1")
	content, ok := cache.get("key1")
	if !ok {
		t.Error("expected cache hit")
	}
	if content != "content1" {
		t.Errorf("content = %q, want content1", content)
	}
}

func TestDocContentCache_Miss(t *testing.T) {
	cache := newDocContentCache(10, 15*time.Minute)

	_, ok := cache.get("nonexistent")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestDocContentCache_Expiry(t *testing.T) {
	cache := newDocContentCache(10, 1*time.Millisecond)

	cache.set("key1", "content1")
	time.Sleep(5 * time.Millisecond)

	_, ok := cache.get("key1")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestDocContentCache_Eviction(t *testing.T) {
	cache := newDocContentCache(2, 15*time.Minute)

	cache.set("key1", "content1")
	time.Sleep(time.Millisecond) // ensure key1 has a strictly older timestamp on low-resolution timers
	cache.set("key2", "content2")
	cache.set("key3", "content3") // should evict key1

	_, ok := cache.get("key1")
	if ok {
		t.Error("expected key1 to be evicted")
	}

	content, ok := cache.get("key3")
	if !ok {
		t.Error("expected cache hit for key3")
	}
	if content != "content3" {
		t.Errorf("content = %q, want content3", content)
	}
}
