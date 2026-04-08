package repositories

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var provDocCols = []string{
	"id", "provider_version_id", "upstream_doc_id",
	"title", "slug", "category", "subcategory", "path", "language",
}

// ---------------------------------------------------------------------------
// BulkCreateProviderVersionDocs
// ---------------------------------------------------------------------------

func TestBulkCreateProviderVersionDocs_Empty(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewProviderDocsRepository(db)
	if err := repo.BulkCreateProviderVersionDocs(context.Background(), "ver-1", nil); err != nil {
		t.Errorf("empty slice should not error: %v", err)
	}
}

func TestBulkCreateProviderVersionDocs_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO provider_version_docs").
		WithArgs(
			"ver-1", "101", "overview", "index", "overview", nil, sqlmock.AnyArg(), "hcl",
			"ver-1", "102", "random_id", "random_id", "resources", nil, sqlmock.AnyArg(), "hcl",
		).
		WillReturnResult(sqlmock.NewResult(0, 2))

	repo := NewProviderDocsRepository(db)
	path1 := "docs/index.md"
	path2 := "docs/resources/random_id.md"
	docs := []models.ProviderVersionDoc{
		{UpstreamDocID: "101", Title: "overview", Slug: "index", Category: "overview", Path: &path1, Language: "hcl"},
		{UpstreamDocID: "102", Title: "random_id", Slug: "random_id", Category: "resources", Path: &path2, Language: "hcl"},
	}

	if err := repo.BulkCreateProviderVersionDocs(context.Background(), "ver-1", docs); err != nil {
		t.Fatalf("BulkCreateProviderVersionDocs error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestBulkCreateProviderVersionDocs_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO provider_version_docs").
		WillReturnError(errDB)

	repo := NewProviderDocsRepository(db)
	docs := []models.ProviderVersionDoc{
		{UpstreamDocID: "101", Title: "overview", Slug: "index", Category: "overview", Language: "hcl"},
	}

	if err := repo.BulkCreateProviderVersionDocs(context.Background(), "ver-1", docs); err == nil {
		t.Error("expected error on DB failure")
	}
}

// ---------------------------------------------------------------------------
// ListProviderVersionDocs
// ---------------------------------------------------------------------------

func TestListProviderVersionDocs_NoFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows(provDocCols).
		AddRow("d1", "ver-1", "101", "overview", "index", "overview", nil, "docs/index.md", "hcl").
		AddRow("d2", "ver-1", "102", "random_id", "random_id", "resources", nil, "docs/resources/random_id.md", "hcl")
	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1").
		WillReturnRows(rows)

	repo := NewProviderDocsRepository(db)
	docs, err := repo.ListProviderVersionDocs(context.Background(), "ver-1", nil, nil)
	if err != nil {
		t.Fatalf("ListProviderVersionDocs error: %v", err)
	}
	if len(docs) != 2 {
		t.Errorf("got %d docs, want 2", len(docs))
	}
}

func TestListProviderVersionDocs_WithCategoryFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows(provDocCols).
		AddRow("d1", "ver-1", "101", "overview", "index", "overview", nil, "docs/index.md", "hcl")
	category := "overview"
	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", "overview").
		WillReturnRows(rows)

	repo := NewProviderDocsRepository(db)
	docs, err := repo.ListProviderVersionDocs(context.Background(), "ver-1", &category, nil)
	if err != nil {
		t.Fatalf("ListProviderVersionDocs error: %v", err)
	}
	if len(docs) != 1 {
		t.Errorf("got %d docs, want 1", len(docs))
	}
	if docs[0].Category != "overview" {
		t.Errorf("category = %q, want overview", docs[0].Category)
	}
}

func TestListProviderVersionDocs_WithBothFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows(provDocCols)
	category := "resources"
	language := "python"
	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", "resources", "python").
		WillReturnRows(rows)

	repo := NewProviderDocsRepository(db)
	docs, err := repo.ListProviderVersionDocs(context.Background(), "ver-1", &category, &language)
	if err != nil {
		t.Fatalf("ListProviderVersionDocs error: %v", err)
	}
	if len(docs) != 0 {
		t.Errorf("got %d docs, want 0", len(docs))
	}
}

func TestListProviderVersionDocs_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WillReturnError(errDB)

	repo := NewProviderDocsRepository(db)
	_, err = repo.ListProviderVersionDocs(context.Background(), "ver-1", nil, nil)
	if err == nil {
		t.Error("expected error on DB failure")
	}
}

// ---------------------------------------------------------------------------
// GetProviderVersionDocBySlug
// ---------------------------------------------------------------------------

func TestGetProviderVersionDocBySlug_Found(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows(provDocCols).
		AddRow("d1", "ver-1", "101", "overview", "index", "overview", nil, "docs/index.md", "hcl")
	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", "overview", "index").
		WillReturnRows(rows)

	repo := NewProviderDocsRepository(db)
	doc, err := repo.GetProviderVersionDocBySlug(context.Background(), "ver-1", "overview", "index")
	if err != nil {
		t.Fatalf("GetProviderVersionDocBySlug error: %v", err)
	}
	if doc == nil {
		t.Fatal("expected doc, got nil")
	}
	if doc.UpstreamDocID != "101" {
		t.Errorf("upstream_doc_id = %q, want 101", doc.UpstreamDocID)
	}
}

func TestGetProviderVersionDocBySlug_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", "overview", "nonexistent").
		WillReturnRows(sqlmock.NewRows(provDocCols))

	repo := NewProviderDocsRepository(db)
	doc, err := repo.GetProviderVersionDocBySlug(context.Background(), "ver-1", "overview", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc != nil {
		t.Errorf("expected nil doc for nonexistent slug, got %+v", doc)
	}
}

func TestGetProviderVersionDocBySlug_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WillReturnError(errDB)

	repo := NewProviderDocsRepository(db)
	_, err = repo.GetProviderVersionDocBySlug(context.Background(), "ver-1", "overview", "index")
	if err == nil {
		t.Error("expected error on DB failure")
	}
}

// ---------------------------------------------------------------------------
// DeleteProviderVersionDocs
// ---------------------------------------------------------------------------

func TestDeleteProviderVersionDocs_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM provider_version_docs").
		WithArgs("ver-1").
		WillReturnResult(sqlmock.NewResult(0, 5))

	repo := NewProviderDocsRepository(db)
	if err := repo.DeleteProviderVersionDocs(context.Background(), "ver-1"); err != nil {
		t.Errorf("DeleteProviderVersionDocs error: %v", err)
	}
}

func TestDeleteProviderVersionDocs_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM provider_version_docs").
		WillReturnError(errDB)

	repo := NewProviderDocsRepository(db)
	if err := repo.DeleteProviderVersionDocs(context.Background(), "ver-1"); err == nil {
		t.Error("expected error on DB failure")
	}
}

// ---------------------------------------------------------------------------
// ListProviderVersionDocsPaginated
// ---------------------------------------------------------------------------

func TestListProviderVersionDocsPaginated_NoFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewProviderDocsRepository(db)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("ver-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", 10, 0).
		WillReturnRows(sqlmock.NewRows(provDocCols).
			AddRow("doc-1", "ver-1", "101", "Overview", "index", "overview", nil, "path/index.mdx", "hcl"))

	docs, total, err := repo.ListProviderVersionDocsPaginated(context.Background(), "ver-1", nil, nil, 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(docs) != 1 {
		t.Errorf("len = %d, want 1", len(docs))
	}
}

func TestListProviderVersionDocsPaginated_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewProviderDocsRepository(db)

	cat := "resources"
	lang := "hcl"

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("ver-1", "resources", "hcl").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	mock.ExpectQuery("SELECT.*FROM provider_version_docs").
		WithArgs("ver-1", "resources", "hcl", 10, 0).
		WillReturnRows(sqlmock.NewRows(provDocCols).
			AddRow("doc-1", "ver-1", "101", "Random ID", "random_id", "resources", nil, "path/resources/random_id.mdx", "hcl").
			AddRow("doc-2", "ver-1", "102", "UUID", "uuid", "resources", nil, "path/resources/uuid.mdx", "hcl"))

	docs, total, err := repo.ListProviderVersionDocsPaginated(context.Background(), "ver-1", &cat, &lang, 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(docs) != 2 {
		t.Errorf("len = %d, want 2", len(docs))
	}
}

func TestListProviderVersionDocsPaginated_CountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewProviderDocsRepository(db)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("ver-1").
		WillReturnError(errDB)

	_, _, err = repo.ListProviderVersionDocsPaginated(context.Background(), "ver-1", nil, nil, 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// CountProviderVersionDocs
// ---------------------------------------------------------------------------

func TestCountProviderVersionDocs_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewProviderDocsRepository(db)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("ver-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	count, err := repo.CountProviderVersionDocs(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 5 {
		t.Errorf("count = %d, want 5", count)
	}
}

func TestCountProviderVersionDocs_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewProviderDocsRepository(db)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("ver-err").
		WillReturnError(errDB)

	_, err = repo.CountProviderVersionDocs(context.Background(), "ver-err")
	if err == nil {
		t.Error("expected error, got nil")
	}
}
