package repositories

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/analyzer"
)

func newDocsRepo(t *testing.T) (*ModuleDocsRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewModuleDocsRepository(db), mock
}

var docsCols = []string{"inputs", "outputs", "providers", "requirements"}

func sampleDocsRow() *sqlmock.Rows {
	return sqlmock.NewRows(docsCols).AddRow(
		`[{"name":"region","type":"string","required":false}]`,
		`[{"name":"vpc_id"}]`,
		`[{"name":"aws","source":"hashicorp/aws"}]`,
		`{"required_version":">= 1.0"}`,
	)
}

// ---------------------------------------------------------------------------
// UpsertModuleDocs
// ---------------------------------------------------------------------------

func TestUpsertModuleDocs_Success(t *testing.T) {
	repo, mock := newDocsRepo(t)
	doc := &analyzer.ModuleDoc{
		Inputs:  []analyzer.InputVar{{Name: "region", Type: "string"}},
		Outputs: []analyzer.OutputVal{{Name: "vpc_id"}},
		Providers: []analyzer.ProviderReq{
			{Name: "aws", Source: "hashicorp/aws", VersionConstraints: ">= 4.0"},
		},
		Requirements: &analyzer.Requirements{RequiredVersion: ">= 1.0"},
	}

	mock.ExpectExec("INSERT INTO module_version_docs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpsertModuleDocs(context.Background(), "ver-1", doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestUpsertModuleDocs_NilDoc(t *testing.T) {
	repo, mock := newDocsRepo(t)
	// Nil doc is a no-op — no DB call expected
	if err := repo.UpsertModuleDocs(context.Background(), "ver-1", nil); err != nil {
		t.Fatalf("unexpected error for nil doc: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestUpsertModuleDocs_NoRequirements(t *testing.T) {
	repo, mock := newDocsRepo(t)
	doc := &analyzer.ModuleDoc{
		Inputs:  []analyzer.InputVar{{Name: "x"}},
		Outputs: []analyzer.OutputVal{},
	}

	mock.ExpectExec("INSERT INTO module_version_docs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpsertModuleDocs(context.Background(), "ver-1", doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpsertModuleDocs_DBError(t *testing.T) {
	repo, mock := newDocsRepo(t)
	doc := &analyzer.ModuleDoc{Inputs: []analyzer.InputVar{{Name: "x"}}}
	mock.ExpectExec("INSERT INTO module_version_docs").
		WillReturnError(errors.New("db error"))

	if err := repo.UpsertModuleDocs(context.Background(), "ver-1", doc); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetModuleDocs
// ---------------------------------------------------------------------------

func TestGetModuleDocs_Found(t *testing.T) {
	repo, mock := newDocsRepo(t)
	mock.ExpectQuery("SELECT inputs, outputs, providers, requirements").
		WithArgs("ver-1").
		WillReturnRows(sampleDocsRow())

	doc, err := repo.GetModuleDocs(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
	if len(doc.Inputs) != 1 || doc.Inputs[0].Name != "region" {
		t.Errorf("unexpected inputs: %v", doc.Inputs)
	}
	if len(doc.Outputs) != 1 || doc.Outputs[0].Name != "vpc_id" {
		t.Errorf("unexpected outputs: %v", doc.Outputs)
	}
	if len(doc.Providers) != 1 || doc.Providers[0].Name != "aws" {
		t.Errorf("unexpected providers: %v", doc.Providers)
	}
	if doc.Requirements == nil || doc.Requirements.RequiredVersion == "" {
		t.Errorf("expected requirements, got %+v", doc.Requirements)
	}
}

func TestGetModuleDocs_NotFound(t *testing.T) {
	repo, mock := newDocsRepo(t)
	mock.ExpectQuery("SELECT inputs, outputs, providers, requirements").
		WithArgs("ver-99").
		WillReturnRows(sqlmock.NewRows(docsCols))

	doc, err := repo.GetModuleDocs(context.Background(), "ver-99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc != nil {
		t.Errorf("expected nil, got %+v", doc)
	}
}

func TestGetModuleDocs_DBError(t *testing.T) {
	repo, mock := newDocsRepo(t)
	mock.ExpectQuery("SELECT inputs, outputs, providers, requirements").
		WithArgs("ver-1").
		WillReturnError(errors.New("db error"))

	_, err := repo.GetModuleDocs(context.Background(), "ver-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetModuleDocs_NullRequirements(t *testing.T) {
	repo, mock := newDocsRepo(t)
	rows := sqlmock.NewRows(docsCols).AddRow(
		`[{"name":"x"}]`,
		`[]`,
		`[]`,
		nil, // NULL requirements
	)
	mock.ExpectQuery("SELECT inputs, outputs, providers, requirements").
		WithArgs("ver-1").
		WillReturnRows(rows)

	doc, err := repo.GetModuleDocs(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
	if doc.Requirements != nil {
		t.Errorf("expected nil requirements, got %+v", doc.Requirements)
	}
}

// ---------------------------------------------------------------------------
// HasDocs
// ---------------------------------------------------------------------------

func TestHasDocs_True(t *testing.T) {
	repo, mock := newDocsRepo(t)
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("ver-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	has, err := repo.HasDocs(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Error("expected true")
	}
}

func TestHasDocs_False(t *testing.T) {
	repo, mock := newDocsRepo(t)
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("ver-99").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	has, err := repo.HasDocs(context.Background(), "ver-99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("expected false")
	}
}

func TestHasDocs_DBError(t *testing.T) {
	repo, mock := newDocsRepo(t)
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("ver-1").
		WillReturnError(errors.New("db error"))

	_, err := repo.HasDocs(context.Background(), "ver-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}
