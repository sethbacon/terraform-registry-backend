package repositories

import (
	"context"
	"fmt"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
)

func newOrgQuotaRepo(t *testing.T) (*OrgQuotaRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewOrgQuotaRepository(sqlx.NewDb(db, "postgres")), mock
}

var orgQuotaCols = []string{
	"organization_id", "storage_bytes_limit", "publishes_per_day", "downloads_per_day",
	"storage_bytes_used", "publishes_today", "downloads_today",
}

func TestOrgQuotaRepo_List_Empty(t *testing.T) {
	repo, mock := newOrgQuotaRepo(t)
	mock.ExpectQuery(`FROM organizations`).
		WillReturnRows(sqlmock.NewRows(orgQuotaCols))

	got, err := repo.ListQuotaStatuses(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(got))
	}
}

func TestOrgQuotaRepo_List_WithRows_Ratios(t *testing.T) {
	repo, mock := newOrgQuotaRepo(t)
	mock.ExpectQuery(`FROM organizations`).
		WillReturnRows(sqlmock.NewRows(orgQuotaCols).
			AddRow("org-1", 1000, 100, 200, 500, 50, 50).
			AddRow("org-2", 0, 0, 0, 9999, 9, 9))

	got, err := repo.ListQuotaStatuses(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(got))
	}
	if got[0].StorageRatio != 0.5 || got[0].PublishRatio != 0.5 || got[0].DownloadRatio != 0.25 {
		t.Errorf("org-1 ratios = %+v", got[0])
	}
	// limit=0 => ratio=0 (unlimited).
	if got[1].StorageRatio != 0 || got[1].PublishRatio != 0 || got[1].DownloadRatio != 0 {
		t.Errorf("org-2 ratios = %+v", got[1])
	}
}

func TestOrgQuotaRepo_List_OrgFilter(t *testing.T) {
	repo, mock := newOrgQuotaRepo(t)
	mock.ExpectQuery(`FROM organizations`).
		WithArgs("org-only").
		WillReturnRows(sqlmock.NewRows(orgQuotaCols).
			AddRow("org-only", 200, 20, 20, 10, 1, 2))

	got, err := repo.ListQuotaStatuses(context.Background(), "org-only")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].OrganizationID != "org-only" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestOrgQuotaRepo_List_DBError(t *testing.T) {
	repo, mock := newOrgQuotaRepo(t)
	mock.ExpectQuery(`FROM organizations`).
		WillReturnError(fmt.Errorf("db error"))

	if _, err := repo.ListQuotaStatuses(context.Background(), ""); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestOrgQuotaRepo_Ratio(t *testing.T) {
	cases := []struct {
		name        string
		used, limit int64
		want        float64
	}{
		{"unlimited", 100, 0, 0},
		{"negative limit treated as unlimited", 100, -1, 0},
		{"half used", 50, 100, 0.5},
		{"over limit", 200, 100, 2.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ratio(tc.used, tc.limit)
			if got != tc.want {
				t.Errorf("ratio(%d,%d) = %v, want %v", tc.used, tc.limit, got, tc.want)
			}
		})
	}
}
