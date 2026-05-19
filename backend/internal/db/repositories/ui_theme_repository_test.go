package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func newUIThemeRepo(t *testing.T) (*UIThemeRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewUIThemeRepository(sqlx.NewDb(db, "postgres")), mock
}

var uiThemeCols = []string{
	"product_name", "primary_color", "secondary_color_light", "secondary_color_dark",
	"logo_url", "favicon_url", "login_hero_url", "updated_at",
}

func TestUIThemeRepo_Get_NoRow(t *testing.T) {
	repo, mock := newUIThemeRepo(t)
	mock.ExpectQuery(`SELECT.*FROM ui_theme_config`).
		WillReturnRows(sqlmock.NewRows(uiThemeCols))

	got, err := repo.Get(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestUIThemeRepo_Get_Found(t *testing.T) {
	repo, mock := newUIThemeRepo(t)
	product := "Acme"
	mock.ExpectQuery(`SELECT.*FROM ui_theme_config`).
		WillReturnRows(sqlmock.NewRows(uiThemeCols).
			AddRow(product, "#5C4EE5", nil, nil, nil, nil, nil, time.Now()))

	got, err := repo.Get(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ProductName == nil || *got.ProductName != product {
		t.Fatalf("unexpected row: %+v", got)
	}
}

func TestUIThemeRepo_Get_DBError(t *testing.T) {
	repo, mock := newUIThemeRepo(t)
	mock.ExpectQuery(`SELECT.*FROM ui_theme_config`).
		WillReturnError(fmt.Errorf("db error"))

	if _, err := repo.Get(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUIThemeRepo_Upsert_Success(t *testing.T) {
	repo, mock := newUIThemeRepo(t)
	product := "Acme"
	mock.ExpectQuery(`INSERT INTO ui_theme_config`).
		WillReturnRows(sqlmock.NewRows(uiThemeCols).
			AddRow(product, nil, nil, nil, nil, nil, nil, time.Now()))

	got, err := repo.Upsert(context.Background(), &models.UIThemeConfig{ProductName: &product})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ProductName == nil || *got.ProductName != product {
		t.Fatalf("unexpected returned row: %+v", got)
	}
}

func TestUIThemeRepo_Upsert_DBError(t *testing.T) {
	repo, mock := newUIThemeRepo(t)
	mock.ExpectQuery(`INSERT INTO ui_theme_config`).
		WillReturnError(fmt.Errorf("db error"))

	if _, err := repo.Upsert(context.Background(), &models.UIThemeConfig{}); err == nil {
		t.Fatal("expected error, got nil")
	}
}
