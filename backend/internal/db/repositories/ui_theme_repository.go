// ui_theme_repository.go is the persistence layer for the singleton ui_theme_config
// row. Get returns nil/nil when no row has been written yet so the handler can
// distinguish "not set" (404 → frontend uses built-in defaults) from a real error.
package repositories

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// UIThemeRepository handles reads and upserts against ui_theme_config.
type UIThemeRepository struct {
	db *sqlx.DB
}

// NewUIThemeRepository constructs a UIThemeRepository.
func NewUIThemeRepository(db *sqlx.DB) *UIThemeRepository {
	return &UIThemeRepository{db: db}
}

// Get returns the singleton theme row, or nil if it hasn't been written.
func (r *UIThemeRepository) Get(ctx context.Context) (*models.UIThemeConfig, error) {
	var cfg models.UIThemeConfig
	query := `
		SELECT product_name, primary_color, secondary_color_light, secondary_color_dark,
		       logo_url, favicon_url, login_hero_url, updated_at
		FROM ui_theme_config
		WHERE id = 1
	`
	err := r.db.GetContext(ctx, &cfg, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Upsert writes (or replaces) the singleton theme row. Returns the saved row.
func (r *UIThemeRepository) Upsert(ctx context.Context, in *models.UIThemeConfig) (*models.UIThemeConfig, error) {
	query := `
		INSERT INTO ui_theme_config (
			id, product_name, primary_color, secondary_color_light, secondary_color_dark,
			logo_url, favicon_url, login_hero_url, updated_at
		) VALUES (
			1, $1, $2, $3, $4, $5, $6, $7, NOW()
		)
		ON CONFLICT (id) DO UPDATE SET
			product_name          = EXCLUDED.product_name,
			primary_color         = EXCLUDED.primary_color,
			secondary_color_light = EXCLUDED.secondary_color_light,
			secondary_color_dark  = EXCLUDED.secondary_color_dark,
			logo_url              = EXCLUDED.logo_url,
			favicon_url           = EXCLUDED.favicon_url,
			login_hero_url        = EXCLUDED.login_hero_url,
			updated_at            = NOW()
		RETURNING product_name, primary_color, secondary_color_light, secondary_color_dark,
		          logo_url, favicon_url, login_hero_url, updated_at
	`
	var out models.UIThemeConfig
	err := r.db.QueryRowxContext(ctx, query,
		in.ProductName, in.PrimaryColor, in.SecondaryColorLight, in.SecondaryColorDark,
		in.LogoURL, in.FaviconURL, in.LoginHeroURL,
	).StructScan(&out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
