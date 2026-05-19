// ui_theme.go defines the model for the singleton white-label theme configuration
// stored in the ui_theme_config table. All fields are optional pointers — a nil
// value means "no override; use the built-in frontend default".
package models

import "time"

// UIThemeConfig is the singleton white-label theme row.
//
// The shape matches the frontend `UIThemeConfig` TypeScript interface consumed
// by ThemeContext and BrandingStep.
type UIThemeConfig struct {
	ProductName         *string   `json:"product_name,omitempty"          db:"product_name"`
	PrimaryColor        *string   `json:"primary_color,omitempty"         db:"primary_color"`
	SecondaryColorLight *string   `json:"secondary_color_light,omitempty" db:"secondary_color_light"`
	SecondaryColorDark  *string   `json:"secondary_color_dark,omitempty"  db:"secondary_color_dark"`
	LogoURL             *string   `json:"logo_url,omitempty"              db:"logo_url"`
	FaviconURL          *string   `json:"favicon_url,omitempty"           db:"favicon_url"`
	LoginHeroURL        *string   `json:"login_hero_url,omitempty"        db:"login_hero_url"`
	UpdatedAt           time.Time `json:"updated_at"                      db:"updated_at"`
}
