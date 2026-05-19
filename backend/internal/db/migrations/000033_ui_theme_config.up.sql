-- 000033_ui_theme_config.up.sql
-- Single-row table holding the white-label theme configuration consumed by the
-- frontend (ThemeContext) and written by the setup wizard / admin UI.
-- The id=1 CHECK enforces the singleton invariant.

CREATE TABLE IF NOT EXISTS ui_theme_config (
    id                      INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    product_name            TEXT,
    primary_color           TEXT,
    secondary_color_light   TEXT,
    secondary_color_dark    TEXT,
    logo_url                TEXT,
    favicon_url             TEXT,
    login_hero_url          TEXT,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
