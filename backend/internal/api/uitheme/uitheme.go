// Package uitheme implements the public read and admin write handlers for the
// singleton white-label theme configuration. The frontend ThemeContext consumes
// the public GET endpoint to brand the login page (which is reached before any
// authentication), so the read endpoint is intentionally unauthenticated.
package uitheme

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Handlers holds the UI theme endpoints.
type Handlers struct {
	repo *repositories.UIThemeRepository
}

// NewHandlers constructs a Handlers backed by ui_theme_config.
func NewHandlers(db *sqlx.DB) *Handlers {
	return &Handlers{repo: repositories.NewUIThemeRepository(db)}
}

// @Summary      Get UI theme configuration
// @Description  Returns the white-label theme configuration consumed by the frontend ThemeContext. Public — no authentication required so the login page can brand itself before sign-in. Returns 404 when nothing has been configured; the frontend then falls back to its built-in defaults.
// @Tags         UI Theme
// @Produce      json
// @Success      200  {object}  models.UIThemeConfig
// @Failure      404  {object}  map[string]interface{}  "Theme has not been configured"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/ui/theme [get]
func (h *Handlers) GetTheme() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := h.repo.Get(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load ui theme"})
			return
		}
		if cfg == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "ui theme not configured"})
			return
		}
		c.Header("Cache-Control", "public, max-age=60")
		c.JSON(http.StatusOK, cfg)
	}
}

// @Summary      Upsert UI theme configuration
// @Description  Writes the white-label theme used by the frontend. Accepts the same shape returned by GET /api/v1/ui/theme. Accessible to admin scope or via a valid setup token (used by the setup wizard's BrandingStep). Color fields must be `#RGB` or `#RRGGBB`. URL fields must be absolute https URLs or relative paths beginning with `/`.
// @Tags         UI Theme
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.UIThemeConfig  true  "Theme configuration"
// @Success      200  {object}  models.UIThemeConfig
// @Failure      400  {object}  map[string]interface{}  "Invalid input"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/ui-theme [put]
func (h *Handlers) PutTheme() gin.HandlerFunc {
	return func(c *gin.Context) {
		var in models.UIThemeConfig
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validateTheme(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		saved, err := h.repo.Upsert(c.Request.Context(), &in)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save ui theme"})
			return
		}
		c.JSON(http.StatusOK, saved)
	}
}

var (
	// `#RGB` or `#RRGGBB` (case-insensitive).
	reHexColor = regexp.MustCompile(`^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$`)

	// Disallow values that could escape an `<img src>` or CSS variable into JS.
	// We accept absolute https URLs (no inline scripts) or relative paths
	// (must start with `/`). Anything else is rejected.
	errBadURL = errors.New("must be an https:// URL or a relative path starting with /")
)

func validateTheme(in *models.UIThemeConfig) error {
	colorFields := []struct {
		name string
		val  *string
	}{
		{"primary_color", in.PrimaryColor},
		{"secondary_color_light", in.SecondaryColorLight},
		{"secondary_color_dark", in.SecondaryColorDark},
	}
	for _, f := range colorFields {
		if f.val == nil || *f.val == "" {
			continue
		}
		if !reHexColor.MatchString(*f.val) {
			return fmt.Errorf("%s: must be a hex color like #5C4EE5 or #abc", f.name)
		}
	}

	urlFields := []struct {
		name string
		val  *string
	}{
		{"logo_url", in.LogoURL},
		{"favicon_url", in.FaviconURL},
		{"login_hero_url", in.LoginHeroURL},
	}
	for _, f := range urlFields {
		if f.val == nil || *f.val == "" {
			continue
		}
		if err := validateURL(*f.val); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}

	if in.ProductName != nil {
		if len(*in.ProductName) > 200 {
			return errors.New("product_name: must be 200 characters or fewer")
		}
	}
	return nil
}

func validateURL(s string) error {
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return nil
	}
	if strings.HasPrefix(s, "https://") && !strings.ContainsAny(s, "\"' \t\n\r<>") {
		return nil
	}
	return errBadURL
}
