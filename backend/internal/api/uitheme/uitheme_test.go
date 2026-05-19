package uitheme

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func newTestRouter(t *testing.T) (*Handlers, *gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sqlxDB := sqlx.NewDb(db, "postgres")
	h := NewHandlers(sqlxDB)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ui/theme", h.GetTheme())
	r.PUT("/admin/ui-theme", h.PutTheme())
	return h, r, mock
}

func TestGetTheme_NotConfigured_404(t *testing.T) {
	_, r, mock := newTestRouter(t)
	mock.ExpectQuery(`SELECT.*FROM ui_theme_config`).
		WillReturnError(sqlNoRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/ui/theme", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetTheme_Success(t *testing.T) {
	_, r, mock := newTestRouter(t)
	product := "Acme Registry"
	primary := "#5C4EE5"
	cols := []string{
		"product_name", "primary_color", "secondary_color_light", "secondary_color_dark",
		"logo_url", "favicon_url", "login_hero_url", "updated_at",
	}
	mock.ExpectQuery(`SELECT.*FROM ui_theme_config`).
		WillReturnRows(mock.NewRows(cols).AddRow(product, primary, nil, nil, nil, nil, nil, fixedTime()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/ui/theme", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp models.UIThemeConfig
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ProductName == nil || *resp.ProductName != product {
		t.Fatalf("product_name = %v, want %s", resp.ProductName, product)
	}
	if resp.PrimaryColor == nil || *resp.PrimaryColor != primary {
		t.Fatalf("primary_color = %v, want %s", resp.PrimaryColor, primary)
	}
}

func TestGetTheme_DBError(t *testing.T) {
	_, r, mock := newTestRouter(t)
	mock.ExpectQuery(`SELECT.*FROM ui_theme_config`).
		WillReturnError(errDB())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/ui/theme", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestPutTheme_InvalidJSON(t *testing.T) {
	_, r, _ := newTestRouter(t)
	req := httptest.NewRequest("PUT", "/admin/ui-theme", bytes.NewReader([]byte("{bad json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPutTheme_DBError(t *testing.T) {
	_, r, mock := newTestRouter(t)
	mock.ExpectQuery(`INSERT INTO ui_theme_config`).
		WillReturnError(errDB())

	body, _ := json.Marshal(map[string]any{"product_name": "Acme"})
	req := httptest.NewRequest("PUT", "/admin/ui-theme", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestPutTheme_InvalidColor(t *testing.T) {
	_, r, _ := newTestRouter(t)
	body, _ := json.Marshal(map[string]any{"primary_color": "rgb(1,2,3)"})
	req := httptest.NewRequest("PUT", "/admin/ui-theme", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestPutTheme_InvalidURL(t *testing.T) {
	_, r, _ := newTestRouter(t)
	body, _ := json.Marshal(map[string]any{"logo_url": "javascript:alert(1)"})
	req := httptest.NewRequest("PUT", "/admin/ui-theme", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestPutTheme_Success(t *testing.T) {
	_, r, mock := newTestRouter(t)
	product := "Acme"
	primary := "#5C4EE5"
	logo := "https://cdn.example.com/logo.svg"
	cols := []string{
		"product_name", "primary_color", "secondary_color_light", "secondary_color_dark",
		"logo_url", "favicon_url", "login_hero_url", "updated_at",
	}
	mock.ExpectQuery(`INSERT INTO ui_theme_config`).
		WillReturnRows(mock.NewRows(cols).AddRow(product, primary, nil, nil, logo, nil, nil, fixedTime()))

	body, _ := json.Marshal(map[string]any{"product_name": product, "primary_color": primary, "logo_url": logo})
	req := httptest.NewRequest("PUT", "/admin/ui-theme", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
}

func TestPutTheme_RelativeURL_Allowed(t *testing.T) {
	_, r, mock := newTestRouter(t)
	cols := []string{
		"product_name", "primary_color", "secondary_color_light", "secondary_color_dark",
		"logo_url", "favicon_url", "login_hero_url", "updated_at",
	}
	mock.ExpectQuery(`INSERT INTO ui_theme_config`).
		WillReturnRows(mock.NewRows(cols).AddRow(nil, nil, nil, nil, "/assets/logo.svg", nil, nil, fixedTime()))

	body, _ := json.Marshal(map[string]any{"logo_url": "/assets/logo.svg"})
	req := httptest.NewRequest("PUT", "/admin/ui-theme", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
}

func TestValidateTheme(t *testing.T) {
	cases := []struct {
		name    string
		in      models.UIThemeConfig
		wantErr bool
	}{
		{"all empty ok", models.UIThemeConfig{}, false},
		{"short hex ok", models.UIThemeConfig{PrimaryColor: strptr("#abc")}, false},
		{"long hex ok", models.UIThemeConfig{PrimaryColor: strptr("#5C4EE5")}, false},
		{"https logo ok", models.UIThemeConfig{LogoURL: strptr("https://cdn.example.com/x.png")}, false},
		{"relative logo ok", models.UIThemeConfig{LogoURL: strptr("/static/logo.svg")}, false},
		{"bad color", models.UIThemeConfig{PrimaryColor: strptr("red")}, true},
		{"http insecure", models.UIThemeConfig{LogoURL: strptr("http://cdn.example.com/x.png")}, true},
		{"javascript scheme", models.UIThemeConfig{LogoURL: strptr("javascript:alert(1)")}, true},
		{"protocol relative", models.UIThemeConfig{LogoURL: strptr("//cdn.example.com/x.png")}, true},
		{"url with quote", models.UIThemeConfig{LogoURL: strptr(`https://cdn.example.com/x".png`)}, true},
		{"long product name", models.UIThemeConfig{ProductName: strptr(longString(201))}, true},
		{"200 char product ok", models.UIThemeConfig{ProductName: strptr(longString(200))}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTheme(&tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTheme err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// --- helpers ---

func strptr(s string) *string { return &s }

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func sqlNoRows() error { return sql.ErrNoRows }

func errDB() error { return testErr("database error") }

type testErr string

func (e testErr) Error() string { return string(e) }

func fixedTime() time.Time {
	t, _ := time.Parse(time.RFC3339, "2026-05-18T20:00:00Z")
	return t
}
