package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newOIDCConfigRepo(t *testing.T) (*repositories.OIDCConfigRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func newSetupRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	repo, mock := newOIDCConfigRepo(t)
	r := gin.New()
	r.Use(SetupTokenMiddleware(repo))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return mock, r
}

func doSetupRequest(r *gin.Engine, authHeader string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — setup already completed
// ---------------------------------------------------------------------------

func TestSetupMiddleware_SetupCompleted(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(true))

	w := doSetupRequest(r, "SetupToken valid-token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — setup completed check error
// ---------------------------------------------------------------------------

func TestSetupMiddleware_SetupCheckError(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnError(errors.New("db down"))

	w := doSetupRequest(r, "SetupToken valid-token")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — missing authorization header
// ---------------------------------------------------------------------------

func TestSetupMiddleware_MissingHeader(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))

	w := doSetupRequest(r, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — wrong scheme (Bearer instead of SetupToken)
// ---------------------------------------------------------------------------

func TestSetupMiddleware_WrongScheme(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))

	w := doSetupRequest(r, "Bearer some-jwt")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — no stored hash (no token generated)
// ---------------------------------------------------------------------------

func TestSetupMiddleware_NoStoredHash(t *testing.T) {
	mock, r := newSetupRouter(t)
	// setup_completed = false
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	// setup_token_hash is NULL
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(nil))

	w := doSetupRequest(r, "SetupToken some-token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — hash retrieval error
// ---------------------------------------------------------------------------

func TestSetupMiddleware_HashRetrievalError(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnError(errors.New("connection lost"))

	w := doSetupRequest(r, "SetupToken some-token")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — wrong token
// ---------------------------------------------------------------------------

func TestSetupMiddleware_WrongToken(t *testing.T) {
	mock, r := newSetupRouter(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-token"), bcrypt.MinCost)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

	w := doSetupRequest(r, "SetupToken wrong-token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — valid token
// ---------------------------------------------------------------------------

func TestSetupMiddleware_ValidToken(t *testing.T) {
	mock, r := newSetupRouter(t)

	token := "my-valid-setup-token"
	hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

	w := doSetupRequest(r, "SetupToken "+token)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — case-insensitive scheme
// ---------------------------------------------------------------------------

func TestSetupMiddleware_CaseInsensitiveScheme(t *testing.T) {
	mock, r := newSetupRouter(t)

	token := "my-valid-setup-token"
	hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

	w := doSetupRequest(r, "setuptoken "+token)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (scheme should be case-insensitive)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — rate limiter unit tests
// ---------------------------------------------------------------------------

func TestSetupRateLimiter_AllowsWithinLimit(t *testing.T) {
	rl := newSetupRateLimiter()
	for i := 0; i < setupMaxAttempts; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
}

func TestSetupRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := newSetupRateLimiter()
	for i := 0; i < setupMaxAttempts; i++ {
		rl.allow("1.2.3.4")
	}
	if rl.allow("1.2.3.4") {
		t.Error("attempt beyond limit should be blocked")
	}
}

func TestSetupRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := newSetupRateLimiter()
	// Exhaust limit for IP-A
	for i := 0; i < setupMaxAttempts; i++ {
		rl.allow("10.0.0.1")
	}
	// IP-B should still be allowed
	if !rl.allow("10.0.0.2") {
		t.Error("different IP should have independent rate limit")
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — rate limit returns 429
// ---------------------------------------------------------------------------

func TestSetupMiddleware_RateLimitExceeded(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	r := gin.New()
	r.Use(SetupTokenMiddleware(repo))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Make setupMaxAttempts + 1 requests (each needs completed check)
	for i := 0; i <= setupMaxAttempts; i++ {
		mock.ExpectQuery("SELECT setup_completed FROM system_settings").
			WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	}

	var lastCode int
	for i := 0; i <= setupMaxAttempts; i++ {
		w := doSetupRequest(r, "SetupToken any-token")
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after exceeding rate limit, status = %d, want 429", lastCode)
	}
}
