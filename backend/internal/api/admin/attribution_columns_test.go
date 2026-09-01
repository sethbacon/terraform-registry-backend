package admin

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// The four attribution columns that were ALWAYS NULL (issue #899).
//
// middleware.AuthMiddleware stores the principal as `c.Set("user_id", user.ID)`
// and models.User.ID is a STRING. These four sites asserted
// `userID.(uuid.UUID)`, so the assertion never succeeded, the value was
// silently dropped, and the column was written NULL on every request:
//
//	admin/mirror.go            -> mirror_configurations.created_by
//	admin/storage.go (create)  -> storage_config.created_by
//	admin/storage.go (update)  -> storage_config.updated_by
//	admin/storage_migration.go -> storage_migrations.created_by
//
// A type assertion that fails yields the zero value and no error, which is why
// nothing ever surfaced — and why three of the foreign keys migration 000056
// dropped looked harmless: they were constraints on columns nothing populated.
//
// Every test below drives the handler with the context value the MIDDLEWARE
// actually sets (a string) and asserts on the bound SQL argument, because the
// bug was invisible at every other layer: the response, the status code and
// the model in memory were all correct.
//
// admin/storage.go's activate path is not here. It always handled both types,
// and its switch is the spelling currentUserNullUUID now shares with the four.
// setup/handlers.go is not here either: it passes uuid.Nil deliberately, and
// StorageConfigRepository.SetStorageConfigured documents NULLIF treating that
// as NULL because no user exists yet during first-run setup. Neither is this
// defect.

const attributionUserID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

// argsWithAttribution builds an argument matcher list of the given width where
// every position matches anything except the one under test.
//
// The alternative — spelling out all 29 arguments of the storage_config insert
// — would make the test fail for reasons that have nothing to do with the
// column it exists to pin.
func argsWithAttribution(width, index int, want driver.Value) []driver.Value {
	args := make([]driver.Value, width)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[index] = want
	return args
}

// ---------------------------------------------------------------------------
// mirror_configurations.created_by
// ---------------------------------------------------------------------------

func newAttributionMirrorRouter(t *testing.T, userID any) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("newSQLMock: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	h := NewMirrorHandler(repositories.NewMirrorRepository(sqlxDB),
		repositories.NewOrganizationRepository(db),
		repositories.NewProviderRepository(db))

	r := gin.New()
	r.POST("/mirrors", func(c *gin.Context) {
		if userID != nil {
			c.Set("user_id", userID)
		}
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		h.CreateMirrorConfig(c)
	})
	return mock, r
}

func createMirror(mock sqlmock.Sqlmock, r *gin.Engine, createdBy driver.Value) *httptest.ResponseRecorder {
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
	expectOrganizationByID(mock, knownUUID)
	// created_by is the last of the insert's eighteen arguments.
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WithArgs(argsWithAttribution(18, 17, createdBy)...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "attributed-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
		})), knownUUID))
	return w
}

func TestAttribution_MirrorCreatedByRecordsTheCaller(t *testing.T) {
	mock, r := newAttributionMirrorRouter(t, attributionUserID)
	w := createMirror(mock, r, attributionUserID)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mirror_configurations.created_by was not the caller: %v", err)
	}
}

// The uuid.UUID spelling still works. Nothing in production sets it, but tests
// do, and accepting only one of the two is how the original defect survived.
func TestAttribution_MirrorCreatedByAcceptsUUIDContextValue(t *testing.T) {
	mock, r := newAttributionMirrorRouter(t, uuid.MustParse(attributionUserID))
	w := createMirror(mock, r, attributionUserID)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mirror_configurations.created_by was not the caller: %v", err)
	}
}

// No principal (an API key with no user binding) still writes NULL, which is
// the honest answer rather than a zero UUID standing in for somebody.
func TestAttribution_MirrorCreatedByIsNullWithoutAPrincipal(t *testing.T) {
	mock, r := newAttributionMirrorRouter(t, nil)
	w := createMirror(mock, r, nil)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mirror_configurations.created_by was not NULL: %v", err)
	}
}

// ---------------------------------------------------------------------------
// storage_config.created_by / .updated_by
// ---------------------------------------------------------------------------

func newAttributionStorageRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("newSQLMock: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewStorageHandlers(&config.Config{},
		repositories.NewStorageConfigRepository(sqlx.NewDb(db, "sqlmock")), nil)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", attributionUserID) })
	r.POST("/storage/configs", h.CreateStorageConfig)
	r.PUT("/storage/configs/:id", h.UpdateStorageConfig)
	return mock, r
}

func TestAttribution_StorageConfigCreatedByRecordsTheCaller(t *testing.T) {
	mock, r := newAttributionStorageRouter(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	// created_by and updated_by are the last two of the insert's twenty-nine
	// arguments; both are stamped from the creating principal.
	args := argsWithAttribution(29, 27, attributionUserID)
	args[28] = attributionUserID
	mock.ExpectExec("INSERT INTO storage_config").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/storage",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("storage_config.created_by/updated_by were not the caller: %v", err)
	}
}

func TestAttribution_StorageConfigUpdatedByRecordsTheCaller(t *testing.T) {
	mock, r := newAttributionStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	// updated_by is the last of the update's twenty-seven arguments.
	mock.ExpectExec("UPDATE storage_config SET").
		WithArgs(argsWithAttribution(27, 26, attributionUserID)...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/data",
		})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("storage_config.updated_by was not the caller: %v", err)
	}
}

// ---------------------------------------------------------------------------
// storage_migrations.created_by
// ---------------------------------------------------------------------------

func TestAttribution_StorageMigrationCreatedByRecordsTheCaller(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("newSQLMock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	svc := services.NewStorageMigrationService(
		repositories.NewStorageMigrationRepository(sqlxDB),
		repositories.NewStorageConfigRepository(sqlxDB),
		nil, nil, nil, &config.Config{})
	h := NewStorageMigrationHandler(svc)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", attributionUserID) })
	r.POST("/migrations", h.StartMigration)

	srcID := "11111111-1111-1111-1111-111111111111"
	tgtID := "22222222-2222-2222-2222-222222222222"

	// source and target storage configs
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	// nothing to move, so no items insert follows
	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))
	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))
	// created_by is the last of the insert's thirteen arguments.
	mock.ExpectExec("INSERT INTO storage_migrations").
		WithArgs(argsWithAttribution(13, 12, attributionUserID)...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations",
		jsonBody(map[string]interface{}{
			"source_config_id": srcID,
			"target_config_id": tgtID,
		})))

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("storage_migrations.created_by was not the caller: %v", err)
	}
}
