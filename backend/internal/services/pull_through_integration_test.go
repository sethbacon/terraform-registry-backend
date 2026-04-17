// pull_through_integration_test.go exercises PullThroughService methods that
// drive both an HTTP upstream registry and the database layer.  httptest.Server
// provides the upstream, sqlmock provides the DB.  Together these tests cover
// FetchProviderMetadata, fetchAndStoreShasums, and GetConfigsForProvider
// without requiring a live registry or Postgres instance.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newPullThroughEnv constructs a PullThroughService backed by sqlmock DBs for
// the provider (std *sql.DB) and mirror (sqlx *sqlx.DB) repositories, plus an
// httptest.Server ready to be configured per test.  Returns the service, both
// mocks, and the mux so individual tests can register the endpoints they need.
func newPullThroughEnv(t *testing.T) (
	svc *PullThroughService,
	provMock, mirrorMock sqlmock.Sqlmock,
	mux *http.ServeMux,
	server *httptest.Server,
) {
	t.Helper()

	provDB, pmock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (provider): %v", err)
	}
	t.Cleanup(func() { provDB.Close() })

	mirrorDB, mmock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (mirror): %v", err)
	}
	t.Cleanup(func() { mirrorDB.Close() })

	providerRepo := repositories.NewProviderRepository(provDB)
	mirrorRepo := repositories.NewMirrorRepository(sqlx.NewDb(mirrorDB, "sqlmock"))

	svc = NewPullThroughService(providerRepo, mirrorRepo, nil /* orgRepo: unused */)

	mux = http.NewServeMux()
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return svc, pmock, mmock, mux, server
}

// versionsListResponse produces the JSON body for /v1/providers/{ns}/{type}/versions.
func versionsListResponse(version string, platforms []map[string]string) string {
	b, _ := json.Marshal(map[string]interface{}{
		"versions": []map[string]interface{}{
			{
				"version":   version,
				"protocols": []string{"6.0"},
				"platforms": platforms,
			},
		},
	})
	return string(b)
}

// ---------------------------------------------------------------------------
// FetchProviderMetadata — upstream error paths
// ---------------------------------------------------------------------------

func TestFetchProviderMetadata_UpstreamDiscoveryFailure(t *testing.T) {
	svc, _, _, _, server := newPullThroughEnv(t)
	// No handler registered → all requests return 404 → discovery fails.
	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: server.URL}

	_, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err == nil {
		t.Fatal("expected error from upstream discovery failure, got nil")
	}
	if !strings.Contains(err.Error(), "upstream version list") {
		t.Errorf("error = %q, want to contain 'upstream version list'", err.Error())
	}
}

func TestFetchProviderMetadata_EmptyVersions(t *testing.T) {
	svc, _, _, mux, server := newPullThroughEnv(t)
	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"providers.v1": "/v1/providers/"}`)
	})
	mux.HandleFunc("/v1/providers/hashicorp/aws/versions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"versions": []}`)
	})

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: server.URL}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(available) != 0 {
		t.Errorf("available = %v, want empty", available)
	}
}

// ---------------------------------------------------------------------------
// FetchProviderMetadata — happy path
// ---------------------------------------------------------------------------

// providerGetCols are the 10 columns returned by ProviderRepository.GetProvider positional scan.
var providerGetCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_at", "updated_at", "created_by_name",
}

// providerCreateCols are returned by CreateProvider's RETURNING clause.
var providerCreateCols = []string{"id", "created_at", "updated_at"}

// versionGetCols are the 12 columns returned by GetVersion positional scan.
var versionGetCols = []string{
	"id", "provider_id", "version", "protocols", "gpg_public_key",
	"shasums_url", "shasums_signature_url", "published_by",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
}

// versionCreateCols are returned by CreateVersion's RETURNING clause.
var versionCreateCols = []string{"id", "created_at"}

func TestFetchProviderMetadata_HappyPath(t *testing.T) {
	svc, pmock, _, mux, server := newPullThroughEnv(t)

	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"providers.v1": "/v1/providers/"}`)
	})
	mux.HandleFunc("/v1/providers/hashicorp/aws/versions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, versionsListResponse("1.2.3", []map[string]string{
			{"os": "linux", "arch": "amd64"},
		}))
	})
	mux.HandleFunc("/v1/providers/hashicorp/aws/1.2.3/download/linux/amd64", func(w http.ResponseWriter, r *http.Request) {
		shasumsURL := server.URL + "/shasums/1.2.3"
		_, _ = fmt.Fprintf(w, `{
			"protocols": ["6.0"],
			"os": "linux",
			"arch": "amd64",
			"filename": "terraform-provider-aws_1.2.3_linux_amd64.zip",
			"download_url": "%s/binary/1.2.3/linux_amd64.zip",
			"shasums_url": "%s",
			"shasums_signature_url": "%s/shasums.sig/1.2.3",
			"shasum": "abcdef",
			"signing_keys": {
				"gpg_public_keys": [{"ascii_armor": "FAKE-KEY", "key_id": "KEY1"}]
			}
		}`, server.URL, shasumsURL, server.URL)
	})
	mux.HandleFunc("/shasums/1.2.3", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "abc123  terraform-provider-aws_1.2.3_linux_amd64.zip\n")
	})

	// DB expectations — UpsertProvider → GetProvider (miss) + CreateProvider.
	pmock.ExpectQuery("SELECT.*FROM providers p").
		WithArgs("org-1", "hashicorp", "aws").
		WillReturnRows(sqlmock.NewRows(providerGetCols))
	pmock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerCreateCols).AddRow(uuid.New().String(), time.Now(), time.Now()))

	// UpsertVersion → GetVersion (miss) + CreateVersion.
	pmock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(sqlmock.NewRows(versionGetCols))
	pvID := uuid.New().String()
	pmock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(versionCreateCols).AddRow(pvID, time.Now()))

	// UpsertProviderVersionShasums → begin/prepare/exec/commit.
	pmock.ExpectBegin()
	pmock.ExpectPrepare("INSERT INTO provider_version_shasums")
	pmock.ExpectExec("INSERT INTO provider_version_shasums").
		WithArgs(pvID, "terraform-provider-aws_1.2.3_linux_amd64.zip", "abc123").
		WillReturnResult(sqlmock.NewResult(1, 1))
	pmock.ExpectCommit()

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: server.URL}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(available) != 1 || available[0] != "1.2.3" {
		t.Errorf("available = %v, want [1.2.3]", available)
	}
	if err := pmock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB expectations: %v", err)
	}
}

// TestFetchProviderMetadata_SkipsPlatformlessVersions exercises the branch that
// warns & continues when a version has no platforms.
func TestFetchProviderMetadata_SkipsPlatformlessVersions(t *testing.T) {
	svc, pmock, _, mux, server := newPullThroughEnv(t)

	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"providers.v1": "/v1/providers/"}`)
	})
	mux.HandleFunc("/v1/providers/hashicorp/aws/versions", func(w http.ResponseWriter, r *http.Request) {
		// Version with no platforms — should be skipped.
		_, _ = fmt.Fprint(w, versionsListResponse("2.0.0", nil))
	})

	// Provider is upserted before the version loop begins.
	pmock.ExpectQuery("SELECT.*FROM providers p").
		WithArgs("org-1", "hashicorp", "aws").
		WillReturnRows(sqlmock.NewRows(providerGetCols))
	pmock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerCreateCols).AddRow(uuid.New().String(), time.Now(), time.Now()))

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: server.URL}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No versions should be returned because the only one had no platforms.
	if len(available) != 0 {
		t.Errorf("available = %v, want empty", available)
	}
}

// TestFetchProviderMetadata_UpsertProviderError covers the failure path when
// the DB layer returns an error during UpsertProvider.
func TestFetchProviderMetadata_UpsertProviderError(t *testing.T) {
	svc, pmock, _, mux, server := newPullThroughEnv(t)

	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"providers.v1": "/v1/providers/"}`)
	})
	mux.HandleFunc("/v1/providers/hashicorp/aws/versions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, versionsListResponse("1.0.0", []map[string]string{
			{"os": "linux", "arch": "amd64"},
		}))
	})

	// GetProvider returns an error → UpsertProvider propagates it.
	pmock.ExpectQuery("SELECT.*FROM providers p").
		WillReturnError(fmt.Errorf("db unreachable"))

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: server.URL}

	_, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "upsert provider") {
		t.Errorf("error = %q, want to contain 'upsert provider'", err.Error())
	}
}

// TestFetchProviderMetadata_PackageInfoFailure_SkipsVersion exercises the
// branch where GetProviderPackage returns an error; the version is skipped
// but the overall call still succeeds with an empty list.
func TestFetchProviderMetadata_PackageInfoFailure_SkipsVersion(t *testing.T) {
	svc, pmock, _, mux, server := newPullThroughEnv(t)

	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"providers.v1": "/v1/providers/"}`)
	})
	mux.HandleFunc("/v1/providers/hashicorp/aws/versions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, versionsListResponse("1.0.0", []map[string]string{
			{"os": "linux", "arch": "amd64"},
		}))
	})
	// No handler for /v1/providers/hashicorp/aws/1.0.0/download/... → 404
	// which causes GetProviderPackage to error → version is skipped.

	pmock.ExpectQuery("SELECT.*FROM providers p").
		WithArgs("org-1", "hashicorp", "aws").
		WillReturnRows(sqlmock.NewRows(providerGetCols))
	pmock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerCreateCols).AddRow(uuid.New().String(), time.Now(), time.Now()))

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: server.URL}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(available) != 0 {
		t.Errorf("available = %v, want empty (version should be skipped)", available)
	}
}

// ---------------------------------------------------------------------------
// fetchAndStoreShasums — indirectly covered by TestFetchProviderMetadata_HappyPath
// ---------------------------------------------------------------------------
// The non-empty path is exercised by the happy-path test above (which asserts
// the BeginTx/Prepare/Exec/Commit sequence on the provider DB).  A direct unit
// test is not included here because fetchAndStoreShasums requires a
// *mirror.UpstreamRegistry, which is constructed via the mirror package's
// exported NewUpstreamRegistry used internally by FetchProviderMetadata.

// ---------------------------------------------------------------------------
// GetConfigsForProvider — sqlx-backed repository delegation
// ---------------------------------------------------------------------------

func TestGetConfigsForProvider_DBError(t *testing.T) {
	svc, _, mmock, _, _ := newPullThroughEnv(t)

	mmock.ExpectQuery("SELECT.*FROM mirror_configurations.*pull_through_enabled").
		WillReturnError(fmt.Errorf("db down"))

	_, err := svc.GetConfigsForProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetConfigsForProvider_Empty(t *testing.T) {
	svc, _, mmock, _, _ := newPullThroughEnv(t)

	mmock.ExpectQuery("SELECT.*FROM mirror_configurations.*pull_through_enabled").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "description", "upstream_registry_url", "organization_id",
			"namespace_filter", "provider_filter", "version_filter", "platform_filter",
			"enabled", "sync_interval_hours", "pull_through_enabled",
			"pull_through_cache_ttl_hours", "last_sync_at", "last_sync_status", "last_sync_error",
			"created_at", "updated_at", "created_by",
		}))

	configs, err := svc.GetConfigsForProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("configs = %v, want empty", configs)
	}
}
