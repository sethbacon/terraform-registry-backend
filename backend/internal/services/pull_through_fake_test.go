// pull_through_fake_test.go exercises PullThroughService branches that are
// awkward to reach through httptest — filter-empties, per-version upsert errors,
// and shasums-download errors — by injecting a fakeUpstreamClient via
// PullThroughService.SetUpstreamFactory.  These tests complement the
// httptest-driven coverage in pull_through_integration_test.go.
package services

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// ---------------------------------------------------------------------------
// fakeUpstreamClient
// ---------------------------------------------------------------------------

// fakeUpstreamClient implements mirror.UpstreamRegistryClient with in-memory
// canned responses.  Each method returns what the corresponding field dictates.
type fakeUpstreamClient struct {
	listVersions        []mirror.ProviderVersion
	listVersionsErr     error
	getPackageResult    *mirror.ProviderPackageResponse
	getPackageErr       error
	getPackageByVersion map[string]*mirror.ProviderPackageResponse // keyed by version
	downloadFileResult  []byte
	downloadFileErr     error
	downloadFileByURL   map[string][]byte
}

func (f *fakeUpstreamClient) DiscoverServices(ctx context.Context) (*mirror.ServiceDiscoveryResponse, error) {
	return &mirror.ServiceDiscoveryResponse{ProvidersV1: "/v1/providers/"}, nil
}

func (f *fakeUpstreamClient) ListProviderVersions(ctx context.Context, namespace, providerName string) ([]mirror.ProviderVersion, error) {
	return f.listVersions, f.listVersionsErr
}

func (f *fakeUpstreamClient) GetProviderPackage(ctx context.Context, namespace, providerName, version, os, arch string) (*mirror.ProviderPackageResponse, error) {
	if f.getPackageByVersion != nil {
		if resp, ok := f.getPackageByVersion[version]; ok {
			return resp, nil
		}
	}
	return f.getPackageResult, f.getPackageErr
}

func (f *fakeUpstreamClient) DownloadFile(ctx context.Context, fileURL string) ([]byte, error) {
	if f.downloadFileByURL != nil {
		if data, ok := f.downloadFileByURL[fileURL]; ok {
			return data, nil
		}
	}
	return f.downloadFileResult, f.downloadFileErr
}

func (f *fakeUpstreamClient) DownloadFileStream(ctx context.Context, fileURL string) (*mirror.DownloadStream, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeUpstreamClient) GetProviderDocIndexByVersion(ctx context.Context, namespace, providerName, version string) ([]mirror.ProviderDocEntry, error) {
	return nil, nil
}

func (f *fakeUpstreamClient) GetProviderDocContent(ctx context.Context, upstreamDocID string) (string, error) {
	return "", nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func strPtr(s string) *string { return &s }

// newFakePullThroughService wires a PullThroughService with the provided fake
// upstream client and returns the provider-DB mock for setting expectations.
func newFakePullThroughService(t *testing.T, fake *fakeUpstreamClient) (*PullThroughService, sqlmock.Sqlmock) {
	t.Helper()
	svc, pmock, _, _, _ := newPullThroughEnv(t)
	svc.SetUpstreamFactory(func(baseURL string) mirror.UpstreamRegistryClient {
		return fake
	})
	return svc, pmock
}

// TestFetchProviderMetadata_FilterExcludesAll covers the branch where the
// version filter leaves no versions to sync.
func TestFetchProviderMetadata_FilterExcludesAll(t *testing.T) {
	fake := &fakeUpstreamClient{
		listVersions: []mirror.ProviderVersion{
			{Version: "1.0.0", Protocols: []string{"6.0"}, Platforms: []mirror.ProviderPlatform{{OS: "linux", Arch: "amd64"}}},
		},
	}
	svc, _ := newFakePullThroughService(t, fake)

	mirrorCfg := &models.MirrorConfiguration{
		UpstreamRegistryURL: "https://example.invalid",
		VersionFilter:       strPtr("99.99.99"), // matches nothing
	}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(available) != 0 {
		t.Errorf("available = %v, want empty (filter excluded all)", available)
	}
}

// TestFetchProviderMetadata_UpsertVersionError covers the per-version upsert
// failure path: the version is skipped (warn logged) and the loop continues.
func TestFetchProviderMetadata_UpsertVersionError(t *testing.T) {
	fake := &fakeUpstreamClient{
		listVersions: []mirror.ProviderVersion{
			{Version: "1.0.0", Protocols: []string{"6.0"}, Platforms: []mirror.ProviderPlatform{{OS: "linux", Arch: "amd64"}}},
		},
		getPackageResult: &mirror.ProviderPackageResponse{
			SHASumsURL: "https://example.invalid/sha",
		},
	}
	svc, pmock := newFakePullThroughService(t, fake)

	// UpsertProvider succeeds...
	pmock.ExpectQuery("SELECT.*FROM providers p").
		WillReturnRows(sqlmock.NewRows(providerGetCols))
	pmock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerCreateCols).AddRow(uuid.New().String(), time.Now(), time.Now()))

	// ...but UpsertVersion fails at the GetVersion step.
	pmock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnError(fmt.Errorf("db down"))

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: "https://example.invalid"}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(available) != 0 {
		t.Errorf("available = %v, want empty (version should be skipped)", available)
	}
	if err := pmock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB expectations: %v", err)
	}
}

// TestFetchProviderMetadata_ShasumsDownloadError covers the branch where
// fetchAndStoreShasums fails but the version is still recorded.
func TestFetchProviderMetadata_ShasumsDownloadError(t *testing.T) {
	fake := &fakeUpstreamClient{
		listVersions: []mirror.ProviderVersion{
			{Version: "1.0.0", Protocols: []string{"6.0"}, Platforms: []mirror.ProviderPlatform{{OS: "linux", Arch: "amd64"}}},
		},
		getPackageResult: &mirror.ProviderPackageResponse{
			SHASumsURL: "https://example.invalid/sha",
		},
		downloadFileErr: errors.New("network cut"),
	}
	svc, pmock := newFakePullThroughService(t, fake)

	// Happy DB path for provider + version; no shasums writes (download fails).
	pmock.ExpectQuery("SELECT.*FROM providers p").
		WillReturnRows(sqlmock.NewRows(providerGetCols))
	pmock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerCreateCols).AddRow(uuid.New().String(), time.Now(), time.Now()))
	pmock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(sqlmock.NewRows(versionGetCols))
	pmock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(versionCreateCols).AddRow(uuid.New().String(), time.Now()))

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: "https://example.invalid"}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Version is still reported available — only the shasums step failed.
	if len(available) != 1 || available[0] != "1.0.0" {
		t.Errorf("available = %v, want [1.0.0]", available)
	}
	if err := pmock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB expectations: %v", err)
	}
}

// TestFetchProviderMetadata_EmptyShasumsFile covers the branch where the
// SHASUMS download succeeds but the file is empty — no DB writes issued.
func TestFetchProviderMetadata_EmptyShasumsFile(t *testing.T) {
	fake := &fakeUpstreamClient{
		listVersions: []mirror.ProviderVersion{
			{Version: "1.0.0", Protocols: []string{"6.0"}, Platforms: []mirror.ProviderPlatform{{OS: "linux", Arch: "amd64"}}},
		},
		getPackageResult: &mirror.ProviderPackageResponse{
			SHASumsURL: "https://example.invalid/sha",
		},
		downloadFileResult: []byte(""), // empty → parseSHASUMContent returns empty → early return
	}
	svc, pmock := newFakePullThroughService(t, fake)

	pmock.ExpectQuery("SELECT.*FROM providers p").
		WillReturnRows(sqlmock.NewRows(providerGetCols))
	pmock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerCreateCols).AddRow(uuid.New().String(), time.Now(), time.Now()))
	pmock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(sqlmock.NewRows(versionGetCols))
	pmock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(versionCreateCols).AddRow(uuid.New().String(), time.Now()))

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: "https://example.invalid"}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(available) != 1 {
		t.Errorf("available = %v, want [1.0.0]", available)
	}
	if err := pmock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB expectations: %v", err)
	}
}

// TestFetchProviderMetadata_HappyPath_WithShasums_FakeClient mirrors the
// httptest happy-path test but via the fake client.  Useful regression check
// that the injection seam does not alter behavior.
func TestFetchProviderMetadata_HappyPath_FakeClient(t *testing.T) {
	shasumsURL := "https://example.invalid/sha/1.0.0"
	fake := &fakeUpstreamClient{
		listVersions: []mirror.ProviderVersion{
			{Version: "1.0.0", Protocols: []string{"6.0"}, Platforms: []mirror.ProviderPlatform{{OS: "linux", Arch: "amd64"}}},
		},
		getPackageResult: &mirror.ProviderPackageResponse{
			SHASumsURL: shasumsURL,
			SigningKeys: mirror.SigningKeysInfo{
				GPGPublicKeys: []mirror.GPGPublicKey{{ASCIIArmor: "FAKE-KEY"}},
			},
		},
		downloadFileByURL: map[string][]byte{
			shasumsURL: []byte("abc123  terraform-provider-aws_1.0.0_linux_amd64.zip\n"),
		},
	}
	svc, pmock := newFakePullThroughService(t, fake)

	pmock.ExpectQuery("SELECT.*FROM providers p").
		WillReturnRows(sqlmock.NewRows(providerGetCols))
	pmock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerCreateCols).AddRow(uuid.New().String(), time.Now(), time.Now()))
	pmock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(sqlmock.NewRows(versionGetCols))
	pvID := uuid.New().String()
	pmock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(versionCreateCols).AddRow(pvID, time.Now()))

	pmock.ExpectBegin()
	pmock.ExpectPrepare("INSERT INTO provider_version_shasums")
	pmock.ExpectExec("INSERT INTO provider_version_shasums").
		WithArgs(pvID, "terraform-provider-aws_1.0.0_linux_amd64.zip", "abc123").
		WillReturnResult(sqlmock.NewResult(1, 1))
	pmock.ExpectCommit()

	mirrorCfg := &models.MirrorConfiguration{UpstreamRegistryURL: "https://example.invalid"}

	available, err := svc.FetchProviderMetadata(context.Background(), mirrorCfg, "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(available) != 1 || available[0] != "1.0.0" {
		t.Errorf("available = %v, want [1.0.0]", available)
	}
	if err := pmock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB expectations: %v", err)
	}
}
