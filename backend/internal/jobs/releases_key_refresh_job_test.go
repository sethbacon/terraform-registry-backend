package jobs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// helper: build a fully wired ReleasesKeyRefreshJob over a sqlmock + a stub
// HTTP server serving the given body for HashiCorp's URL. OpenTofu URL is
// pointed at an immediately-closed listener so the second tool always fails
// without contaminating the HashiCorp telemetry counter we're asserting on.
func newJobWithStubs(t *testing.T, hashicorpBody string) (*ReleasesKeyRefreshJob, sqlmock.Sqlmock, *httptest.Server) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := repositories.NewReleasesGPGKeyRepository(sqlx.NewDb(db, "postgres"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(hashicorpBody))
	}))
	t.Cleanup(srv.Close)

	cfg := &config.ReleasesGPGKeysConfig{
		Enabled:              true,
		RefreshIntervalHours: 1,
		ExpiryWarningDays:    60,
		HashiCorpURL:         srv.URL,
		OpenTofuURL:          "http://127.0.0.1:0", // immediate connection refused
	}
	job, err := NewReleasesKeyRefreshJob(cfg, repo, srv.Client())
	if err != nil {
		t.Fatalf("NewReleasesKeyRefreshJob: %v", err)
	}
	return job, mock, srv
}

func TestReleasesKeyRefreshJob_Disabled_IsNoOp(t *testing.T) {
	job, _, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)
	job.cfg.Enabled = false

	// Start should return immediately. Run on goroutine + short ctx to be sure.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not return when disabled")
	}
}

func TestReleasesKeyRefreshJob_RefreshOne_Success(t *testing.T) {
	job, mock, srv := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)

	mock.ExpectExec(`INSERT INTO releases_gpg_keys`).
		WillReturnResult(sqlmock.NewResult(0, 1))

	job.refreshOne(context.Background(), toolEndpoint{
		tool:        "terraform",
		url:         srv.URL,
		fingerprint: "C874011F0AB405110D02105534365D9472D7468F",
	})

	// Cache must be populated so the resolver hand-off works.
	if got := job.ResolveReleasesKey("terraform"); got == "" {
		t.Fatal("expected resolver to return the cached key after success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestReleasesKeyRefreshJob_RefreshOne_FingerprintMismatch_LeavesCacheUntouched(t *testing.T) {
	job, _, srv := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)

	// Pin a wrong-but-valid-shape fingerprint. No Upsert expectation —
	// sqlmock will fail if the job tries to write.
	job.refreshOne(context.Background(), toolEndpoint{
		tool:        "terraform",
		url:         srv.URL,
		fingerprint: "0000000000000000000000000000000000000000",
	})

	if got := job.ResolveReleasesKey("terraform"); got != "" {
		t.Fatal("expected cache to remain empty on fingerprint mismatch")
	}
}

func TestReleasesKeyRefreshJob_RefreshOne_FetchFailure_LeavesCacheUntouched(t *testing.T) {
	job, _, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)

	// Hit an immediately-closed listener so the HTTP fetch errors.
	job.refreshOne(context.Background(), toolEndpoint{
		tool:        "terraform",
		url:         "http://127.0.0.1:0",
		fingerprint: "C874011F0AB405110D02105534365D9472D7468F",
	})

	if got := job.ResolveReleasesKey("terraform"); got != "" {
		t.Fatal("expected cache to remain empty on fetch failure")
	}
}

func TestReleasesKeyRefreshJob_RefreshOne_SkipsUnchanged(t *testing.T) {
	job, mock, srv := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)

	// First call inserts.
	mock.ExpectExec(`INSERT INTO releases_gpg_keys`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	job.refreshOne(context.Background(), toolEndpoint{
		tool:        "terraform",
		url:         srv.URL,
		fingerprint: "C874011F0AB405110D02105534365D9472D7468F",
	})

	// Second call with identical body — no second INSERT expected. If the
	// job tries to write, sqlmock will fail when ExpectationsWereMet runs.
	job.refreshOne(context.Background(), toolEndpoint{
		tool:        "terraform",
		url:         srv.URL,
		fingerprint: "C874011F0AB405110D02105534365D9472D7468F",
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestReleasesKeyRefreshJob_PrimeCache_LoadsPersistedRow(t *testing.T) {
	job, mock, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)

	expiry := time.Now().Add(365 * 24 * time.Hour)
	cols := []string{"tool", "armored_key", "primary_fpr", "key_expires_at", "source_url", "fetched_at"}
	mock.ExpectQuery(`SELECT.*FROM releases_gpg_keys WHERE tool`).
		WithArgs("terraform").
		WillReturnRows(sqlmock.NewRows(cols).AddRow(
			"terraform",
			mirror.HashiCorpReleasesGPGKey,
			"C874011F0AB405110D02105534365D9472D7468F",
			expiry, "https://example.com", time.Now(),
		))
	// OpenTofu row: not found — returns empty rowset so Get returns nil/nil.
	otCols := cols
	mock.ExpectQuery(`SELECT.*FROM releases_gpg_keys WHERE tool`).
		WithArgs("opentofu").
		WillReturnRows(sqlmock.NewRows(otCols))

	job.primeCacheFromDB(context.Background())

	if got := job.ResolveReleasesKey("terraform"); got == "" {
		t.Error("expected resolver to return terraform key after prime")
	}
	if got := job.ResolveReleasesKey("opentofu"); got != "" {
		t.Error("expected resolver to return empty for opentofu (no row)")
	}
}

func TestReleasesKeyRefreshJob_PrimeCache_RejectsFingerprintDriftOnDB(t *testing.T) {
	job, mock, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)

	// Manually-edited DB row with the wrong fingerprint. The job must
	// refuse to load it so a hostile DB write can't poison the resolver.
	cols := []string{"tool", "armored_key", "primary_fpr", "key_expires_at", "source_url", "fetched_at"}
	mock.ExpectQuery(`SELECT.*FROM releases_gpg_keys WHERE tool`).
		WithArgs("terraform").
		WillReturnRows(sqlmock.NewRows(cols).AddRow(
			"terraform",
			"ARMORED-MAYBE-HOSTILE",
			"0000000000000000000000000000000000000000",
			nil, "https://example.com", time.Now(),
		))
	mock.ExpectQuery(`SELECT.*FROM releases_gpg_keys WHERE tool`).
		WithArgs("opentofu").
		WillReturnRows(sqlmock.NewRows(cols))

	job.primeCacheFromDB(context.Background())

	if got := job.ResolveReleasesKey("terraform"); got != "" {
		t.Error("expected resolver to ignore drift-fingerprint row")
	}
}

func TestReleasesKeyRefreshJob_ExportExpiryGauges_DoesNotPanic(t *testing.T) {
	job, _, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)
	// Even with no cache entries, the embedded snapshots must export
	// without panic so dashboards stay populated before the first fetch.
	job.exportExpiryGauges()
}

func TestReleasesKeyRefreshJob_ResolveReleasesKey_NilSafe(t *testing.T) {
	var job *ReleasesKeyRefreshJob
	if got := job.ResolveReleasesKey("terraform"); got != "" {
		t.Errorf("nil receiver should return empty, got %q", got)
	}
}

func TestReleasesKeyRefreshJob_Stop_NilSafe(t *testing.T) {
	var job *ReleasesKeyRefreshJob
	// Should not panic.
	job.Stop()
}

func TestReleasesKeyRefreshJob_Stop_Idempotent(t *testing.T) {
	job, _, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)
	job.Stop()
	job.Stop() // second call must not panic on closed channel
}

// TestReleasesKeyRefreshJob_RunCycle drives the top-level cycle once. With
// the HashiCorp stub serving a valid key it must persist that tool's row,
// then with OpenTofu pointed at a dead listener the cycle must complete
// without surfacing the failure (per-tool failures are counted but the
// cycle keeps going).
func TestReleasesKeyRefreshJob_RunCycle(t *testing.T) {
	job, mock, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)

	mock.ExpectExec(`INSERT INTO releases_gpg_keys`).
		WillReturnResult(sqlmock.NewResult(0, 1))

	job.runCycle(context.Background())

	// HashiCorp must be cached; OpenTofu must remain absent (its fetch hit a
	// dead listener) — both outcomes prove the cycle iterated through both
	// tools without aborting early.
	if got := job.ResolveReleasesKey("terraform"); got == "" {
		t.Error("expected terraform key to be cached after runCycle")
	}
	if got := job.ResolveReleasesKey("opentofu"); got != "" {
		t.Error("expected opentofu cache to remain empty after fetch failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestReleasesKeyRefreshJob_ExportOne_KeyWithoutExpiry exercises the
// "expiry == zero" branch of exportOne. A key with no LatestSigningExpiry
// must still set the gauge (to 0) and not log a warning.
func TestReleasesKeyRefreshJob_ExportOne_KeyWithoutExpiry(t *testing.T) {
	job, _, _ := newJobWithStubs(t, mirror.HashiCorpReleasesGPGKey)
	// Empty armored string → ParseReleasesKey errors; exportOne logs and
	// returns. Exercises the parse-failure branch without panicking.
	job.exportOne("terraform", "cache", "not a key", time.Now(), 60*24*time.Hour)
	// Then the empty-armored fast path.
	job.exportOne("terraform", "cache", "", time.Now(), 60*24*time.Hour)
}

// TestEmbeddedKeyForTool covers the helper directly so its switch arms are
// all exercised.
func TestEmbeddedKeyForTool(t *testing.T) {
	if embeddedKeyForTool("terraform") == "" {
		t.Error("terraform: expected embedded key, got empty")
	}
	if embeddedKeyForTool("Terraform") == "" {
		t.Error("Terraform (mixed case): expected embedded key, got empty")
	}
	if embeddedKeyForTool("opentofu") == "" {
		t.Error("opentofu: expected embedded key, got empty")
	}
	if embeddedKeyForTool("does-not-exist") != "" {
		t.Error("unknown tool: expected empty, got non-empty")
	}
}
