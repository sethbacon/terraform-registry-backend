package repositories

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// Issue #869 — the reported defect, reproduced against real PostgreSQL and the
// real schema, because it is a property of an ON CONFLICT clause and no mock
// can evaluate one.
//
// The report was that the binary mirror served sha256:"" for every
// terraform-docs version while its SHA256SUMS blob was byte-identical to
// upstream, and that the rows had been "bulk-touched" — updated_at moved,
// sha256 did not. What actually happened is worse than "did not": the sync
// job's step-4 upsert re-inserts every platform straight from the upstream
// release index, that index row carries no checksum, and the conflict clause
// wrote the resulting empty string over the verified hash. The row keeps
// sync_status='synced' throughout, so the download API goes on serving the
// binary with no checksum for it.
//
// Set TFR_TEST_DATABASE_URL to run these.

const mirrorSHA256ScratchPrefix = "tfr_869_"

func mirrorScratchDB(t *testing.T) *sqlx.DB {
	t.Helper()

	raw := os.Getenv("TFR_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TFR_TEST_DATABASE_URL not set — needs a reachable Postgres")
	}
	base, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(base.Scheme, "postgres") {
		t.Skipf("TFR_TEST_DATABASE_URL is not a postgres:// URL (%q)", raw)
	}

	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("Postgres not reachable at TFR_TEST_DATABASE_URL: %v", err)
	}

	name := mirrorSHA256ScratchPrefix + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
		t.Skipf("cannot create a scratch database (needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		drop, dropErr := sql.Open("pgx", raw)
		if dropErr != nil {
			return
		}
		defer drop.Close()
		_, _ = drop.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})

	scratch := *base
	scratch.Path = "/" + name
	dsn := scratch.String()

	m, err := migrate.New("file://../migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("applying migrations: %v", err)
	}

	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sqlx.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedMirrorVersion creates a config + version and returns the version id.
func seedMirrorVersion(t *testing.T, db *sqlx.DB, tool, version, versionSyncStatus string) (configID, versionID uuid.UUID) {
	t.Helper()
	configID = uuid.New()
	versionID = uuid.New()

	if _, err := db.Exec(
		`INSERT INTO terraform_mirror_configs (id, name, tool, upstream_url) VALUES ($1, $2, $3, $4)`,
		configID, "mirror-"+versionID.String()[:8], tool, "https://github.com/terraform-docs/terraform-docs",
	); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO terraform_versions (id, config_id, version, sync_status, sums_storage_key)
		 VALUES ($1, $2, $3, $4, $5)`,
		versionID, configID, version, versionSyncStatus, "terraform-binaries/"+version+"/SHA256SUMS",
	); err != nil {
		t.Fatalf("seed version: %v", err)
	}
	return configID, versionID
}

func platformSHA256(t *testing.T, db *sqlx.DB, id uuid.UUID) (sha, status string, verified bool) {
	t.Helper()
	if err := db.QueryRow(
		`SELECT sha256, sync_status, sha256_verified FROM terraform_version_platforms WHERE id = $1`, id,
	).Scan(&sha, &status, &verified); err != nil {
		t.Fatalf("read back platform: %v", err)
	}
	return sha, status, verified
}

// TestUpsertPlatform_ReSyncDoesNotEraseStoredSHA256 is the regression test for
// the reported symptom. It replays the exact sequence: a first sync that stores
// a verified hash, then the next sync's metadata upsert, which arrives with the
// zero-valued SHA256 that performSync's step 4 always sends.
//
// Before the fix this left the sha256 column empty with sync_status still
// 'synced' — the state the reporter's probe found on all three terraform-docs
// versions.
func TestUpsertPlatform_ReSyncDoesNotEraseStoredSHA256(t *testing.T) {
	db := mirrorScratchDB(t)
	repo := NewTerraformMirrorRepository(db)
	ctx := context.Background()

	_, versionID := seedMirrorVersion(t, db, "terraform-docs", "0.24.0", "synced")

	const upstreamName = "terraform-docs-v0.24.0-linux-amd64.tar.gz"
	const knownHash = "9005daf969de0b50134493a2c00078b49f5f5b39d021cda7c89bf4d4f3d776d3"

	// First sync: the row is created, downloaded and its hash persisted.
	p := &models.TerraformVersionPlatform{
		VersionID:   versionID,
		OS:          "linux",
		Arch:        "amd64",
		UpstreamURL: "https://github.com/terraform-docs/terraform-docs/releases/download/v0.24.0/" + upstreamName,
		Filename:    upstreamName,
		SyncStatus:  "pending",
	}
	if err := repo.UpsertPlatform(ctx, p); err != nil {
		t.Fatalf("first UpsertPlatform: %v", err)
	}
	storageKey := "terraform-binaries/0.24.0/linux/amd64/" + upstreamName
	backend := "azure"
	if err := repo.UpdatePlatformSyncStatus(ctx, p.ID, "synced", &storageKey, &backend, true, false, false, nil); err != nil {
		t.Fatalf("UpdatePlatformSyncStatus: %v", err)
	}
	if err := repo.UpdatePlatformSHA256(ctx, p.ID, knownHash); err != nil {
		t.Fatalf("UpdatePlatformSHA256: %v", err)
	}
	if sha, _, _ := platformSHA256(t, db, p.ID); sha != knownHash {
		t.Fatalf("precondition: sha256 = %q, want %q", sha, knownHash)
	}

	// Next sync tick: performSync step 4 re-upserts the platform from the
	// upstream release index. That struct carries no SHA256 — same shape as
	// the production call site.
	reSync := &models.TerraformVersionPlatform{
		VersionID:   versionID,
		OS:          "linux",
		Arch:        "amd64",
		UpstreamURL: p.UpstreamURL,
		Filename:    upstreamName,
		SyncStatus:  "pending",
	}
	if err := repo.UpsertPlatform(ctx, reSync); err != nil {
		t.Fatalf("re-sync UpsertPlatform: %v", err)
	}

	sha, status, _ := platformSHA256(t, db, p.ID)
	if sha != knownHash {
		t.Fatalf("re-sync erased the stored checksum: sha256 = %q, want %q — this is issue #869: "+
			"the download API serves this row with sha256:\"\" and fail-closed installers refuse it", sha, knownHash)
	}
	if status != "synced" {
		t.Errorf("sync_status = %q, want synced (the upsert must not disturb it)", status)
	}
}

// A genuinely new checksum from upstream must still land — the fix preserves a
// stored hash against an EMPTY incoming one, not against every incoming one.
func TestUpsertPlatform_NonEmptyIncomingSHA256StillOverwrites(t *testing.T) {
	db := mirrorScratchDB(t)
	repo := NewTerraformMirrorRepository(db)
	ctx := context.Background()

	_, versionID := seedMirrorVersion(t, db, "terraform", "1.9.0", "synced")

	p := &models.TerraformVersionPlatform{
		VersionID: versionID, OS: "linux", Arch: "amd64",
		UpstreamURL: "https://u", Filename: "terraform_1.9.0_linux_amd64.zip",
		SHA256: "aaaa", SyncStatus: "pending",
	}
	if err := repo.UpsertPlatform(ctx, p); err != nil {
		t.Fatalf("first UpsertPlatform: %v", err)
	}
	p2 := &models.TerraformVersionPlatform{
		VersionID: versionID, OS: "linux", Arch: "amd64",
		UpstreamURL: "https://u", Filename: "terraform_1.9.0_linux_amd64.zip",
		SHA256: "bbbb", SyncStatus: "pending",
	}
	if err := repo.UpsertPlatform(ctx, p2); err != nil {
		t.Fatalf("second UpsertPlatform: %v", err)
	}

	if sha, _, _ := platformSHA256(t, db, p.ID); sha != "bbbb" {
		t.Fatalf("sha256 = %q, want bbbb — a non-empty upstream value must overwrite", sha)
	}
}

// TestListVersionsMissingSHA256_IncludesPartialVersions covers the second half
// of why the defect was permanent. The SHA256 back-fill used to walk only
// versions whose OWN sync_status was 'synced'. A version left 'partial' by a
// single unavailable platform still serves the platforms that succeeded, so
// gating on the version's status skipped exactly the rows that needed repair,
// on every run, forever.
func TestListVersionsMissingSHA256_IncludesPartialVersions(t *testing.T) {
	db := mirrorScratchDB(t)
	repo := NewTerraformMirrorRepository(db)
	ctx := context.Background()

	configID, versionID := seedMirrorVersion(t, db, "terraform-docs", "0.23.0", "partial")

	// One synced platform with no checksum (needs repair) and one still
	// pending (must not, on its own, make the version a candidate).
	if _, err := db.Exec(
		`INSERT INTO terraform_version_platforms (version_id, os, arch, upstream_url, filename, sha256, sync_status)
		 VALUES ($1,'linux','amd64','https://u','terraform-docs-v0.23.0-linux-amd64.tar.gz','','synced'),
		        ($1,'freebsd','arm','https://u','terraform-docs-v0.23.0-freebsd-arm.tar.gz','','pending')`,
		versionID,
	); err != nil {
		t.Fatalf("seed platforms: %v", err)
	}

	versions, err := repo.ListVersionsMissingSHA256(ctx, configID)
	if err != nil {
		t.Fatalf("ListVersionsMissingSHA256: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("got %d versions, want 1 — a 'partial' version with a synced, checksum-less platform must be a repair candidate", len(versions))
	}
	if versions[0].Version != "0.23.0" {
		t.Errorf("version = %q, want 0.23.0", versions[0].Version)
	}

	count, err := repo.CountPlatformsMissingSHA256(ctx, configID)
	if err != nil {
		t.Fatalf("CountPlatformsMissingSHA256: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 (only the synced row counts; a pending one is not yet being served)", count)
	}
}

// A version with every checksum present is not a candidate, and a deprecated
// version is not one either — its platforms are no longer offered, so it must
// not hold the invariant red forever.
func TestListVersionsMissingSHA256_ExcludesHealthyAndDeprecated(t *testing.T) {
	db := mirrorScratchDB(t)
	repo := NewTerraformMirrorRepository(db)
	ctx := context.Background()

	configID, healthyID := seedMirrorVersion(t, db, "terraform", "1.9.0", "synced")
	if _, err := db.Exec(
		`INSERT INTO terraform_version_platforms (version_id, os, arch, upstream_url, filename, sha256, sync_status)
		 VALUES ($1,'linux','amd64','https://u','terraform_1.9.0_linux_amd64.zip','deadbeef','synced')`,
		healthyID,
	); err != nil {
		t.Fatalf("seed healthy platform: %v", err)
	}

	deprecatedID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO terraform_versions (id, config_id, version, sync_status, is_deprecated)
		 VALUES ($1, $2, '1.2.3', 'synced', true)`, deprecatedID, configID,
	); err != nil {
		t.Fatalf("seed deprecated version: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO terraform_version_platforms (version_id, os, arch, upstream_url, filename, sha256, sync_status)
		 VALUES ($1,'linux','amd64','https://u','terraform_1.2.3_linux_amd64.zip','','synced')`,
		deprecatedID,
	); err != nil {
		t.Fatalf("seed deprecated platform: %v", err)
	}

	versions, err := repo.ListVersionsMissingSHA256(ctx, configID)
	if err != nil {
		t.Fatalf("ListVersionsMissingSHA256: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("got %d candidate versions, want 0 (healthy + deprecated only): %+v", len(versions), versions)
	}
	count, err := repo.CountPlatformsMissingSHA256(ctx, configID)
	if err != nil {
		t.Fatalf("CountPlatformsMissingSHA256: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}
