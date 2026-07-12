// terraform_mirror_sync.go implements the background job that keeps all enabled
// Terraform binary mirror configs up to date by periodically fetching the
// releases index from each config's upstream, downloading new binary zips,
// verifying them, and persisting them to the configured storage backend.
//
// Design follows the provider MirrorSyncJob pattern:
//   - One job instance loops over ALL enabled configs on each tick.
//   - Per-config active-sync tracking prevents overlapping runs.
//   - TriggerSync(ctx, configID) allows a single config to be synced on demand.
//   - GPG key selection driven by config.Tool ("terraform" → HashiCorp key,
//     "opentofu" → OpenTofu key, "custom" / gpg_verify=false → skip).
package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
	"github.com/terraform-registry/terraform-registry/internal/safego"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"

	"github.com/google/uuid"
)

// TerraformMirrorSyncJob periodically refreshes all enabled Terraform binary mirror configs.
type TerraformMirrorSyncJob struct {
	repo               *repositories.TerraformMirrorRepository
	storageBackend     storage.Storage
	storageBackendName string

	activeSyncs      map[uuid.UUID]bool
	activeSyncsMutex sync.Mutex

	stopCh    chan struct{}
	startedCh chan struct{}
	wg        sync.WaitGroup

	// manualTriggerCh carries explicit per-config sync requests from HTTP handlers.
	manualTriggerCh chan uuid.UUID
}

// NewTerraformMirrorSyncJob creates a new TerraformMirrorSyncJob.
func NewTerraformMirrorSyncJob(
	repo *repositories.TerraformMirrorRepository,
	storageBackend storage.Storage,
	storageBackendName string,
) *TerraformMirrorSyncJob {
	return &TerraformMirrorSyncJob{
		repo:               repo,
		storageBackend:     storageBackend,
		storageBackendName: storageBackendName,
		activeSyncs:        make(map[uuid.UUID]bool),
		stopCh:             make(chan struct{}),
		startedCh:          make(chan struct{}),
		manualTriggerCh:    make(chan uuid.UUID, 16),
	}
}

// Start begins the background sync loop, checking every intervalMinutes.
func (j *TerraformMirrorSyncJob) Start(ctx context.Context, intervalMinutes int) {
	log.Printf("[terraform-mirror] starting sync job (interval: %d minutes)", intervalMinutes)

	j.wg.Add(1)
	go func() {
		close(j.startedCh)
		defer j.wg.Done()

		ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
		defer ticker.Stop()

		// Run an initial scheduled check immediately on startup.
		j.runScheduledSyncs(ctx)

		for {
			select {
			case <-ticker.C:
				j.runScheduledSyncs(ctx)
			case configID := <-j.manualTriggerCh:
				cid := configID
				safego.Go(func() { j.syncConfig(ctx, cid, "manual") })
			case <-j.stopCh:
				log.Println("[terraform-mirror] sync job stopped")
				return
			case <-ctx.Done():
				log.Println("[terraform-mirror] sync job context cancelled")
				return
			}
		}
	}()
}

// Stop halts the background loop gracefully.
func (j *TerraformMirrorSyncJob) Stop() {
	<-j.startedCh
	close(j.stopCh)
	j.wg.Wait()
}

// TriggerSync enqueues a manual sync for a single config identified by its UUID.
func (j *TerraformMirrorSyncJob) TriggerSync(ctx context.Context, configID uuid.UUID) error {
	select {
	case j.manualTriggerCh <- configID:
		return nil
	default:
		return fmt.Errorf("sync queue is full — a sync for this config may already be running")
	}
}

// ----- Scheduled sync -------------------------------------------------------

func (j *TerraformMirrorSyncJob) runScheduledSyncs(ctx context.Context) {
	configs, err := j.repo.GetConfigsNeedingSync(ctx)
	if err != nil {
		log.Printf("[terraform-mirror] failed to get configs needing sync: %v", err)
		return
	}

	if len(configs) == 0 {
		return
	}

	log.Printf("[terraform-mirror] %d config(s) need syncing", len(configs))

	for _, cfg := range configs {
		cfgID := cfg.ID // capture for goroutine

		j.activeSyncsMutex.Lock()
		if j.activeSyncs[cfgID] {
			log.Printf("[terraform-mirror] config %s (%s) is already syncing, skipping", cfg.Name, cfgID)
			j.activeSyncsMutex.Unlock()
			continue
		}
		j.activeSyncs[cfgID] = true
		j.activeSyncsMutex.Unlock()

		safego.Go(func() { j.doSync(ctx, cfgID, "scheduler") })
	}
}

// syncConfig is the entrypoint for a manual sync trigger.
// coverage:skip:integration-only — delegates to doSync which constructs a live releases client and talks to upstream HTTP + DB; exercised by integration tests.
func (j *TerraformMirrorSyncJob) syncConfig(ctx context.Context, configID uuid.UUID, triggeredBy string) {
	j.activeSyncsMutex.Lock()
	if j.activeSyncs[configID] {
		log.Printf("[terraform-mirror] config %s already syncing, ignoring %s trigger", configID, triggeredBy)
		j.activeSyncsMutex.Unlock()
		return
	}
	j.activeSyncs[configID] = true
	j.activeSyncsMutex.Unlock()

	j.doSync(ctx, configID, triggeredBy)
}

// doSync performs the full sync lifecycle for one config: load, create history, sync, update history.
// coverage:skip:integration-only — drives the complete sync pipeline with a live releases client + storage + DB; exercised by the api-test integration suite.
func (j *TerraformMirrorSyncJob) doSync(ctx context.Context, configID uuid.UUID, triggeredBy string) {
	defer func() {
		j.activeSyncsMutex.Lock()
		delete(j.activeSyncs, configID)
		j.activeSyncsMutex.Unlock()
	}()

	cfg, err := j.repo.GetByID(ctx, configID)
	if err != nil || cfg == nil {
		log.Printf("[terraform-mirror] cannot load config %s for sync: %v", configID, err)
		return
	}

	log.Printf("[terraform-mirror] starting sync for %s (tool: %s, upstream: %s)", cfg.Name, cfg.Tool, cfg.UpstreamURL)

	// Create history record
	histRecord := &models.TerraformSyncHistory{
		ConfigID:    configID,
		TriggeredBy: triggeredBy,
		StartedAt:   time.Now(),
		Status:      "running",
	}
	if createErr := j.repo.CreateSyncHistory(ctx, histRecord); createErr != nil {
		log.Printf("[terraform-mirror] failed to create sync history for %s: %v", cfg.Name, createErr)
	}

	// Run the actual sync
	versionsSynced, platformsSynced, versionsFailed, syncDetails, syncErr := j.performSync(ctx, cfg)

	// Use a cleanup context so history is always recorded even if original ctx was cancelled.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status := "success"
	var errMsg *string
	if syncErr != nil {
		status = "failed"
		s := syncErr.Error()
		errMsg = &s
		log.Printf("[terraform-mirror] sync FAILED for %s: %v", cfg.Name, syncErr)
	} else {
		log.Printf("[terraform-mirror] sync completed for %s: versions=%d platforms=%d failed=%d",
			cfg.Name, versionsSynced, platformsSynced, versionsFailed)
	}

	var detailsStr *string
	if syncDetails != nil {
		if b, err := json.Marshal(syncDetails); err == nil {
			s := string(b)
			detailsStr = &s
		}
	}

	_ = j.repo.CompleteSyncHistory(cleanupCtx, histRecord.ID, status,
		versionsSynced, platformsSynced, versionsFailed, errMsg, detailsStr)
	_ = j.repo.UpdateSyncStatus(cleanupCtx, configID, status, errMsg)
}

// ----- Client interface -----------------------------------------------------

// terraformReleasesClient is satisfied by both TerraformReleasesClient (for
// releases.hashicorp.com / releases.opentofu.org) and GitHubReleasesClient
// (for any github.com upstream URL). Using an interface lets performSync and
// syncVersionBinaries work with either implementation without branching.
type terraformReleasesClient interface {
	ListVersions(ctx context.Context) ([]mirror.TerraformVersionInfo, error)
	FetchSHASums(ctx context.Context, version string) (map[string]string, []byte, error)
	FetchSHASumsSignature(ctx context.Context, version string) ([]byte, error)
	DownloadBinaryStream(ctx context.Context, downloadURL string) (io.ReadCloser, int64, error)
}

// newReleasesClient constructs the appropriate client for the configured upstream URL.
// GitHub URLs (containing "github.com") use the GitHub Releases API; all other
// URLs use the standard HashiCorp/OpenTofu releases index format.
// coverage:skip:integration-only — factory that wires a live HTTP client; covered indirectly via integration tests.
func newReleasesClient(upstreamURL, productName string) (terraformReleasesClient, error) {
	if mirror.IsGitHubReleasesURL(upstreamURL) {
		// GitHub asset filenames use the binary's published prefix, which may differ
		// from the logical product name. For example, OpenTofu publishes assets as
		// "tofu_*" even though the product is called "opentofu".
		binaryPrefix := githubBinaryPrefix(productName)
		return mirror.NewGitHubReleasesClient(upstreamURL, binaryPrefix)
	}
	return mirror.NewTerraformReleasesClient(upstreamURL, productName), nil
}

// githubBinaryPrefix returns the filename prefix used in GitHub release assets
// for a given logical product name. For most tools the prefix equals the product
// name, but OpenTofu is a known exception (binary is "tofu", not "opentofu").
func githubBinaryPrefix(productName string) string {
	switch strings.ToLower(productName) {
	case "opentofu":
		return "tofu"
	default:
		return productName
	}
}

// ----- Sync implementation --------------------------------------------------

// terraformSyncDetails is the JSONB payload stored in terraform_sync_history.
type terraformSyncDetails struct {
	VersionsFound int      `json:"versions_found"`
	Errors        []string `json:"errors,omitempty"`
}

// coverage:skip:integration-only — performs live upstream HTTP + storage + DB writes for the complete sync pipeline; exercised by api-test integration suite.
func (j *TerraformMirrorSyncJob) performSync(
	ctx context.Context,
	cfg *models.TerraformMirrorConfig,
) (versionsSynced, platformsSynced, versionsFailed int, details *terraformSyncDetails, err error) {
	details = &terraformSyncDetails{}

	// Derive product name from the tool field for URL path construction.
	productName := productNameForTool(cfg.Tool)
	client, clientErr := newReleasesClient(cfg.UpstreamURL, productName)
	if clientErr != nil {
		return 0, 0, 0, details, fmt.Errorf("failed to create releases client: %w", clientErr)
	}

	// 1. Fetch version index from upstream.
	allVersions, fetchErr := client.ListVersions(ctx)
	if fetchErr != nil {
		return 0, 0, 0, details, fmt.Errorf("failed to fetch upstream index: %w", fetchErr)
	}

	details.VersionsFound = len(allVersions)

	// 2. Drop pre-release versions when stable_only is enabled.
	// This runs BEFORE the version filter so that filters like "latest:N" select
	// from stable versions only (otherwise "latest:5" might pick 5 alpha releases
	// and stable_only would then discard them all, resulting in 0 synced versions).
	if cfg.StableOnly {
		stable := allVersions[:0]
		for _, v := range allVersions {
			if !hasPreReleaseSuffix(v.Version) {
				stable = append(stable, v)
			}
		}
		allVersions = stable
	}

	// 3. Apply version filter if configured.
	allVersions = filterTerraformVersions(allVersions, cfg.VersionFilter)

	// 4. Parse platform filter from config.
	var allowedPlatforms map[string]bool
	if cfg.PlatformFilter != nil && *cfg.PlatformFilter != "" {
		var platforms []string
		if jsonErr := json.Unmarshal([]byte(*cfg.PlatformFilter), &platforms); jsonErr == nil && len(platforms) > 0 {
			allowedPlatforms = make(map[string]bool, len(platforms))
			for _, p := range platforms {
				allowedPlatforms[strings.ToLower(p)] = true
			}
		}
	}

	// 4. Upsert version + platform rows (metadata only, no downloads yet).
	for _, vi := range allVersions {
		v := &models.TerraformVersion{
			ConfigID:       cfg.ID,
			Version:        vi.Version,
			SyncStatus:     "pending",
			ApprovalStatus: j.resolveTerraformApproval(ctx, cfg, vi.Version),
		}
		if upsertErr := j.repo.UpsertVersion(ctx, v); upsertErr != nil {
			log.Printf("[terraform-mirror] failed to upsert version %s: %v", vi.Version, upsertErr)
			continue
		}

		for _, build := range vi.Builds {
			if allowedPlatforms != nil {
				key := fmt.Sprintf("%s/%s", strings.ToLower(build.OS), strings.ToLower(build.Arch))
				if !allowedPlatforms[key] {
					continue
				}
			}

			p := &models.TerraformVersionPlatform{
				VersionID:   v.ID,
				OS:          build.OS,
				Arch:        build.Arch,
				UpstreamURL: build.URL,
				Filename:    build.Filename,
				SyncStatus:  "pending",
			}
			if upsertErr := j.repo.UpsertPlatform(ctx, p); upsertErr != nil {
				log.Printf("[terraform-mirror] failed to upsert platform %s/%s@%s: %v",
					build.OS, build.Arch, vi.Version, upsertErr)
			}
		}
	}

	// 5. Download pending platform binaries, grouped by version.
	pendingPlatforms, listErr := j.repo.ListPendingPlatforms(ctx, cfg.ID)
	if listErr != nil {
		return 0, 0, 0, details, fmt.Errorf("failed to list pending platforms: %w", listErr)
	}

	// Group platforms by version ID so we only fetch SUMS once per version.
	type platformGroup struct {
		version   string
		versionID uuid.UUID
		platforms []models.TerraformVersionPlatform
	}
	dbVersions, versionsErr := j.repo.ListVersions(ctx, cfg.ID, false)
	if versionsErr != nil {
		return 0, 0, 0, details, fmt.Errorf("failed to list versions for grouping: %w", versionsErr)
	}
	versionByID := make(map[uuid.UUID]models.TerraformVersion, len(dbVersions))
	for _, vv := range dbVersions {
		versionByID[vv.ID] = vv
	}

	groups := make(map[uuid.UUID]*platformGroup)
	for _, p := range pendingPlatforms {
		if _, ok := groups[p.VersionID]; !ok {
			if vv, found := versionByID[p.VersionID]; found {
				groups[p.VersionID] = &platformGroup{
					version:   vv.Version,
					versionID: vv.ID,
				}
			}
		}
		if g, ok := groups[p.VersionID]; ok {
			g.platforms = append(g.platforms, p)
		}
	}

	for _, group := range groups {
		vs, ps, vf := j.syncVersionBinaries(ctx, client, cfg, group.version, group.versionID, group.platforms)
		versionsSynced += vs
		platformsSynced += ps
		versionsFailed += vf
	}

	// 6. GPG back-fill: for synced versions whose platforms have gpg_verified=false,
	// re-verify the SUMS signature and update the flag in-place (no re-download).
	// This covers the case where versions were synced before a real GPG key was embedded.
	if cfg.GPGVerify && gpgKeyForConfig(cfg) != "" {
		if backfillErr := j.backfillGPGVerification(ctx, client, cfg, allVersions); backfillErr != nil {
			log.Printf("[terraform-mirror] GPG back-fill error for %s: %v", cfg.Name, backfillErr)
		}
	}

	// 6b. SHA256 back-fill: for already-synced platforms with sha256='', fetch the
	// upstream SHA256SUMS text (~5KB) and write the per-filename hashes into the
	// sha256 column. No binaries are re-downloaded.
	if backfillErr := j.backfillSHA256(ctx, client, cfg, allVersions); backfillErr != nil {
		log.Printf("[terraform-mirror] SHA256 back-fill error for %s: %v", cfg.Name, backfillErr)
	}

	// 6c. Signature back-fill: upload SHA256SUMS and its detached GPG signature
	// for any already-synced version whose storage keys are still NULL. This
	// covers versions synced before signature persistence was introduced; the
	// public download endpoint will now return populated URLs for them.
	if backfillErr := j.backfillSignatureStorage(ctx, client, cfg, allVersions); backfillErr != nil {
		log.Printf("[terraform-mirror] signature back-fill error for %s: %v", cfg.Name, backfillErr)
	}

	// 6d. Attestation back-fill: for already-synced platforms whose digest is
	// known but attestation_verified is still false, (re-)check the GitHub
	// attestation. Covers an operator flipping verify_github_attestation on
	// after the initial sync — no binaries are re-downloaded, only the small
	// attestation bundle per platform.
	if backfillErr := j.backfillAttestation(ctx, cfg, allVersions); backfillErr != nil {
		log.Printf("[terraform-mirror] attestation back-fill error for %s: %v", cfg.Name, backfillErr)
	}

	// 7. Mark the highest fully-synced stable version as is_latest.
	if setLatestErr := j.updateLatestVersion(ctx, cfg.ID); setLatestErr != nil {
		log.Printf("[terraform-mirror] failed to update latest version for %s: %v", cfg.Name, setLatestErr)
	}

	return versionsSynced, platformsSynced, versionsFailed, details, nil
}

// syncVersionBinaries downloads and stores binaries for a single version's platforms.
// coverage:skip:integration-only — orchestrates real HTTP downloads, GPG verification, and storage writes; covered by integration tests.
func (j *TerraformMirrorSyncJob) syncVersionBinaries(
	ctx context.Context,
	client terraformReleasesClient,
	cfg *models.TerraformMirrorConfig,
	version string,
	versionID uuid.UUID,
	platforms []models.TerraformVersionPlatform,
) (versionsSynced, platformsSynced, versionsFailed int) {
	_ = j.repo.UpdateVersionSyncStatus(ctx, versionID, "syncing", nil)

	// Fetch SHA256SUMS once for the whole version.
	sums, sumsRaw, sumsErr := client.FetchSHASums(ctx, version)
	if sumsErr != nil {
		log.Printf("[terraform-mirror] failed to fetch SHA256SUMS for %s@%s: %v", version, cfg.Name, sumsErr)
		sums = nil
	}

	// GPG-verify the SUMS file if enabled. Capture sigBytes so we can persist
	// it alongside the SUMS file for the public download endpoint to serve.
	sumsGPGVerified := false
	var verifiedSigBytes []byte
	if cfg.GPGVerify && sumsRaw != nil {
		gpgKey := gpgKeyForConfig(cfg)
		if gpgKey != "" {
			sigBytes, sigErr := client.FetchSHASumsSignature(ctx, version)
			if sigErr != nil {
				log.Printf("[terraform-mirror] failed to fetch GPG sig for %s@%s: %v", version, cfg.Name, sigErr)
			} else {
				if verifyErr := validation.VerifySignature(gpgKey, sumsRaw, sigBytes); verifyErr != nil {
					log.Printf("[terraform-mirror] GPG verification FAILED for %s SHA256SUMS (%s): %v",
						version, cfg.Name, verifyErr)
				} else {
					sumsGPGVerified = true
					verifiedSigBytes = sigBytes
					log.Printf("[terraform-mirror] GPG verification OK for %s SHA256SUMS (%s)", version, cfg.Name)
				}
			}
		} else {
			if mirror.IsUnsignedUpstreamTool(cfg.Tool) {
				// OPA (and any other unsigned-upstream tool) publishes no release
				// signature — only per-file SHA-256 checksums, already fetched into
				// `sums` and checked per binary below. Integrity is verified;
				// authenticity cannot be. Surface this honestly rather than as a
				// missing-key warning (the admin signing-keys view shows the same).
				log.Printf("[terraform-mirror] %s publishes no release signature; verifying %s by checksum only (no GPG)", cfg.Tool, version)
			} else {
				log.Printf("[terraform-mirror] GPG verify enabled but no key for tool %q — skipping GPG check", cfg.Tool)
			}
		}
	}

	// Persist SHA256SUMS (always, if we fetched it) and the GPG signature
	// (only when GPG verification succeeded). These are served by the public
	// download endpoint so clients can verify integrity offline.
	j.storeVersionVerificationFiles(ctx, cfg, version, versionID, sumsRaw, verifiedSigBytes)

	// If GPG verification succeeded, back-fill the flag on any already-synced
	// platforms for this version (they were skipped by ListPendingPlatforms but
	// their gpg_verified column may still be false from the original sync run
	// when no real key was embedded).
	if sumsGPGVerified {
		if backfillErr := j.repo.UpdateGPGVerifiedForVersion(ctx, versionID, true); backfillErr != nil {
			log.Printf("[terraform-mirror] failed to back-fill gpg_verified for version %s: %v", version, backfillErr)
		}
	}

	// Build the GitHub attestation verifier once per version (not once per
	// platform — the pinned identity is the same for every binary in this
	// config). nil when the flag is off or the upstream isn't GitHub-hosted,
	// in which case syncOnePlatform skips attestation entirely.
	attestVerifier := attestationVerifierForConfig(cfg)

	platformOK := 0
	platformFail := 0
	for _, p := range platforms {
		ok := j.syncOnePlatform(ctx, client, version, p, sums, sumsGPGVerified, attestVerifier)
		if ok {
			platformOK++
		} else {
			platformFail++
		}
	}

	if platformFail == 0 && platformOK > 0 {
		_ = j.repo.UpdateVersionSyncStatus(ctx, versionID, "synced", nil)
		versionsSynced = 1
	} else if platformOK == 0 {
		_ = j.repo.UpdateVersionSyncStatus(ctx, versionID, "failed", nil)
		versionsFailed = 1
	} else {
		_ = j.repo.UpdateVersionSyncStatus(ctx, versionID, "partial", nil)
		versionsSynced = 1
	}

	platformsSynced = platformOK
	return versionsSynced, platformsSynced, versionsFailed
}

// storeVersionVerificationFiles persists the per-version SHA256SUMS file and
// (when GPG verification succeeded) its detached signature to the storage
// backend, then records the storage keys on terraform_versions so the public
// download endpoint can return URLs for them.
//
// Behaviour:
//   - sumsRaw is uploaded whenever non-nil; the file is small (~few KB) and
//     useful to clients even without GPG.
//   - sigBytes is uploaded only when non-nil, which the caller arranges only
//     after VerifySignature has returned nil — never store an unverified sig.
//   - Storage or DB failures are logged but do not fail the sync run; the
//     binaries are still usable, just without offline GPG verification.
//
// coverage:skip:integration-only — performs storage uploads and DB writes; covered by integration tests.
func (j *TerraformMirrorSyncJob) storeVersionVerificationFiles(
	ctx context.Context,
	cfg *models.TerraformMirrorConfig,
	version string,
	versionID uuid.UUID,
	sumsRaw []byte,
	sigBytes []byte,
) {
	if len(sumsRaw) == 0 && len(sigBytes) == 0 {
		return
	}

	var sumsKey, sigKey *string

	if len(sumsRaw) > 0 {
		path := fmt.Sprintf("terraform-binaries/%s/SHA256SUMS", version)
		if _, err := j.storageBackend.Upload(ctx, path, bytes.NewReader(sumsRaw), int64(len(sumsRaw))); err != nil {
			log.Printf("[terraform-mirror] failed to upload SHA256SUMS for %s@%s: %v", version, cfg.Name, err)
		} else {
			sumsKey = &path
		}
	}

	if len(sigBytes) > 0 {
		path := fmt.Sprintf("terraform-binaries/%s/SHA256SUMS.%s.sig", version, cfg.Tool)
		if _, err := j.storageBackend.Upload(ctx, path, bytes.NewReader(sigBytes), int64(len(sigBytes))); err != nil {
			log.Printf("[terraform-mirror] failed to upload SHA256SUMS sig for %s@%s: %v", version, cfg.Name, err)
		} else {
			sigKey = &path
		}
	}

	if sumsKey == nil && sigKey == nil {
		return
	}

	if err := j.repo.UpdateVersionSignatureStorage(ctx, versionID, sumsKey, sigKey); err != nil {
		log.Printf("[terraform-mirror] failed to persist signature storage keys for %s@%s: %v", version, cfg.Name, err)
	}
}

// syncOnePlatform downloads a single binary and stores it.
// coverage:skip:integration-only — streams a live binary from upstream, checksums it, and uploads to the storage backend; covered by integration tests.
func (j *TerraformMirrorSyncJob) syncOnePlatform(
	ctx context.Context,
	client terraformReleasesClient,
	version string,
	p models.TerraformVersionPlatform,
	sums map[string]string,
	sumsGPGVerified bool,
	attestVerifier attestationVerifier,
) bool {
	// Skip if already stored.
	if p.StorageKey != nil {
		exists, err := j.storageBackend.Exists(ctx, *p.StorageKey)
		if err == nil && exists {
			backendName := j.storageBackendName
			attestationVerified := verifyBinaryAttestation(ctx, attestVerifier, version, p.OS, p.Arch, p.SHA256)
			_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "synced", p.StorageKey, &backendName, true, sumsGPGVerified, attestationVerified, nil)
			return true
		}
	}

	log.Printf("[terraform-mirror] downloading %s (%s/%s)", version, p.OS, p.Arch)

	body, _, dlErr := client.DownloadBinaryStream(ctx, p.UpstreamURL)
	if dlErr != nil {
		errStr := dlErr.Error()
		_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, false, false, false, &errStr)
		log.Printf("[terraform-mirror] download failed for %s %s/%s: %v", version, p.OS, p.Arch, dlErr)
		return false
	}

	tmpFile, tmpErr := os.CreateTemp("", "terraform-binary-*.zip")
	if tmpErr != nil {
		body.Close()
		errStr := fmt.Sprintf("failed to create temp file: %v", tmpErr)
		_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, false, false, false, &errStr)
		return false
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	hasher := sha256.New()
	written, copyErr := io.Copy(tmpFile, io.TeeReader(body, hasher))
	body.Close()
	if copyErr != nil {
		errStr := fmt.Sprintf("failed to stream binary to disk: %v", copyErr)
		_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, false, false, false, &errStr)
		return false
	}
	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))

	sha256Verified := false
	if sums != nil {
		if expectedHash, ok := sums[p.Filename]; ok {
			if strings.EqualFold(actualSHA256, expectedHash) {
				sha256Verified = true
			} else {
				errStr := fmt.Sprintf("sha256 mismatch: got %s want %s", actualSHA256, expectedHash)
				_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, false, false, false, &errStr)
				log.Printf("[terraform-mirror] SHA256 mismatch for %s %s/%s", version, p.OS, p.Arch)
				return false
			}
		}
	}

	if sha256Verified {
		if shaErr := j.repo.UpdatePlatformSHA256(ctx, p.ID, strings.ToLower(actualSHA256)); shaErr != nil {
			log.Printf("[terraform-mirror] failed to persist sha256 for %s %s/%s: %v", version, p.OS, p.Arch, shaErr)
		}
	}

	// GitHub Artifact Attestation verification binds to the digest of the bytes
	// actually downloaded (actualSHA256), independent of whether the upstream's
	// checksum sidecar matched — the whole point is not to trust the same
	// upstream response twice. Absence (older pre-attestation release) and
	// infrastructure unavailability (air-gapped, rate-limited) both degrade to
	// checksum-only rather than failing the platform sync.
	attestationVerified := verifyBinaryAttestation(ctx, attestVerifier, version, p.OS, p.Arch, actualSHA256)

	if _, seekErr := tmpFile.Seek(0, io.SeekStart); seekErr != nil {
		errStr := fmt.Sprintf("failed to seek temp file: %v", seekErr)
		_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, sha256Verified, sumsGPGVerified, attestationVerified, &errStr)
		return false
	}

	storagePath := fmt.Sprintf("terraform-binaries/%s/%s/%s/%s", version, p.OS, p.Arch, p.Filename)
	_, uploadErr := j.storageBackend.Upload(ctx, storagePath, tmpFile, written)
	if uploadErr != nil {
		errStr := uploadErr.Error()
		_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, sha256Verified, sumsGPGVerified, attestationVerified, &errStr)
		log.Printf("[terraform-mirror] upload failed for %s %s/%s: %v", version, p.OS, p.Arch, uploadErr)
		return false
	}

	backendName := j.storageBackendName
	_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "synced", &storagePath, &backendName, sha256Verified, sumsGPGVerified, attestationVerified, nil)
	log.Printf("[terraform-mirror] stored %s %s/%s -> %s", version, p.OS, p.Arch, storagePath)
	return true
}

// backfillSHA256 populates the sha256 column for already-synced platforms whose
// hash was not persisted during their original sync run. It fetches the
// lightweight upstream SHA256SUMS text for each filtered version (~5KB each)
// and writes per-filename hashes — no binary downloads.
// coverage:skip:integration-only — fetches SUMS files over HTTP and writes to the database; covered by integration tests.
func (j *TerraformMirrorSyncJob) backfillSHA256(
	ctx context.Context,
	client terraformReleasesClient,
	cfg *models.TerraformMirrorConfig,
	filteredVersions []mirror.TerraformVersionInfo,
) error {
	wantedVersions := make(map[string]bool, len(filteredVersions))
	for _, vi := range filteredVersions {
		wantedVersions[vi.Version] = true
	}

	syncedVersions, err := j.repo.ListVersions(ctx, cfg.ID, true /* syncedOnly */)
	if err != nil {
		return fmt.Errorf("failed to list synced versions: %w", err)
	}

	for _, sv := range syncedVersions {
		if !wantedVersions[sv.Version] {
			continue
		}

		platforms, plErr := j.repo.ListPlatformsForVersion(ctx, sv.ID)
		if plErr != nil {
			log.Printf("[terraform-mirror] sha256 backfill: failed to list platforms for %s: %v", sv.Version, plErr)
			continue
		}
		needsBackfill := false
		for _, p := range platforms {
			if p.SyncStatus == "synced" && p.SHA256 == "" {
				needsBackfill = true
				break
			}
		}
		if !needsBackfill {
			continue
		}

		sums, _, sumsErr := client.FetchSHASums(ctx, sv.Version)
		if sumsErr != nil {
			log.Printf("[terraform-mirror] sha256 backfill: failed to fetch SUMS for %s: %v", sv.Version, sumsErr)
			continue
		}
		if len(sums) == 0 {
			continue
		}
		if bfErr := j.repo.BackfillPlatformSHA256(ctx, sv.ID, sums); bfErr != nil {
			log.Printf("[terraform-mirror] sha256 backfill: DB update failed for %s: %v", sv.Version, bfErr)
			continue
		}
		log.Printf("[terraform-mirror] sha256 backfill: populated hashes for version %s", sv.Version)
	}

	return nil
}

// backfillGPGVerification re-verifies the SHA256SUMS GPG signature for any synced
// version that still has gpg_verified=false on its platforms. No binaries are
// re-downloaded — only the lightweight SUMS + signature files are fetched.
// coverage:skip:integration-only — fetches SUMS files over HTTP and writes to the database; covered by integration tests.
func (j *TerraformMirrorSyncJob) backfillGPGVerification(
	ctx context.Context,
	client terraformReleasesClient,
	cfg *models.TerraformMirrorConfig,
	filteredVersions []mirror.TerraformVersionInfo,
) error {
	gpgKey := gpgKeyForConfig(cfg)
	if gpgKey == "" {
		return nil
	}

	// Build a set of version strings we care about (already filtered by version/platform/stable rules).
	wantedVersions := make(map[string]bool, len(filteredVersions))
	for _, vi := range filteredVersions {
		wantedVersions[vi.Version] = true
	}

	// Load all synced versions for this config.
	syncedVersions, err := j.repo.ListVersions(ctx, cfg.ID, true /* syncedOnly */)
	if err != nil {
		return fmt.Errorf("failed to list synced versions: %w", err)
	}

	for _, sv := range syncedVersions {
		if !wantedVersions[sv.Version] {
			continue
		}

		// Check if any platform for this version still has gpg_verified=false.
		platforms, plErr := j.repo.ListPlatformsForVersion(ctx, sv.ID)
		if plErr != nil {
			log.Printf("[terraform-mirror] backfill: failed to list platforms for %s: %v", sv.Version, plErr)
			continue
		}
		needsBackfill := false
		for _, p := range platforms {
			if !p.GPGVerified {
				needsBackfill = true
				break
			}
		}
		if !needsBackfill {
			continue
		}

		// Fetch and verify the SUMS signature — no binary download needed.
		_, sumsRaw, sumsErr := client.FetchSHASums(ctx, sv.Version)
		if sumsErr != nil {
			log.Printf("[terraform-mirror] backfill: failed to fetch SHA256SUMS for %s: %v", sv.Version, sumsErr)
			continue
		}
		sigBytes, sigErr := client.FetchSHASumsSignature(ctx, sv.Version)
		if sigErr != nil {
			log.Printf("[terraform-mirror] backfill: failed to fetch GPG sig for %s: %v", sv.Version, sigErr)
			continue
		}
		if verifyErr := validation.VerifySignature(gpgKey, sumsRaw, sigBytes); verifyErr != nil {
			log.Printf("[terraform-mirror] backfill: GPG verification FAILED for %s: %v", sv.Version, verifyErr)
			continue
		}

		log.Printf("[terraform-mirror] backfill: GPG verification OK for %s — updating platforms", sv.Version)
		if updErr := j.repo.UpdateGPGVerifiedForVersion(ctx, sv.ID, true); updErr != nil {
			log.Printf("[terraform-mirror] backfill: failed to update gpg_verified for %s: %v", sv.Version, updErr)
		}
	}

	return nil
}

// backfillSignatureStorage uploads the per-version SHA256SUMS file and (when
// GPG verification succeeds) its detached signature for any already-synced
// version whose sums_storage_key or sig_storage_key column is still NULL.
// This covers versions synced before signature persistence was introduced.
// Binaries are never re-downloaded — only the small SUMS + signature files.
// coverage:skip:integration-only — fetches SUMS/sig files over HTTP and writes to storage + DB; covered by integration tests.
func (j *TerraformMirrorSyncJob) backfillSignatureStorage(
	ctx context.Context,
	client terraformReleasesClient,
	cfg *models.TerraformMirrorConfig,
	filteredVersions []mirror.TerraformVersionInfo,
) error {
	// Limit work to versions the operator has actually opted into via the
	// platform/version/stable filters.
	wantedVersions := make(map[string]bool, len(filteredVersions))
	for _, vi := range filteredVersions {
		wantedVersions[vi.Version] = true
	}

	syncedVersions, err := j.repo.ListVersions(ctx, cfg.ID, true /* syncedOnly */)
	if err != nil {
		return fmt.Errorf("failed to list synced versions: %w", err)
	}

	gpgKey := gpgKeyForConfig(cfg)

	for _, sv := range syncedVersions {
		if !wantedVersions[sv.Version] {
			continue
		}
		// Skip versions that already have at least the SUMS stored. A sig may
		// still be missing if GPG was disabled the first time around, but we
		// re-attempt that on every sync to pick up a newly-configured key.
		sumsAlreadyStored := sv.SumsStorageKey != nil && *sv.SumsStorageKey != ""
		sigAlreadyStored := sv.SigStorageKey != nil && *sv.SigStorageKey != ""
		if sumsAlreadyStored && (sigAlreadyStored || !cfg.GPGVerify || gpgKey == "") {
			continue
		}

		_, sumsRaw, sumsErr := client.FetchSHASums(ctx, sv.Version)
		if sumsErr != nil {
			log.Printf("[terraform-mirror] sig backfill: failed to fetch SHA256SUMS for %s: %v", sv.Version, sumsErr)
			continue
		}

		var verifiedSigBytes []byte
		if cfg.GPGVerify && gpgKey != "" {
			sigBytes, sigErr := client.FetchSHASumsSignature(ctx, sv.Version)
			if sigErr != nil {
				log.Printf("[terraform-mirror] sig backfill: failed to fetch GPG sig for %s: %v", sv.Version, sigErr)
			} else if verifyErr := validation.VerifySignature(gpgKey, sumsRaw, sigBytes); verifyErr != nil {
				log.Printf("[terraform-mirror] sig backfill: GPG verification FAILED for %s: %v", sv.Version, verifyErr)
			} else {
				verifiedSigBytes = sigBytes
			}
		}

		// Reuse the same upload helper used during the normal sync path so
		// storage path conventions and DB updates stay consistent.
		j.storeVersionVerificationFiles(ctx, cfg, sv.Version, sv.ID, sumsRaw, verifiedSigBytes)
	}

	return nil
}

// backfillAttestation re-checks the GitHub Artifact Attestation for any synced
// platform whose digest is known (sha256 != "") but attestation_verified is
// still false. Unlike GPG (one signature per version), an attestation is
// per-binary-digest, so this walks platforms individually rather than
// flipping a single flag for the whole version. A no-op when the flag is off
// or the upstream isn't GitHub-hosted (attestationVerifierForConfig returns
// nil). No binaries are re-downloaded — only the small attestation bundle.
// coverage:skip:integration-only — calls the live GitHub attestation API and writes to the database; covered by integration tests.
func (j *TerraformMirrorSyncJob) backfillAttestation(
	ctx context.Context,
	cfg *models.TerraformMirrorConfig,
	filteredVersions []mirror.TerraformVersionInfo,
) error {
	verifier := attestationVerifierForConfig(cfg)
	if verifier == nil {
		return nil
	}

	wantedVersions := make(map[string]bool, len(filteredVersions))
	for _, vi := range filteredVersions {
		wantedVersions[vi.Version] = true
	}

	syncedVersions, err := j.repo.ListVersions(ctx, cfg.ID, true /* syncedOnly */)
	if err != nil {
		return fmt.Errorf("failed to list synced versions: %w", err)
	}

	for _, sv := range syncedVersions {
		if !wantedVersions[sv.Version] {
			continue
		}
		platforms, plErr := j.repo.ListPlatformsForVersion(ctx, sv.ID)
		if plErr != nil {
			log.Printf("[terraform-mirror] attestation backfill: failed to list platforms for %s: %v", sv.Version, plErr)
			continue
		}
		for _, p := range platforms {
			if p.SyncStatus != "synced" || p.SHA256 == "" || p.AttestationVerified {
				continue
			}
			if !verifyBinaryAttestation(ctx, verifier, sv.Version, p.OS, p.Arch, p.SHA256) {
				continue
			}
			if updErr := j.repo.UpdatePlatformAttestationVerified(ctx, p.ID, true); updErr != nil {
				log.Printf("[terraform-mirror] attestation backfill: failed to update platform %s: %v", p.ID, updErr)
			}
		}
	}

	return nil
}

// updateLatestVersion scans all fully-synced versions for a config and sets is_latest
// on the highest stable semver. Runs inside a DB transaction (via SetLatestVersion).
// coverage:skip:requires-database — selects and updates synced-version rows; covered by integration tests.
func (j *TerraformMirrorSyncJob) updateLatestVersion(ctx context.Context, configID uuid.UUID) error {
	syncedVersions, err := j.repo.ListVersions(ctx, configID, true /* syncedOnly */)
	if err != nil || len(syncedVersions) == 0 {
		return err
	}

	// Exclude versions that are gated and not yet approved — "latest" must never
	// resolve to a pending or rejected version.
	visible := make([]models.TerraformVersion, 0, len(syncedVersions))
	for _, v := range syncedVersions {
		if v.ApprovalStatus == nil || *v.ApprovalStatus == models.VersionApprovalStatusApproved {
			visible = append(visible, v)
		}
	}
	if len(visible) == 0 {
		return nil // nothing approved/visible yet — leave is_latest unset
	}

	stable := make([]models.TerraformVersion, 0, len(visible))
	for _, v := range visible {
		if !hasPreReleaseSuffix(v.Version) {
			stable = append(stable, v)
		}
	}

	if len(stable) == 0 {
		stable = visible
	}

	sort.Slice(stable, func(i, k int) bool {
		return compareTerraformSemver(stable[i].Version, stable[k].Version) > 0
	})

	return j.repo.SetLatestVersion(ctx, configID, stable[0].ID)
}

// resolveTerraformApproval decides the approval_status for a freshly discovered
// terraform version. Returns nil when the mirror is not gated, otherwise a
// pending pointer unless an auto-approve rule matches at sync time. GPG
// verification is per-platform and not yet known here, so the gpg_verified rule
// does not fire at discovery time (delay_hours is handled by the periodic sweep).
func (j *TerraformMirrorSyncJob) resolveTerraformApproval(ctx context.Context, cfg *models.TerraformMirrorConfig, version string) *string {
	if !cfg.RequiresApproval {
		return nil
	}
	pending := models.VersionApprovalStatusPending
	approved := models.VersionApprovalStatusApproved

	rules, err := mirror.ParseAutoApproveRules(cfg.AutoApproveRules)
	if err != nil || rules == nil {
		return &pending
	}

	var existing []string
	if vs, lErr := j.repo.ListVersions(ctx, cfg.ID, false); lErr == nil {
		for _, v := range vs {
			existing = append(existing, v.Version)
		}
	}

	matched, _ := mirror.EvaluateAutoApprove(rules, mirror.AutoApproveInput{
		Version:          version,
		GPGVerified:      false,
		ExistingVersions: existing,
		VersionAge:       0,
	})
	if matched {
		return &approved
	}
	return &pending
}

// ----- Tool helpers ---------------------------------------------------------

// productNameForTool returns the URL path segment for the given tool value.
func productNameForTool(tool string) string {
	switch strings.ToLower(tool) {
	case "opentofu":
		return "opentofu"
	case "packer":
		return "packer"
	case "sentinel":
		return "sentinel"
	case "opa":
		return "opa"
	case "terraform-docs":
		return "terraform-docs"
	default:
		return "terraform"
	}
}

// ReleasesKeyResolver returns the ASCII-armored release-signing key for the
// given tool, preferring a fresh upstream snapshot over the embedded fallback.
// Implementations must return "" only when no key (cached or embedded) is
// available so callers can correctly choose to skip GPG verification.
type ReleasesKeyResolver interface {
	ResolveReleasesKey(tool string) string
}

// releasesKeyResolver is the package-level hook used by gpgKeyForTool. It is
// nil by default — gpgKeyForTool then returns the embedded snapshot directly,
// preserving the original behavior for tests and for deployments that have not
// wired in the auto-refresh job. main.go calls SetReleasesKeyResolver during
// startup to install the cache-aware resolver.
var releasesKeyResolver ReleasesKeyResolver

// SetReleasesKeyResolver installs a resolver consulted by gpgKeyForTool before
// it falls back to the embedded constants. Passing nil clears the hook.
func SetReleasesKeyResolver(r ReleasesKeyResolver) {
	releasesKeyResolver = r
}

// gpgKeyForTool returns the PGP public key block for the given tool.
// Returns "" if no key is configured (caller should skip GPG verification).
// When a resolver is installed via SetReleasesKeyResolver it is consulted
// first; the embedded snapshot is used only when the resolver returns "".
func gpgKeyForTool(tool string) string {
	if releasesKeyResolver != nil {
		if k := releasesKeyResolver.ResolveReleasesKey(tool); k != "" {
			return k
		}
	}
	switch strings.ToLower(tool) {
	case "terraform", "packer", "sentinel":
		return mirror.HashiCorpReleasesGPGKey
	case "opentofu":
		return mirror.OpenTofuReleasesGPGKey
	default:
		return ""
	}
}

// gpgKeyForConfig returns the GPG key to use for a given mirror config,
// checking custom config fields before falling back to the built-in key.
// Returns "" if GPG verification should be skipped.
func gpgKeyForConfig(cfg *models.TerraformMirrorConfig) string {
	if cfg.SkipGPGVerify {
		return ""
	}
	if cfg.CustomGPGKey != nil && *cfg.CustomGPGKey != "" {
		return *cfg.CustomGPGKey
	}
	return gpgKeyForTool(cfg.Tool)
}

// ----- GitHub Artifact Attestation helpers ----------------------------------

// attestationVerifier is satisfied by *mirror.GitHubAttestationVerifier. The
// seam lets tests inject a fake to exercise verifyBinaryAttestation's found /
// not-found / unavailable / failed branches without live network or Sigstore
// trust-root access (both are integration-only, like the releases clients).
type attestationVerifier interface {
	VerifyBinaryAttestation(ctx context.Context, sha256Hex string) error
}

// attestationVerifierForConfig builds the per-config GitHub attestation
// verifier when the operator has opted in. Returns nil when the flag is off
// or the upstream is not GitHub-hosted (the attestation API is GitHub-only —
// releases.hashicorp.com and releases.opentofu.org have no equivalent), in
// which case callers skip attestation entirely and stay checksum-only.
func attestationVerifierForConfig(cfg *models.TerraformMirrorConfig) attestationVerifier {
	if !cfg.VerifyGitHubAttestation || !mirror.IsGitHubReleasesURL(cfg.UpstreamURL) {
		return nil
	}
	v, err := mirror.NewGitHubAttestationVerifier(cfg.UpstreamURL)
	if err != nil {
		log.Printf("[terraform-mirror] cannot build GitHub attestation verifier for %s: %v", cfg.UpstreamURL, err)
		return nil
	}
	return v
}

// verifyBinaryAttestation runs attestation verification for one platform
// binary's digest and returns whether it succeeded, logging the outcome. A nil
// verifier or an empty digest are no-ops (attestation disabled, or the digest
// isn't known yet — e.g. an already-stored platform whose sha256 column was
// never back-filled). Absence of an attestation (older, pre-attestation
// releases) and infrastructure unavailability (offline/air-gapped, GitHub API
// errors) are both logged and treated as graceful degradation to
// checksum-only — never a hard failure of the platform sync.
func verifyBinaryAttestation(ctx context.Context, verifier attestationVerifier, version, os, arch, sha256Hex string) bool {
	if verifier == nil || sha256Hex == "" {
		return false
	}

	err := verifier.VerifyBinaryAttestation(ctx, sha256Hex)
	switch {
	case err == nil:
		log.Printf("[terraform-mirror] GitHub attestation verification OK for %s %s/%s", version, os, arch)
		return true
	case errors.Is(err, mirror.ErrAttestationNotFound):
		log.Printf("[terraform-mirror] no GitHub attestation found for %s %s/%s (pre-attestation release?) — checksum-only", version, os, arch)
		return false
	case errors.Is(err, mirror.ErrAttestationUnavailable):
		log.Printf("[terraform-mirror] WARNING: GitHub attestation verification unavailable for %s %s/%s (offline/rate-limited?): %v — falling back to checksum-only", version, os, arch, err)
		return false
	default:
		log.Printf("[terraform-mirror] GitHub attestation verification FAILED for %s %s/%s: %v", version, os, arch, err)
		return false
	}
}

// ----- Semver helpers -------------------------------------------------------

func hasPreReleaseSuffix(version string) bool {
	v := strings.TrimPrefix(version, "v")
	return strings.Contains(v, "-") || strings.Contains(v, "+")
}

func compareTerraformSemver(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	if idx := strings.IndexAny(a, "-+"); idx != -1 {
		a = a[:idx]
	}
	if idx := strings.IndexAny(b, "-+"); idx != -1 {
		b = b[:idx]
	}

	aParts := splitSemver(a)
	bParts := splitSemver(b)

	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}

	return 0
}

func splitSemver(v string) [3]int {
	var result [3]int
	parts := strings.SplitN(v, ".", 4)
	for i := 0; i < 3 && i < len(parts); i++ {
		n := 0
		for _, ch := range parts[i] {
			if ch >= '0' && ch <= '9' {
				n = n*10 + int(ch-'0')
			}
		}
		result[i] = n
	}
	return result
}

// filterTerraformVersions applies the version_filter expression to a slice of
// TerraformVersionInfo entries. The filter syntax mirrors that of the provider
// mirror's filterVersions helper:
//
//	"1.9." or "1.9"    – prefix match
//	"latest:N"          – N most recent by semver
//	">=1.5.0"           – semver constraint (>=, >, <=, <)
//	"1.5.0,1.6.0"       – comma-separated exact versions
//	"1.9.8"             – single exact version
//
// A nil or empty filter returns all versions unchanged.
func filterTerraformVersions(versions []mirror.TerraformVersionInfo, filter *string) []mirror.TerraformVersionInfo {
	if filter == nil || strings.TrimSpace(*filter) == "" {
		return versions
	}

	fs := strings.TrimSpace(*filter)

	// latest:N
	if strings.HasPrefix(fs, "latest:") {
		countStr := strings.TrimPrefix(fs, "latest:")
		count, err := strconv.Atoi(countStr)
		if err != nil || count <= 0 {
			log.Printf("[terraform-mirror] invalid latest:N filter %q – returning all versions", fs)
			return versions
		}
		return filterTFLatest(versions, count)
	}

	// Prefix with trailing dot or .x  (e.g. "1.9." or "1.9.x")
	if strings.HasSuffix(fs, ".") || strings.HasSuffix(fs, ".x") {
		prefix := strings.TrimSuffix(fs, "x")
		return filterTFByPrefix(versions, prefix)
	}

	// Semver constraints
	if strings.HasPrefix(fs, ">=") || strings.HasPrefix(fs, ">") ||
		strings.HasPrefix(fs, "<=") || strings.HasPrefix(fs, "<") {
		return filterTFBySemver(versions, fs)
	}

	// Comma-separated list — each token uses the same single-token logic
	// (prefix-first, then exact), so "1.13., 1.14." and "1.13, 1.14" both work.
	if strings.Contains(fs, ",") {
		return filterTFByTokenList(versions, fs)
	}

	// Single token: try prefix first, then exact match
	if filtered := filterTFByPrefix(versions, fs+"."); len(filtered) > 0 {
		return filtered
	}
	return filterTFByList(versions, fs)
}

func filterTFLatest(versions []mirror.TerraformVersionInfo, count int) []mirror.TerraformVersionInfo {
	if len(versions) <= count {
		return versions
	}
	sorted := make([]mirror.TerraformVersionInfo, len(versions))
	copy(sorted, versions)
	sort.Slice(sorted, func(i, j int) bool {
		return mirror.CompareSemver(sorted[i].Version, sorted[j].Version) > 0
	})
	return sorted[:count]
}

func filterTFByPrefix(versions []mirror.TerraformVersionInfo, prefix string) []mirror.TerraformVersionInfo {
	var out []mirror.TerraformVersionInfo
	for _, v := range versions {
		if strings.HasPrefix(v.Version, prefix) {
			out = append(out, v)
		}
	}
	return out
}

func filterTFByList(versions []mirror.TerraformVersionInfo, list string) []mirror.TerraformVersionInfo {
	wanted := make(map[string]bool)
	for _, s := range strings.Split(list, ",") {
		wanted[strings.TrimSpace(s)] = true
	}
	var out []mirror.TerraformVersionInfo
	for _, v := range versions {
		if wanted[v.Version] {
			out = append(out, v)
		}
	}
	return out
}

// filterTFByTokenList applies single-token logic (prefix-first, then exact) to each
// comma-separated token, union-ing the results. This allows "1.13., 1.14." and
// "1.13, 1.14" to both work as prefix matches.
func filterTFByTokenList(versions []mirror.TerraformVersionInfo, list string) []mirror.TerraformVersionInfo {
	seen := make(map[string]bool)
	var out []mirror.TerraformVersionInfo
	for _, token := range strings.Split(list, ",") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		var matched []mirror.TerraformVersionInfo
		if strings.HasSuffix(t, ".") || strings.HasSuffix(t, ".x") {
			prefix := strings.TrimSuffix(t, "x")
			matched = filterTFByPrefix(versions, prefix)
		} else if filtered := filterTFByPrefix(versions, t+"."); len(filtered) > 0 {
			matched = filtered
		} else {
			matched = filterTFByList(versions, t)
		}
		for _, v := range matched {
			if !seen[v.Version] {
				seen[v.Version] = true
				out = append(out, v)
			}
		}
	}
	return out
}

func filterTFBySemver(versions []mirror.TerraformVersionInfo, constraint string) []mirror.TerraformVersionInfo {
	var op, target string
	switch {
	case strings.HasPrefix(constraint, ">="):
		op, target = ">=", strings.TrimSpace(strings.TrimPrefix(constraint, ">="))
	case strings.HasPrefix(constraint, "<="):
		op, target = "<=", strings.TrimSpace(strings.TrimPrefix(constraint, "<="))
	case strings.HasPrefix(constraint, ">"):
		op, target = ">", strings.TrimSpace(strings.TrimPrefix(constraint, ">"))
	case strings.HasPrefix(constraint, "<"):
		op, target = "<", strings.TrimSpace(strings.TrimPrefix(constraint, "<"))
	default:
		return versions
	}
	var out []mirror.TerraformVersionInfo
	for _, v := range versions {
		cmp := mirror.CompareSemver(v.Version, target)
		include := false
		switch op {
		case ">=":
			include = cmp >= 0
		case "<=":
			include = cmp <= 0
		case ">":
			include = cmp > 0
		case "<":
			include = cmp < 0
		}
		if include {
			out = append(out, v)
		}
	}
	return out
}
