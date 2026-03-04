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
	"encoding/json"
	"fmt"
	"log"
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
	DownloadBinary(ctx context.Context, downloadURL string) ([]byte, string, error)
}

// newReleasesClient constructs the appropriate client for the configured upstream URL.
// GitHub URLs (containing "github.com") use the GitHub Releases API; all other
// URLs use the standard HashiCorp/OpenTofu releases index format.
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
			ConfigID:   cfg.ID,
			Version:    vi.Version,
			SyncStatus: "pending",
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
	groups := make(map[uuid.UUID]*platformGroup)
	for _, p := range pendingPlatforms {
		if _, ok := groups[p.VersionID]; !ok {
			versions, _ := j.repo.ListVersions(ctx, cfg.ID, false)
			for _, vv := range versions {
				if vv.ID == p.VersionID {
					groups[p.VersionID] = &platformGroup{
						version:   vv.Version,
						versionID: vv.ID,
					}
					break
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
	if cfg.GPGVerify && gpgKeyForTool(cfg.Tool) != "" {
		if backfillErr := j.backfillGPGVerification(ctx, client, cfg, allVersions); backfillErr != nil {
			log.Printf("[terraform-mirror] GPG back-fill error for %s: %v", cfg.Name, backfillErr)
		}
	}

	// 7. Mark the highest fully-synced stable version as is_latest.
	if setLatestErr := j.updateLatestVersion(ctx, cfg.ID); setLatestErr != nil {
		log.Printf("[terraform-mirror] failed to update latest version for %s: %v", cfg.Name, setLatestErr)
	}

	return versionsSynced, platformsSynced, versionsFailed, details, nil
}

// syncVersionBinaries downloads and stores binaries for a single version's platforms.
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

	// GPG-verify the SUMS file if enabled.
	sumsGPGVerified := false
	if cfg.GPGVerify && sumsRaw != nil {
		gpgKey := gpgKeyForTool(cfg.Tool)
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
					log.Printf("[terraform-mirror] GPG verification OK for %s SHA256SUMS (%s)", version, cfg.Name)
				}
			}
		} else {
			log.Printf("[terraform-mirror] GPG verify enabled but no key for tool %q — skipping GPG check", cfg.Tool)
		}
	}

	// If GPG verification succeeded, back-fill the flag on any already-synced
	// platforms for this version (they were skipped by ListPendingPlatforms but
	// their gpg_verified column may still be false from the original sync run
	// when no real key was embedded).
	if sumsGPGVerified {
		if backfillErr := j.repo.UpdateGPGVerifiedForVersion(ctx, versionID, true); backfillErr != nil {
			log.Printf("[terraform-mirror] failed to back-fill gpg_verified for version %s: %v", version, backfillErr)
		}
	}

	platformOK := 0
	platformFail := 0
	for _, p := range platforms {
		ok := j.syncOnePlatform(ctx, client, version, p, sums, sumsGPGVerified)
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

// syncOnePlatform downloads a single binary and stores it.
func (j *TerraformMirrorSyncJob) syncOnePlatform(
	ctx context.Context,
	client terraformReleasesClient,
	version string,
	p models.TerraformVersionPlatform,
	sums map[string]string,
	sumsGPGVerified bool,
) bool {
	// Skip if already stored.
	if p.StorageKey != nil {
		exists, err := j.storageBackend.Exists(ctx, *p.StorageKey)
		if err == nil && exists {
			backendName := j.storageBackendName
			_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "synced", p.StorageKey, &backendName, true, sumsGPGVerified, nil)
			return true
		}
	}

	log.Printf("[terraform-mirror] downloading %s (%s/%s)", version, p.OS, p.Arch)

	data, actualSHA256, dlErr := client.DownloadBinary(ctx, p.UpstreamURL)
	if dlErr != nil {
		errStr := dlErr.Error()
		_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, false, false, &errStr)
		log.Printf("[terraform-mirror] download failed for %s %s/%s: %v", version, p.OS, p.Arch, dlErr)
		return false
	}

	sha256Verified := false
	if sums != nil {
		if expectedHash, ok := sums[p.Filename]; ok {
			if strings.EqualFold(actualSHA256, expectedHash) {
				sha256Verified = true
			} else {
				errStr := fmt.Sprintf("sha256 mismatch: got %s want %s", actualSHA256, expectedHash)
				_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, false, false, &errStr)
				log.Printf("[terraform-mirror] SHA256 mismatch for %s %s/%s", version, p.OS, p.Arch)
				return false
			}
		}
	}

	storagePath := fmt.Sprintf("terraform-binaries/%s/%s/%s/%s", version, p.OS, p.Arch, p.Filename)
	_, uploadErr := j.storageBackend.Upload(ctx, storagePath, bytes.NewReader(data), int64(len(data)))
	if uploadErr != nil {
		errStr := uploadErr.Error()
		_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "failed", nil, nil, sha256Verified, sumsGPGVerified, &errStr)
		log.Printf("[terraform-mirror] upload failed for %s %s/%s: %v", version, p.OS, p.Arch, uploadErr)
		return false
	}

	backendName := j.storageBackendName
	_ = j.repo.UpdatePlatformSyncStatus(ctx, p.ID, "synced", &storagePath, &backendName, sha256Verified, sumsGPGVerified, nil)
	log.Printf("[terraform-mirror] stored %s %s/%s -> %s", version, p.OS, p.Arch, storagePath)
	return true
}

// backfillGPGVerification re-verifies the SHA256SUMS GPG signature for any synced
// version that still has gpg_verified=false on its platforms. No binaries are
// re-downloaded — only the lightweight SUMS + signature files are fetched.
func (j *TerraformMirrorSyncJob) backfillGPGVerification(
	ctx context.Context,
	client terraformReleasesClient,
	cfg *models.TerraformMirrorConfig,
	filteredVersions []mirror.TerraformVersionInfo,
) error {
	gpgKey := gpgKeyForTool(cfg.Tool)
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

// updateLatestVersion scans all fully-synced versions for a config and sets is_latest
// on the highest stable semver. Runs inside a DB transaction (via SetLatestVersion).
func (j *TerraformMirrorSyncJob) updateLatestVersion(ctx context.Context, configID uuid.UUID) error {
	syncedVersions, err := j.repo.ListVersions(ctx, configID, true /* syncedOnly */)
	if err != nil || len(syncedVersions) == 0 {
		return err
	}

	stable := make([]models.TerraformVersion, 0, len(syncedVersions))
	for _, v := range syncedVersions {
		if !hasPreReleaseSuffix(v.Version) {
			stable = append(stable, v)
		}
	}

	if len(stable) == 0 {
		stable = syncedVersions
	}

	sort.Slice(stable, func(i, k int) bool {
		return compareTerraformSemver(stable[i].Version, stable[k].Version) > 0
	})

	return j.repo.SetLatestVersion(ctx, configID, stable[0].ID)
}

// ----- Tool helpers ---------------------------------------------------------

// productNameForTool returns the URL path segment for the given tool value.
func productNameForTool(tool string) string {
	switch strings.ToLower(tool) {
	case "opentofu":
		return "opentofu"
	default:
		return "terraform"
	}
}

// gpgKeyForTool returns the PGP public key block for the given tool.
// Returns "" if no key is configured (caller should skip GPG verification).
func gpgKeyForTool(tool string) string {
	switch strings.ToLower(tool) {
	case "terraform":
		return mirror.HashiCorpReleasesGPGKey
	case "opentofu":
		// OpenTofu key requires a non-placeholder value to be embedded.
		// Until the real key is embedded, return "" to skip verification.
		if strings.Contains(mirror.OpenTofuReleasesGPGKey, "<INSERT_OPENTOFU_GPG_KEY_HERE>") {
			return ""
		}
		return mirror.OpenTofuReleasesGPGKey
	default:
		return ""
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
		return compareSemver(sorted[i].Version, sorted[j].Version) > 0
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
		cmp := compareSemver(v.Version, target)
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
