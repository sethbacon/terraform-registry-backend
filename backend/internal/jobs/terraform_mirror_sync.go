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
	client := mirror.NewTerraformReleasesClient(cfg.UpstreamURL, productName)

	// 1. Fetch version index from upstream.
	allVersions, fetchErr := client.ListVersions(ctx)
	if fetchErr != nil {
		return 0, 0, 0, details, fmt.Errorf("failed to fetch upstream index: %w", fetchErr)
	}

	details.VersionsFound = len(allVersions)

	// 2. Parse platform filter from config.
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

	// 3. Upsert version + platform rows (metadata only, no downloads yet).
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

	// 4. Download pending platform binaries, grouped by version.
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

	// 5. Mark the highest fully-synced stable version as is_latest.
	if setLatestErr := j.updateLatestVersion(ctx, cfg.ID); setLatestErr != nil {
		log.Printf("[terraform-mirror] failed to update latest version for %s: %v", cfg.Name, setLatestErr)
	}

	return versionsSynced, platformsSynced, versionsFailed, details, nil
}

// syncVersionBinaries downloads and stores binaries for a single version's platforms.
func (j *TerraformMirrorSyncJob) syncVersionBinaries(
	ctx context.Context,
	client *mirror.TerraformReleasesClient,
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
	client *mirror.TerraformReleasesClient,
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
