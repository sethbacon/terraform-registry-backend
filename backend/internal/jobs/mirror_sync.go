// Package jobs contains background workers that run on a schedule.
// The mirror sync job periodically fetches new provider versions from upstream registries; the tag verifier confirms that SCM-linked module tags have been correctly published.
// Jobs are designed to be idempotent — re-running after a crash produces the same result as a clean run.
package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
	"github.com/terraform-registry/terraform-registry/internal/safego"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"
	"github.com/terraform-registry/terraform-registry/pkg/checksum"

	"github.com/google/uuid"
)

// safeString returns the string value or "(none)" if nil
func safeString(s *string) string {
	if s == nil {
		return "(none)"
	}
	return *s
}

// filterPlatforms filters platforms based on a JSON array of "os/arch" strings
// If filter is nil or empty, all platforms are returned
func filterPlatforms(platforms []mirror.ProviderPlatform, filter *string) []mirror.ProviderPlatform {
	if filter == nil || *filter == "" {
		return platforms
	}

	// Parse the filter
	var allowedPlatforms []string
	if err := json.Unmarshal([]byte(*filter), &allowedPlatforms); err != nil {
		// If parsing fails, return all platforms
		return platforms
	}

	if len(allowedPlatforms) == 0 {
		return platforms
	}

	// Build a set of allowed platforms for fast lookup
	allowedSet := make(map[string]bool)
	for _, p := range allowedPlatforms {
		allowedSet[strings.ToLower(strings.TrimSpace(p))] = true
	}

	// Filter platforms
	var filtered []mirror.ProviderPlatform
	for _, platform := range platforms {
		platformKey := fmt.Sprintf("%s/%s", strings.ToLower(platform.OS), strings.ToLower(platform.Arch))
		if allowedSet[platformKey] {
			filtered = append(filtered, platform)
		}
	}

	return filtered
}

// MirrorSyncJob handles the synchronization of providers from upstream registries
type MirrorSyncJob struct {
	mirrorRepo         *repositories.MirrorRepository
	providerRepo       *repositories.ProviderRepository
	providerDocsRepo   *repositories.ProviderDocsRepository
	orgRepo            *repositories.OrganizationRepository
	storageBackend     storage.Storage
	storageBackendName string
	activeSyncs        map[uuid.UUID]bool
	activeSyncsMutex   sync.Mutex
	stopCh             chan struct{}
	startedCh          chan struct{} // closed when the Start goroutine is scheduled and running
	wg                 sync.WaitGroup

	// newUpstream is the factory used to build an UpstreamRegistryClient from a
	// base URL.  It defaults to mirror.NewUpstreamRegistry; tests may override it
	// via SetUpstreamFactory to inject a fake client without performing real HTTP.
	newUpstream func(baseURL string) mirror.UpstreamRegistryClient
}

// NewMirrorSyncJob creates a new mirror sync job
func NewMirrorSyncJob(
	mirrorRepo *repositories.MirrorRepository,
	providerRepo *repositories.ProviderRepository,
	providerDocsRepo *repositories.ProviderDocsRepository,
	orgRepo *repositories.OrganizationRepository,
	storageBackend storage.Storage,
	storageBackendName string,
) *MirrorSyncJob {
	return &MirrorSyncJob{
		mirrorRepo:         mirrorRepo,
		providerRepo:       providerRepo,
		providerDocsRepo:   providerDocsRepo,
		orgRepo:            orgRepo,
		storageBackend:     storageBackend,
		storageBackendName: storageBackendName,
		activeSyncs:        make(map[uuid.UUID]bool),
		activeSyncsMutex:   sync.Mutex{},
		stopCh:             make(chan struct{}),
		startedCh:          make(chan struct{}),
		newUpstream: func(baseURL string) mirror.UpstreamRegistryClient {
			return mirror.NewUpstreamRegistry(baseURL)
		},
	}
}

// SetUpstreamFactory replaces the upstream-client factory.  Intended for tests
// that want to substitute a fake mirror.UpstreamRegistryClient; production
// callers should rely on the default factory installed by NewMirrorSyncJob.
func (j *MirrorSyncJob) SetUpstreamFactory(f func(baseURL string) mirror.UpstreamRegistryClient) {
	j.newUpstream = f
}

// Start begins the periodic sync job
func (j *MirrorSyncJob) Start(ctx context.Context, intervalMinutes int) {
	log.Printf("Starting mirror sync job with interval of %d minutes", intervalMinutes)

	// Reset any syncs left in 'in_progress' / 'running' state from a previous process crash.
	if n, err := j.mirrorRepo.ResetStaleSyncs(ctx); err != nil {
		log.Printf("Warning: failed to reset stale syncs on startup: %v", err)
	} else if n > 0 {
		log.Printf("Reset %d stale sync history record(s) from previous process", n)
	}

	j.wg.Add(1)
	go func() {
		close(j.startedCh) // signal that the goroutine is running (wg.Add already done)
		defer j.wg.Done()

		ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
		defer ticker.Stop()

		// Run initial sync immediately
		j.runScheduledSyncs(ctx)

		for {
			select {
			case <-ticker.C:
				j.runScheduledSyncs(ctx)
			case <-j.stopCh:
				log.Println("Mirror sync job stopped")
				return
			case <-ctx.Done():
				log.Println("Mirror sync job context cancelled")
				return
			}
		}
	}()
}

// Stop stops the sync job. It waits for the Start goroutine to be scheduled
// before signalling it to exit, avoiding a race between wg.Add (in Start) and
// wg.Wait (in Stop) when Start and Stop are called concurrently.
func (j *MirrorSyncJob) Stop() {
	<-j.startedCh // ensure wg.Add(1) has been called before wg.Wait()
	close(j.stopCh)
	j.wg.Wait()
}

// runScheduledSyncs checks for mirrors that need syncing and triggers them
func (j *MirrorSyncJob) runScheduledSyncs(ctx context.Context) {
	mirrors, err := j.mirrorRepo.GetMirrorsNeedingSync(ctx)
	if err != nil {
		log.Printf("Error getting mirrors needing sync: %v", err)
		return
	}

	if len(mirrors) == 0 {
		log.Println("No mirrors need syncing at this time")
		return
	}

	log.Printf("Found %d mirrors needing sync", len(mirrors))

	for _, mirror := range mirrors {
		// Check if this mirror is already syncing
		j.activeSyncsMutex.Lock()
		if j.activeSyncs[mirror.ID] {
			log.Printf("Mirror %s is already syncing, skipping", mirror.Name)
			j.activeSyncsMutex.Unlock()
			continue
		}
		j.activeSyncs[mirror.ID] = true
		j.activeSyncsMutex.Unlock()

		// Run sync in a goroutine with panic recovery
		mirrorCopy := mirror
		safego.Go(func() { j.syncMirror(ctx, mirrorCopy) })
	}
}

// syncMirror performs the actual synchronization of a mirror.
// coverage:skip:integration-only — constructs a live mirror.UpstreamRegistry HTTP client inline and drives sync history + status writes to the database; tested end-to-end via the api-test integration suite in cmd/api-test.
func (j *MirrorSyncJob) syncMirror(ctx context.Context, config models.MirrorConfiguration) {
	defer func() {
		j.activeSyncsMutex.Lock()
		delete(j.activeSyncs, config.ID)
		j.activeSyncsMutex.Unlock()
	}()

	log.Printf("Starting sync for mirror: %s (ID: %s)", config.Name, config.ID)

	// Create sync history record
	syncHistory := &models.MirrorSyncHistory{
		ID:             uuid.New(),
		MirrorConfigID: config.ID,
		StartedAt:      time.Now(),
		Status:         "running",
	}

	if err := j.mirrorRepo.CreateSyncHistory(ctx, syncHistory); err != nil {
		log.Printf("Error creating sync history for mirror %s: %v", config.Name, err)
		return
	}

	// Update mirror config status to in_progress
	if err := j.mirrorRepo.UpdateSyncStatus(ctx, config.ID, "in_progress", nil); err != nil {
		log.Printf("Error updating sync status for mirror %s: %v", config.Name, err)
	}

	// Perform the actual sync
	syncDetails, err := j.performSync(ctx, config)

	// Create a new context for cleanup operations to ensure they complete even if the original context is cancelled
	// Use a background context with a reasonable timeout
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cleanupCancel()

	// Update sync history with results
	now := time.Now()
	syncHistory.CompletedAt = &now

	// Copy sync details to history
	if syncDetails != nil {
		syncHistory.ProvidersSynced = syncDetails.ProvidersSynced
		syncHistory.ProvidersFailed = syncDetails.ProvidersFailed
	}

	if err != nil {
		log.Printf("Sync failed for mirror %s: %v", config.Name, err)
		syncHistory.Status = "failed"
		errMsg := err.Error()
		syncHistory.ErrorMessage = &errMsg

		// Update mirror config with error (use cleanupCtx)
		if updateErr := j.mirrorRepo.UpdateSyncStatus(cleanupCtx, config.ID, "failed", &errMsg); updateErr != nil {
			log.Printf("ERROR: Failed to update mirror config status to 'failed': %v", updateErr)
		}
	} else {
		log.Printf("Sync completed successfully for mirror %s: synced=%d, failed=%d",
			config.Name, syncHistory.ProvidersSynced, syncHistory.ProvidersFailed)
		syncHistory.Status = "success"

		// Update mirror config with success (use cleanupCtx)
		if updateErr := j.mirrorRepo.UpdateSyncStatus(cleanupCtx, config.ID, "success", nil); updateErr != nil {
			log.Printf("ERROR: Failed to update mirror config status to 'success': %v", updateErr)
		}
	}

	// Store sync details as JSON
	if syncDetails != nil {
		detailsJSON, _ := json.Marshal(syncDetails)
		str := string(detailsJSON)
		syncHistory.SyncDetails = &str
	}

	// Update sync history (use cleanupCtx)
	log.Printf("Updating sync history for mirror %s (ID: %s) - Status: %s, Started: %v, Completed: %v",
		config.Name, syncHistory.ID, syncHistory.Status, syncHistory.StartedAt, syncHistory.CompletedAt)

	if err := j.mirrorRepo.UpdateSyncHistory(cleanupCtx, syncHistory); err != nil {
		log.Printf("ERROR: Failed to update sync history for mirror %s: %v", config.Name, err)
	} else {
		log.Printf("Successfully updated sync history for mirror %s", config.Name)
	}
}

// SyncDetails contains detailed information about a sync operation
type SyncDetails struct {
	Namespaces      []string         `json:"namespaces"`
	ProvidersFound  int              `json:"providers_found"`
	ProvidersSynced int              `json:"providers_synced"`
	ProvidersFailed int              `json:"providers_failed"`
	Errors          []string         `json:"errors,omitempty"`
	SyncedProviders []SyncedProvider `json:"synced_providers,omitempty"`
}

// SyncedProvider contains information about a synced provider
type SyncedProvider struct {
	Namespace   string   `json:"namespace"`
	Name        string   `json:"name"`
	Versions    []string `json:"versions"`
	VersionsNew int      `json:"versions_new"`
}

// performSync performs the actual provider synchronization.
// coverage:skip:integration-only — builds a live mirror.UpstreamRegistry and orchestrates HTTP calls + DB writes; exercised by api-test integration suite.
func (j *MirrorSyncJob) performSync(ctx context.Context, config models.MirrorConfiguration) (*SyncDetails, error) {
	details := &SyncDetails{
		Errors: []string{},
	}

	// Create upstream registry client via the injectable factory so tests can
	// substitute a fake without real HTTP.
	upstreamClient := j.newUpstream(config.UpstreamRegistryURL)

	// Test service discovery first
	_, err := upstreamClient.DiscoverServices(ctx)
	if err != nil {
		return details, fmt.Errorf("service discovery failed: %w", err)
	}

	// Parse namespace and provider filters
	var namespaces []string
	var providerNames []string

	if config.NamespaceFilter != nil && *config.NamespaceFilter != "" {
		if err := json.Unmarshal([]byte(*config.NamespaceFilter), &namespaces); err != nil {
			return details, fmt.Errorf("invalid namespace filter: %w", err)
		}
	}

	if config.ProviderFilter != nil && *config.ProviderFilter != "" {
		if err := json.Unmarshal([]byte(*config.ProviderFilter), &providerNames); err != nil {
			return details, fmt.Errorf("invalid provider filter: %w", err)
		}
	}

	// Handle different filter combinations
	if len(namespaces) == 0 && len(providerNames) == 0 {
		// No filters at all - can't enumerate full registry
		log.Printf("Mirror %s has no filters configured. Full registry mirroring not yet implemented.", config.Name)
		return details, fmt.Errorf("full registry mirroring not yet implemented - please configure namespace and/or provider filters")
	}

	// If only provider names are specified without namespace, default to "hashicorp"
	if len(namespaces) == 0 && len(providerNames) > 0 {
		log.Printf("No namespace filter specified, defaulting to 'hashicorp' namespace")
		namespaces = []string{"hashicorp"}
	}

	// If only namespace is specified without provider names, we can't enumerate
	if len(namespaces) > 0 && len(providerNames) == 0 {
		log.Printf("Mirror %s has namespace filter but no provider filter. Provider enumeration not yet implemented.", config.Name)
		return details, fmt.Errorf("provider enumeration not yet implemented - please also configure provider filters (e.g., 'aws', 'azurerm', 'google')")
	}

	// Sync all namespace/provider combinations
	for _, namespace := range namespaces {
		for _, providerName := range providerNames {
			syncedProvider, err := j.syncProvider(ctx, upstreamClient, config, namespace, providerName)
			if err != nil {
				details.ProvidersFailed++
				details.Errors = append(details.Errors, fmt.Sprintf("%s/%s: %v", namespace, providerName, err))
				log.Printf("Error syncing provider %s/%s: %v", namespace, providerName, err)
			} else {
				details.ProvidersSynced++
				details.SyncedProviders = append(details.SyncedProviders, *syncedProvider)
				log.Printf("Successfully synced provider %s/%s (%d versions)", namespace, providerName, len(syncedProvider.Versions))
			}
		}
	}

	details.Namespaces = namespaces
	details.ProvidersFound = len(namespaces) * len(providerNames)

	return details, nil
}

// syncProvider syncs a single provider from upstream.
// coverage:skip:integration-only — takes an UpstreamRegistryClient and drives real HTTP + DB flow; covered by integration tests.
func (j *MirrorSyncJob) syncProvider(ctx context.Context, upstreamClient mirror.UpstreamRegistryClient, config models.MirrorConfiguration, namespace, providerName string) (*SyncedProvider, error) {
	// List versions from upstream
	allVersions, err := upstreamClient.ListProviderVersions(ctx, namespace, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}

	if len(allVersions) == 0 {
		return nil, fmt.Errorf("no versions found")
	}

	// Apply version filter
	versions := mirror.FilterVersions(allVersions, config.VersionFilter)
	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions match filter %q (found %d total versions)", *config.VersionFilter, len(allVersions))
	}

	log.Printf("Filtered %d versions to %d versions using filter %q for %s/%s",
		len(allVersions), len(versions), safeString(config.VersionFilter), namespace, providerName)

	syncedProvider := &SyncedProvider{
		Namespace: namespace,
		Name:      providerName,
		Versions:  []string{},
	}

	// Determine organization ID for the provider
	var orgID string
	if config.OrganizationID != nil {
		orgID = config.OrganizationID.String()
	} else {
		// Config has no org assigned — fall back to the default organization so the
		// provider is visible in org-scoped searches (multi-tenant mode).
		defaultOrg, err := j.orgRepo.GetDefaultOrganization(ctx)
		if err == nil && defaultOrg != nil {
			orgID = defaultOrg.ID
		}
	}

	// Check if this provider already exists locally
	// Use GetProviderByNamespaceType which handles single-tenant mode (empty orgID)
	existingProvider, err := j.providerRepo.GetProviderByNamespaceType(ctx, orgID, namespace, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing provider: %w", err)
	}

	var localProvider *models.Provider
	var mirroredProvider *models.MirroredProvider

	if existingProvider == nil {
		// Create the provider in our local registry
		description := fmt.Sprintf("Mirrored from %s", config.UpstreamRegistryURL)
		source := fmt.Sprintf("%s/%s/%s", config.UpstreamRegistryURL, namespace, providerName)

		localProvider = &models.Provider{
			OrganizationID: orgID,
			Namespace:      namespace,
			Type:           providerName,
			Description:    &description,
			Source:         &source,
		}

		if err := j.providerRepo.CreateProvider(ctx, localProvider); err != nil {
			return nil, fmt.Errorf("failed to create local provider: %w", err)
		}

		log.Printf("Created local provider %s/%s (ID: %s)", namespace, providerName, localProvider.ID)

		// Create mirrored provider tracking record
		mirroredProvider = &models.MirroredProvider{
			ID:                uuid.New(),
			MirrorConfigID:    config.ID,
			ProviderID:        uuid.MustParse(localProvider.ID),
			UpstreamNamespace: namespace,
			UpstreamType:      providerName,
			LastSyncedAt:      time.Now(),
			SyncEnabled:       true,
			CreatedAt:         time.Now(),
		}

		if err := j.mirrorRepo.CreateMirroredProvider(ctx, mirroredProvider); err != nil {
			log.Printf("Warning: failed to create mirrored provider tracking: %v", err)
			// Continue anyway - the provider was created
		}
	} else {
		localProvider = existingProvider

		// Get existing mirrored provider record
		providerUUID, _ := uuid.Parse(localProvider.ID)
		mirroredProvider, err = j.mirrorRepo.GetMirroredProviderByProviderID(ctx, providerUUID)

		// If the provider exists but isn't tracked as mirrored yet, create the tracking record
		if err != nil || mirroredProvider == nil {
			log.Printf("Provider %s/%s exists but not tracked as mirrored. Creating tracking record.", namespace, providerName)

			mirroredProvider = &models.MirroredProvider{
				ID:                uuid.New(),
				MirrorConfigID:    config.ID,
				ProviderID:        uuid.MustParse(localProvider.ID),
				UpstreamNamespace: namespace,
				UpstreamType:      providerName,
				LastSyncedAt:      time.Now(),
				SyncEnabled:       true,
				CreatedAt:         time.Now(),
			}

			if err := j.mirrorRepo.CreateMirroredProvider(ctx, mirroredProvider); err != nil {
				log.Printf("Warning: failed to create mirrored provider tracking: %v", err)
				// Continue anyway - the provider exists
			} else {
				log.Printf("Created mirrored provider tracking for %s/%s", namespace, providerName)
			}
		}
	}

	// Get existing versions to avoid re-downloading
	existingVersions, err := j.providerRepo.ListVersions(ctx, localProvider.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to list existing versions: %w", err)
	}

	existingVersionMap := make(map[string]*models.ProviderVersion)
	for _, v := range existingVersions {
		existingVersionMap[v.Version] = v
	}

	// Sync each version
	for _, version := range versions {
		syncedProvider.Versions = append(syncedProvider.Versions, version.Version)

		// Check if version already exists
		if existingVersion, exists := existingVersionMap[version.Version]; exists {
			// Ensure the mirrored_provider_version tracking record exists
			if mirroredProvider != nil {
				versionUUID, _ := uuid.Parse(existingVersion.ID)
				existingTracking, err := j.mirrorRepo.GetMirroredProviderVersionByVersionID(ctx, versionUUID)
				if err != nil || existingTracking == nil {
					log.Printf("Creating tracking record for existing version %s (ID: %s)", version.Version, versionUUID)
					mpv := &models.MirroredProviderVersion{
						ID:                 uuid.New(),
						MirroredProviderID: mirroredProvider.ID,
						ProviderVersionID:  versionUUID,
						UpstreamVersion:    version.Version,
						SyncedAt:           time.Now(),
						ShasumVerified:     false,
						GPGVerified:        false,
					}
					if err := j.mirrorRepo.CreateMirroredProviderVersion(ctx, mpv); err != nil {
						log.Printf("Warning: failed to create tracking for existing version: %v", err)
					}
				}
			}

			// Check for missing platforms — the user may have deleted individual
			// platform records. Build a set of platforms already in the DB for this version.
			existingPlatforms, err := j.providerRepo.ListPlatforms(ctx, existingVersion.ID)
			if err != nil {
				log.Printf("Warning: failed to list platforms for existing version %s: %v", version.Version, err)
				continue
			}
			existingPlatformSet := make(map[string]bool, len(existingPlatforms))
			for _, ep := range existingPlatforms {
				existingPlatformSet[ep.OS+"/"+ep.Arch] = true
			}

			filteredPlatforms := filterPlatforms(version.Platforms, config.PlatformFilter)
			missingPlatforms := make([]mirror.ProviderPlatform, 0)
			for _, p := range filteredPlatforms {
				if !existingPlatformSet[p.OS+"/"+p.Arch] {
					missingPlatforms = append(missingPlatforms, p)
				}
			}

			if len(missingPlatforms) == 0 {
				// Backfill doc index if it was never populated for this already-complete
				// version. This recovers from prior syncs where doc fetch failed (e.g.,
				// upstream API change). Only one COUNT query is issued; the upstream fetch
				// is skipped entirely when docs already exist.
				if j.providerDocsRepo != nil {
					docCount, countErr := j.providerDocsRepo.CountProviderVersionDocs(ctx, existingVersion.ID)
					if countErr != nil {
						log.Printf("Warning: failed to count docs for %s/%s@%s: %v", namespace, providerName, version.Version, countErr)
					} else if docCount == 0 {
						docEntries, docErr := upstreamClient.GetProviderDocIndexByVersion(ctx, namespace, providerName, version.Version)
						if docErr != nil {
							log.Printf("Warning: failed to backfill doc index for %s/%s@%s: %v", namespace, providerName, version.Version, docErr)
						} else if len(docEntries) > 0 {
							docModels := make([]models.ProviderVersionDoc, len(docEntries))
							for i, d := range docEntries {
								docModels[i] = models.ProviderVersionDoc{
									UpstreamDocID: d.ID,
									Title:         d.Title,
									Slug:          d.Slug,
									Category:      d.Category,
									Subcategory:   d.Subcategory,
									Path:          &d.Path,
									Language:      d.Language,
								}
							}
							if storeErr := j.providerDocsRepo.BulkCreateProviderVersionDocs(ctx, existingVersion.ID, docModels); storeErr != nil {
								log.Printf("Warning: failed to store backfilled doc index for %s/%s@%s: %v", namespace, providerName, version.Version, storeErr)
							} else {
								log.Printf("Backfilled %d doc index entries for %s/%s@%s", len(docModels), namespace, providerName, version.Version)
							}
						}
					}
				}
				log.Printf("Version %s of %s/%s already exists with all platforms, skipping", version.Version, namespace, providerName)
				continue
			}

			log.Printf("Version %s of %s/%s exists but is missing %d platform(s), re-syncing those",
				version.Version, namespace, providerName, len(missingPlatforms))

			// Fetch SHASUM info once for this version then download missing platforms.
			firstPlatform := version.Platforms[0]
			packageInfo, pkgErr := upstreamClient.GetProviderPackage(ctx, namespace, providerName, version.Version, firstPlatform.OS, firstPlatform.Arch)
			var shasumMap map[string]string
			if pkgErr == nil {
				shasumContent, _ := upstreamClient.DownloadFile(ctx, packageInfo.SHASumsURL)
				shasumMap = parseSHASUMFile(string(shasumContent))
				// Persist the full SHA256SUMS so the version JSON can serve zh: hashes
				// for ALL platforms, including those not mirrored locally.
				if len(shasumMap) > 0 {
					if err := j.providerRepo.UpsertProviderVersionShasums(ctx, existingVersion.ID, shasumMap); err != nil {
						log.Printf("Warning: failed to store SHA256SUMS for re-sync of %s/%s@%s: %v", namespace, providerName, version.Version, err)
					}
				}
			} else {
				log.Printf("Warning: failed to get package info for SHASUM for %s/%s@%s: %v", namespace, providerName, version.Version, pkgErr)
			}

			existingVersionRecord := &models.ProviderVersion{
				ID: existingVersion.ID,
			}
			for _, mp := range missingPlatforms {
				if err := j.syncPlatformBinary(ctx, upstreamClient, existingVersionRecord, namespace, providerName, version.Version, mp, shasumMap); err != nil {
					log.Printf("Error re-syncing missing platform %s/%s for %s/%s@%s: %v",
						mp.OS, mp.Arch, namespace, providerName, version.Version, err)
				} else {
					syncedProvider.VersionsNew++
					log.Printf("Re-synced missing platform %s/%s for %s/%s@%s",
						mp.OS, mp.Arch, namespace, providerName, version.Version)
				}
			}
			continue
		}

		// Sync this version (download and create)
		err := j.syncProviderVersion(ctx, upstreamClient, localProvider, mirroredProvider, namespace, providerName, version, config.PlatformFilter)
		if err != nil {
			log.Printf("Error syncing version %s of %s/%s: %v", version.Version, namespace, providerName, err)
			// Continue with other versions
			continue
		}

		syncedProvider.VersionsNew++
		log.Printf("Successfully synced version %s of %s/%s", version.Version, namespace, providerName)
	}

	// Update mirrored provider sync time
	if mirroredProvider != nil {
		mirroredProvider.LastSyncedAt = time.Now()
		if len(versions) > 0 {
			highest := versions[0].Version
			for _, v := range versions[1:] {
				if mirror.CompareSemver(v.Version, highest) > 0 {
					highest = v.Version
				}
			}
			mirroredProvider.LastSyncVersion = &highest
		}
		if err := j.mirrorRepo.UpdateMirroredProvider(ctx, mirroredProvider); err != nil {
			log.Printf("Warning: failed to update mirrored provider sync time for %s/%s: %v", namespace, providerName, err)
		}
	}

	log.Printf("Synced %s/%s: %d total versions, %d new",
		namespace, providerName, len(versions), syncedProvider.VersionsNew)

	return syncedProvider, nil
}

// syncProviderVersion downloads and stores a single version of a provider.
// coverage:skip:integration-only — performs live HTTP downloads, SHA256 verification, and storage uploads for a provider binary; exercised by the api-test integration suite.
func (j *MirrorSyncJob) syncProviderVersion(
	ctx context.Context,
	upstreamClient mirror.UpstreamRegistryClient,
	localProvider *models.Provider,
	mirroredProvider *models.MirroredProvider,
	namespace, providerName string,
	version mirror.ProviderVersion,
	platformFilter *string,
) error {
	// Filter platforms if a filter is specified
	platforms := filterPlatforms(version.Platforms, platformFilter)

	log.Printf("Syncing version %s of %s/%s with %d platforms (filtered from %d)",
		version.Version, namespace, providerName, len(platforms), len(version.Platforms))

	if len(version.Platforms) == 0 {
		return fmt.Errorf("no platforms available for version %s", version.Version)
	}

	// Get package info for the first platform to get signing keys and SHASUM URLs
	firstPlatform := version.Platforms[0]
	packageInfo, err := upstreamClient.GetProviderPackage(ctx, namespace, providerName, version.Version, firstPlatform.OS, firstPlatform.Arch)
	if err != nil {
		return fmt.Errorf("failed to get package info: %w", err)
	}

	// Extract GPG public key
	gpgPublicKey := ""
	if len(packageInfo.SigningKeys.GPGPublicKeys) > 0 {
		gpgPublicKey = packageInfo.SigningKeys.GPGPublicKeys[0].ASCIIArmor
	}

	// Download the SHASUM file to verify binaries
	shasumContent, err := upstreamClient.DownloadFile(ctx, packageInfo.SHASumsURL)
	if err != nil {
		log.Printf("Warning: failed to download SHASUM file: %v", err)
		// Continue without SHASUM verification
	}

	// Download and verify the GPG signature
	gpgVerified := false
	if len(shasumContent) > 0 && gpgPublicKey != "" {
		sigContent, err := upstreamClient.DownloadFile(ctx, packageInfo.SHASumsSignatureURL)
		if err != nil {
			log.Printf("Warning: failed to download SHASUM signature: %v", err)
		} else {
			// Collect all GPG keys from the package
			var publicKeys []string
			for _, gpgKey := range packageInfo.SigningKeys.GPGPublicKeys {
				if gpgKey.ASCIIArmor != "" {
					publicKeys = append(publicKeys, gpgKey.ASCIIArmor)
				}
			}

			if len(publicKeys) > 0 {
				result := verifyGPGSignature(shasumContent, sigContent, publicKeys)
				if result.Verified {
					gpgVerified = true
					log.Printf("GPG signature verified for %s/%s@%s (Key ID: %s)",
						namespace, providerName, version.Version, result.KeyID)
				} else if result.Error != nil {
					log.Printf("Warning: GPG verification failed for %s/%s@%s: %v",
						namespace, providerName, version.Version, result.Error)
				}
			}
		}
	}

	// Parse SHASUM file into a map
	shasumMap := parseSHASUMFile(string(shasumContent))

	// Create the version record
	versionRecord := &models.ProviderVersion{
		ProviderID:         localProvider.ID,
		Version:            version.Version,
		Protocols:          version.Protocols,
		GPGPublicKey:       gpgPublicKey,
		ShasumURL:          packageInfo.SHASumsURL,
		ShasumSignatureURL: packageInfo.SHASumsSignatureURL,
	}

	if err := j.providerRepo.CreateVersion(ctx, versionRecord); err != nil {
		return fmt.Errorf("failed to create version record: %w", err)
	}

	// Persist the full SHA256SUMS map so the Network Mirror Protocol endpoint can
	// serve zh: hashes for ALL platforms in the upstream release (not just the
	// subset we sync locally).  A warning is logged on failure but is non-fatal.
	if len(shasumMap) > 0 {
		if err := j.providerRepo.UpsertProviderVersionShasums(ctx, versionRecord.ID, shasumMap); err != nil {
			log.Printf("Warning: failed to store SHA256SUMS for %s/%s@%s: %v", namespace, providerName, version.Version, err)
		}
	}

	// Fetch and store documentation index entries from upstream.
	// This is non-critical — a failure is logged but does not block the sync.
	if j.providerDocsRepo != nil {
		docEntries, err := upstreamClient.GetProviderDocIndexByVersion(ctx, namespace, providerName, version.Version)
		if err != nil {
			log.Printf("Warning: failed to fetch doc index for %s/%s@%s: %v", namespace, providerName, version.Version, err)
		} else if len(docEntries) > 0 {
			docModels := make([]models.ProviderVersionDoc, len(docEntries))
			for i, d := range docEntries {
				docModels[i] = models.ProviderVersionDoc{
					UpstreamDocID: d.ID,
					Title:         d.Title,
					Slug:          d.Slug,
					Category:      d.Category,
					Subcategory:   d.Subcategory,
					Path:          &d.Path,
					Language:      d.Language,
				}
			}
			if err := j.providerDocsRepo.BulkCreateProviderVersionDocs(ctx, versionRecord.ID, docModels); err != nil {
				log.Printf("Warning: failed to store doc index for %s/%s@%s: %v", namespace, providerName, version.Version, err)
			} else {
				log.Printf("Stored %d doc index entries for %s/%s@%s", len(docModels), namespace, providerName, version.Version)
			}
		}
	}

	// Download and store each platform binary (using filtered platforms)
	platformsDownloaded := 0
	for _, platform := range platforms {
		err := j.syncPlatformBinary(ctx, upstreamClient, versionRecord, namespace, providerName, version.Version, platform, shasumMap)
		if err != nil {
			log.Printf("Error syncing platform %s/%s for %s/%s@%s: %v",
				platform.OS, platform.Arch, namespace, providerName, version.Version, err)
			// Continue with other platforms
			continue
		}
		platformsDownloaded++
	}

	if platformsDownloaded == 0 && len(platforms) > 0 {
		// Clean up the version record if no platforms were downloaded
		if cleanupErr := j.providerRepo.DeleteVersion(ctx, versionRecord.ID); cleanupErr != nil {
			log.Printf("Warning: failed to clean up version record %s: %v", versionRecord.ID, cleanupErr)
		}
		return fmt.Errorf("failed to download any platforms for version %s", version.Version)
	}

	if len(platforms) == 0 {
		// No platforms match filter - skip this version
		if cleanupErr := j.providerRepo.DeleteVersion(ctx, versionRecord.ID); cleanupErr != nil {
			log.Printf("Warning: failed to clean up version record %s: %v", versionRecord.ID, cleanupErr)
		}
		return fmt.Errorf("no platforms match filter for version %s", version.Version)
	}

	// Track the mirrored version
	if mirroredProvider != nil {
		mpv := &models.MirroredProviderVersion{
			ID:                 uuid.New(),
			MirroredProviderID: mirroredProvider.ID,
			ProviderVersionID:  uuid.MustParse(versionRecord.ID),
			UpstreamVersion:    version.Version,
			SyncedAt:           time.Now(),
			ShasumVerified:     len(shasumContent) > 0,
			GPGVerified:        gpgVerified,
		}
		if err := j.mirrorRepo.CreateMirroredProviderVersion(ctx, mpv); err != nil {
			log.Printf("Warning: failed to record mirrored provider version for %s/%s@%s: %v", namespace, providerName, version.Version, err)
		}
	}

	log.Printf("Synced version %s: %d/%d platforms downloaded", version.Version, platformsDownloaded, len(platforms))
	return nil
}

// syncPlatformBinary downloads and stores a single platform binary.
// coverage:skip:integration-only — streams a real provider archive from upstream, verifies its checksum, and writes to the storage backend; exercised by integration tests.
func (j *MirrorSyncJob) syncPlatformBinary(
	ctx context.Context,
	upstreamClient mirror.UpstreamRegistryClient,
	versionRecord *models.ProviderVersion,
	namespace, providerName, version string,
	platform mirror.ProviderPlatform,
	shasumMap map[string]string,
) error {
	// Get download info for this platform
	packageInfo, err := upstreamClient.GetProviderPackage(ctx, namespace, providerName, version, platform.OS, platform.Arch)
	if err != nil {
		return fmt.Errorf("failed to get package info: %w", err)
	}

	log.Printf("Downloading %s from %s", packageInfo.Filename, packageInfo.DownloadURL)

	// Stream binary to a temp file to avoid buffering large zips in memory.
	stream, err := upstreamClient.DownloadFileStream(ctx, packageInfo.DownloadURL)
	if err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "provider-binary-*.zip")
	if err != nil {
		stream.Body.Close()
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	// Stream to disk, computing SHA256 in-flight.
	hasher := sha256.New()
	written, err := io.Copy(tmpFile, io.TeeReader(stream.Body, hasher))
	stream.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to stream binary to disk: %w", err)
	}
	checksumHex := hex.EncodeToString(hasher.Sum(nil))

	// Verify checksum if we have SHASUM data
	expectedChecksum := packageInfo.SHA256Sum
	if expectedChecksum == "" {
		// Try to get from SHASUM file
		if cs, ok := shasumMap[packageInfo.Filename]; ok {
			expectedChecksum = cs
		}
	}

	if expectedChecksum != "" && checksumHex != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, checksumHex)
	}

	log.Printf("Checksum verified for %s: %s", packageInfo.Filename, checksumHex)

	// Store the binary
	storagePath := fmt.Sprintf("providers/%s/%s/%s/%s/%s/%s",
		namespace, providerName, version, platform.OS, platform.Arch, packageInfo.Filename)

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek temp file: %w", err)
	}

	uploadResult, err := j.storageBackend.Upload(ctx, storagePath, tmpFile, written)
	if err != nil {
		return fmt.Errorf("failed to store binary: %w", err)
	}

	// Create platform record
	platformRecord := &models.ProviderPlatform{
		ProviderVersionID: versionRecord.ID,
		OS:                platform.OS,
		Arch:              platform.Arch,
		Filename:          packageInfo.Filename,
		StoragePath:       uploadResult.Path,
		StorageBackend:    j.storageBackendName,
		SizeBytes:         written,
		Shasum:            checksumHex,
	}

	// Compute the h1: dirhash for the zip archive so Terraform's network mirror
	// protocol can serve both zh: (legacy) and h1: (preferred) hashes.
	// HashZipFile uses io.ReaderAt so the temp file can serve as the source.
	if h1, err := checksum.HashZipFile(tmpFile, written); err != nil {
		log.Printf("Warning: failed to compute h1: hash for %s: %v", packageInfo.Filename, err)
	} else {
		platformRecord.H1Hash = &h1
	}

	if err := j.providerRepo.CreatePlatform(ctx, platformRecord); err != nil {
		return fmt.Errorf("failed to create platform record: %w", err)
	}

	log.Printf("Stored platform %s/%s: %s (%d bytes)", platform.OS, platform.Arch, storagePath, written)
	return nil
}

// parseSHASUMFile parses a SHA256SUMS file into a map of filename -> checksum
func parseSHASUMFile(content string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: checksum  filename (two spaces between)
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) == 2 {
			result[parts[1]] = parts[0]
		}
	}
	return result
}

// gpgVerificationResult contains the result of GPG verification
type gpgVerificationResult struct {
	Verified bool
	KeyID    string
	Error    error
}

// verifyGPGSignature verifies a GPG signature using the validation package
func verifyGPGSignature(shasumContent, signatureContent []byte, publicKeys []string) *gpgVerificationResult {
	result := validation.VerifyProviderSignature(shasumContent, signatureContent, publicKeys)
	return &gpgVerificationResult{
		Verified: result.Verified,
		KeyID:    result.KeyID,
		Error:    result.Error,
	}
}

// TriggerManualSync triggers a manual sync for a specific mirror.
// coverage:skip:integration-only — orchestrates the full sync pipeline via syncMirror/performSync which themselves require a live upstream registry.
func (j *MirrorSyncJob) TriggerManualSync(ctx context.Context, mirrorID uuid.UUID) error {
	// Check if already syncing and mark as active atomically
	j.activeSyncsMutex.Lock()
	if j.activeSyncs[mirrorID] {
		j.activeSyncsMutex.Unlock()
		return fmt.Errorf("sync already in progress for this mirror")
	}
	// Mark as active immediately to prevent race conditions
	j.activeSyncs[mirrorID] = true
	j.activeSyncsMutex.Unlock()

	// Get mirror config using the request context
	config, err := j.mirrorRepo.GetByID(ctx, mirrorID)
	if err != nil {
		// If we fail to get config, clean up the active sync flag
		j.activeSyncsMutex.Lock()
		delete(j.activeSyncs, mirrorID)
		j.activeSyncsMutex.Unlock()
		return fmt.Errorf("failed to get mirror configuration: %w", err)
	}
	if config == nil {
		// If config not found, clean up the active sync flag
		j.activeSyncsMutex.Lock()
		delete(j.activeSyncs, mirrorID)
		j.activeSyncsMutex.Unlock()
		return fmt.Errorf("mirror configuration not found")
	}

	// Use a background context for the sync operation since the HTTP request
	// context will be cancelled when the response is sent
	go j.syncMirror(context.Background(), *config) // #nosec G118 -- request context cancels when response is sent; background context is required for async sync

	return nil
}
