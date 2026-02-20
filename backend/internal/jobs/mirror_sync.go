// Package jobs contains background workers that run on a schedule.
// The mirror sync job periodically fetches new provider versions from upstream registries; the tag verifier confirms that SCM-linked module tags have been correctly published.
// Jobs are designed to be idempotent — re-running after a crash produces the same result as a clean run.
package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"

	"github.com/google/uuid"
)

// filterVersions filters a list of provider versions based on the version filter string
// Supported filter formats:
//   - "3." or "3.x" - all versions starting with "3."
//   - "latest:5" - the latest 5 versions (sorted by semver)
//   - "3.74.0,3.73.0" - specific comma-separated versions
//   - ">=3.0.0" - versions >= 3.0.0 (semver comparison)
//   - "" or nil - all versions
func filterVersions(versions []mirror.ProviderVersion, filter *string) []mirror.ProviderVersion {
	if filter == nil || *filter == "" {
		return versions
	}

	filterStr := strings.TrimSpace(*filter)

	// Handle "latest:N" format
	if strings.HasPrefix(filterStr, "latest:") {
		countStr := strings.TrimPrefix(filterStr, "latest:")
		count, err := strconv.Atoi(countStr)
		if err != nil || count <= 0 {
			log.Printf("Invalid latest:N filter format: %s, using all versions", filterStr)
			return versions
		}
		return filterLatestVersions(versions, count)
	}

	// Handle prefix matching (e.g., "3." or "3.x" or "3.7")
	if strings.HasSuffix(filterStr, ".") || strings.HasSuffix(filterStr, ".x") {
		prefix := strings.TrimSuffix(filterStr, "x")
		return filterVersionsByPrefix(versions, prefix)
	}

	// Handle semver constraints (>=, >, <=, <)
	if strings.HasPrefix(filterStr, ">=") || strings.HasPrefix(filterStr, ">") ||
		strings.HasPrefix(filterStr, "<=") || strings.HasPrefix(filterStr, "<") {
		return filterVersionsBySemverConstraint(versions, filterStr)
	}

	// Handle comma-separated specific versions
	if strings.Contains(filterStr, ",") {
		return filterVersionsByList(versions, filterStr)
	}

	// Single version or prefix without trailing dot
	// Try as prefix first
	filtered := filterVersionsByPrefix(versions, filterStr+".")
	if len(filtered) > 0 {
		return filtered
	}

	// Try as exact version
	return filterVersionsByList(versions, filterStr)
}

// filterLatestVersions returns the N most recent versions sorted by semver
func filterLatestVersions(versions []mirror.ProviderVersion, count int) []mirror.ProviderVersion {
	if len(versions) <= count {
		return versions
	}

	// Sort by semver descending
	sorted := make([]mirror.ProviderVersion, len(versions))
	copy(sorted, versions)
	sort.Slice(sorted, func(i, j int) bool {
		return compareSemver(sorted[i].Version, sorted[j].Version) > 0
	})

	return sorted[:count]
}

// filterVersionsByPrefix returns versions that start with the given prefix
func filterVersionsByPrefix(versions []mirror.ProviderVersion, prefix string) []mirror.ProviderVersion {
	var filtered []mirror.ProviderVersion
	for _, v := range versions {
		if strings.HasPrefix(v.Version, prefix) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// filterVersionsByList returns versions that match any in the comma-separated list
func filterVersionsByList(versions []mirror.ProviderVersion, list string) []mirror.ProviderVersion {
	wantedVersions := make(map[string]bool)
	for _, v := range strings.Split(list, ",") {
		wantedVersions[strings.TrimSpace(v)] = true
	}

	var filtered []mirror.ProviderVersion
	for _, v := range versions {
		if wantedVersions[v.Version] {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// filterVersionsBySemverConstraint returns versions matching the semver constraint
func filterVersionsBySemverConstraint(versions []mirror.ProviderVersion, constraint string) []mirror.ProviderVersion {
	var op string
	var targetVersion string

	if strings.HasPrefix(constraint, ">=") {
		op = ">="
		targetVersion = strings.TrimPrefix(constraint, ">=")
	} else if strings.HasPrefix(constraint, "<=") {
		op = "<="
		targetVersion = strings.TrimPrefix(constraint, "<=")
	} else if strings.HasPrefix(constraint, ">") {
		op = ">"
		targetVersion = strings.TrimPrefix(constraint, ">")
	} else if strings.HasPrefix(constraint, "<") {
		op = "<"
		targetVersion = strings.TrimPrefix(constraint, "<")
	} else {
		return versions
	}

	targetVersion = strings.TrimSpace(targetVersion)

	var filtered []mirror.ProviderVersion
	for _, v := range versions {
		cmp := compareSemver(v.Version, targetVersion)
		switch op {
		case ">=":
			if cmp >= 0 {
				filtered = append(filtered, v)
			}
		case ">":
			if cmp > 0 {
				filtered = append(filtered, v)
			}
		case "<=":
			if cmp <= 0 {
				filtered = append(filtered, v)
			}
		case "<":
			if cmp < 0 {
				filtered = append(filtered, v)
			}
		}
	}
	return filtered
}

// compareSemver compares two semver strings
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func compareSemver(a, b string) int {
	aParts := parseSemverParts(a)
	bParts := parseSemverParts(b)

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

// parseSemverParts extracts major, minor, patch from a version string
func parseSemverParts(version string) [3]int {
	// Remove any pre-release suffix (e.g., -alpha, -beta)
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}

	parts := strings.Split(version, ".")
	var result [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		val, _ := strconv.Atoi(parts[i])
		result[i] = val
	}
	return result
}

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
	storageBackend     storage.Storage
	storageBackendName string
	activeSyncs        map[uuid.UUID]bool
	activeSyncsMutex   sync.Mutex
	stopCh             chan struct{}
	wg                 sync.WaitGroup
}

// NewMirrorSyncJob creates a new mirror sync job
func NewMirrorSyncJob(
	mirrorRepo *repositories.MirrorRepository,
	providerRepo *repositories.ProviderRepository,
	storageBackend storage.Storage,
	storageBackendName string,
) *MirrorSyncJob {
	return &MirrorSyncJob{
		mirrorRepo:         mirrorRepo,
		providerRepo:       providerRepo,
		storageBackend:     storageBackend,
		storageBackendName: storageBackendName,
		activeSyncs:        make(map[uuid.UUID]bool),
		activeSyncsMutex:   sync.Mutex{},
		stopCh:             make(chan struct{}),
	}
}

// Start begins the periodic sync job
func (j *MirrorSyncJob) Start(ctx context.Context, intervalMinutes int) {
	log.Printf("Starting mirror sync job with interval of %d minutes", intervalMinutes)

	j.wg.Add(1)
	go func() {
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

// Stop stops the sync job
func (j *MirrorSyncJob) Stop() {
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

		// Run sync in a goroutine
		go j.syncMirror(ctx, mirror)
	}
}

// syncMirror performs the actual synchronization of a mirror
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

// performSync performs the actual provider synchronization
func (j *MirrorSyncJob) performSync(ctx context.Context, config models.MirrorConfiguration) (*SyncDetails, error) {
	details := &SyncDetails{
		Errors: []string{},
	}

	// Create upstream registry client
	upstreamClient := mirror.NewUpstreamRegistry(config.UpstreamRegistryURL)

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

// syncProvider syncs a single provider from upstream
func (j *MirrorSyncJob) syncProvider(ctx context.Context, upstreamClient *mirror.UpstreamRegistry, config models.MirrorConfiguration, namespace, providerName string) (*SyncedProvider, error) {
	// List versions from upstream
	allVersions, err := upstreamClient.ListProviderVersions(ctx, namespace, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}

	if len(allVersions) == 0 {
		return nil, fmt.Errorf("no versions found")
	}

	// Apply version filter
	versions := filterVersions(allVersions, config.VersionFilter)
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
	// In multi-tenant mode, use the org from config; in single-tenant mode, we'll need a default org
	var orgID string
	if config.OrganizationID != nil {
		orgID = config.OrganizationID.String()
	} else {
		// For single-tenant mode, we need to get or create a default organization
		// For now, we'll use an empty string which SearchProviders handles as single-tenant mode
		orgID = ""
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
			log.Printf("Version %s of %s/%s already exists, skipping download", version.Version, namespace, providerName)

			// But ensure the mirrored_provider_version tracking record exists
			if mirroredProvider != nil {
				versionUUID, _ := uuid.Parse(existingVersion.ID)
				existingTracking, err := j.mirrorRepo.GetMirroredProviderVersionByVersionID(ctx, versionUUID)

				if err != nil || existingTracking == nil {
					// Create tracking record for this existing version
					log.Printf("Creating tracking record for existing version %s (ID: %s)", version.Version, versionUUID)
					mpv := &models.MirroredProviderVersion{
						ID:                 uuid.New(),
						MirroredProviderID: mirroredProvider.ID,
						ProviderVersionID:  versionUUID,
						UpstreamVersion:    version.Version,
						SyncedAt:           time.Now(),
						ShasumVerified:     false, // Unknown for existing versions
						GPGVerified:        false, // Unknown for existing versions
					}
					if err := j.mirrorRepo.CreateMirroredProviderVersion(ctx, mpv); err != nil {
						log.Printf("Warning: failed to create tracking for existing version: %v", err)
					} else {
						log.Printf("Successfully created tracking for version %s", version.Version)
					}
				} else {
					log.Printf("Version %s already has tracking record (ID: %s)", version.Version, existingTracking.ID)
				}
			} else {
				log.Printf("WARNING: mirroredProvider is nil, cannot create version tracking for %s", version.Version)
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
			mirroredProvider.LastSyncVersion = &versions[0].Version
		}
		if err := j.mirrorRepo.UpdateMirroredProvider(ctx, mirroredProvider); err != nil {
			log.Printf("Warning: failed to update mirrored provider sync time for %s/%s: %v", namespace, providerName, err)
		}
	}

	log.Printf("Synced %s/%s: %d total versions, %d new",
		namespace, providerName, len(versions), syncedProvider.VersionsNew)

	return syncedProvider, nil
}

// syncProviderVersion downloads and stores a single version of a provider
func (j *MirrorSyncJob) syncProviderVersion(
	ctx context.Context,
	upstreamClient *mirror.UpstreamRegistry,
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

// syncPlatformBinary downloads and stores a single platform binary
func (j *MirrorSyncJob) syncPlatformBinary(
	ctx context.Context,
	upstreamClient *mirror.UpstreamRegistry,
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

	// Download the binary
	binaryContent, err := upstreamClient.DownloadFile(ctx, packageInfo.DownloadURL)
	if err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}

	// Calculate SHA256 checksum
	checksum := sha256.Sum256(binaryContent)
	checksumHex := hex.EncodeToString(checksum[:])

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

	uploadResult, err := j.storageBackend.Upload(ctx, storagePath, bytes.NewReader(binaryContent), int64(len(binaryContent)))
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
		SizeBytes:         int64(len(binaryContent)),
		Shasum:            checksumHex,
	}

	if err := j.providerRepo.CreatePlatform(ctx, platformRecord); err != nil {
		return fmt.Errorf("failed to create platform record: %w", err)
	}

	log.Printf("Stored platform %s/%s: %s (%d bytes)", platform.OS, platform.Arch, storagePath, len(binaryContent))
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

// TriggerManualSync triggers a manual sync for a specific mirror
func (j *MirrorSyncJob) TriggerManualSync(ctx context.Context, mirrorID uuid.UUID) error {
	// Check if already syncing and mark as active atomically
	j.activeSyncsMutex.Lock()
	if j.activeSyncs[mirrorID] {
		j.activeSyncsMutex.Unlock()
		return fmt.Errorf("sync already in progress for this mirror")
	}
	// Mark as active immediately to prevent race conditions
	j.activeSyncs[mirrorID] = true

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
	go j.syncMirror(context.Background(), *config)

	return nil
}
