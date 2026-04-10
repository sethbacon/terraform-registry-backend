// pull_through.go implements on-demand upstream metadata fetching for the Provider Network
// Mirror Protocol.  On a cache miss (provider not yet synced), PullThroughService contacts
// the upstream registry, fetches version metadata and SHA256SUMS, and populates the local
// database.  Binary downloads are intentionally deferred to the existing scheduled sync job;
// the existing zh:-hash enrichment in PlatformIndexHandler serves upstream binary URLs until
// the sync job downloads them locally.
package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// PullThroughService fetches provider metadata from an upstream registry on demand,
// populating provider_versions and provider_version_shasums so that mirror endpoints
// can serve valid responses on cache miss.
type PullThroughService struct {
	providerRepo *repositories.ProviderRepository
	mirrorRepo   *repositories.MirrorRepository
	orgRepo      *repositories.OrganizationRepository
}

// NewPullThroughService constructs a PullThroughService.
func NewPullThroughService(
	providerRepo *repositories.ProviderRepository,
	mirrorRepo *repositories.MirrorRepository,
	orgRepo *repositories.OrganizationRepository,
) *PullThroughService {
	return &PullThroughService{
		providerRepo: providerRepo,
		mirrorRepo:   mirrorRepo,
		orgRepo:      orgRepo,
	}
}

// FetchProviderMetadata fetches the version list and SHA256SUMS from upstream for the
// given provider, populates the local DB, and returns the list of version strings now
// available.  It does NOT download provider binaries — those are served via the existing
// zh:-hash enrichment path and downloaded by the scheduled sync job.
func (s *PullThroughService) FetchProviderMetadata(
	ctx context.Context,
	mirrorCfg *models.MirrorConfiguration,
	orgID, namespace, providerType string,
) ([]string, error) {
	client := mirror.NewUpstreamRegistry(mirrorCfg.UpstreamRegistryURL)

	allVersions, err := client.ListProviderVersions(ctx, namespace, providerType)
	if err != nil {
		return nil, fmt.Errorf("upstream version list: %w", err)
	}
	if len(allVersions) == 0 {
		return nil, nil
	}

	filtered := mirror.FilterVersions(allVersions, mirrorCfg.VersionFilter)
	if len(filtered) == 0 {
		return nil, nil
	}

	provider, err := s.providerRepo.UpsertProvider(ctx, orgID, namespace, providerType)
	if err != nil {
		return nil, fmt.Errorf("upsert provider: %w", err)
	}

	var available []string
	for _, v := range filtered {
		if len(v.Platforms) == 0 {
			slog.Warn("pull-through: skipping version with no platforms",
				"namespace", namespace, "type", providerType, "version", v.Version)
			continue
		}

		// Fetch package info from the first platform to get ShasumURL and GPG key.
		firstPlatform := v.Platforms[0]
		pkgInfo, err := client.GetProviderPackage(ctx, namespace, providerType, v.Version, firstPlatform.OS, firstPlatform.Arch)
		if err != nil {
			slog.Warn("pull-through: failed to get package info, skipping version",
				"version", v.Version, "error", err)
			continue
		}

		gpgKey := ""
		if len(pkgInfo.SigningKeys.GPGPublicKeys) > 0 {
			gpgKey = pkgInfo.SigningKeys.GPGPublicKeys[0].ASCIIArmor
		}

		pv, err := s.providerRepo.UpsertVersion(
			ctx, provider.ID, v.Version,
			v.Protocols, pkgInfo.SHASumsURL, pkgInfo.SHASumsSignatureURL, gpgKey,
		)
		if err != nil {
			slog.Warn("pull-through: failed to upsert version",
				"version", v.Version, "error", err)
			continue
		}

		// Fetch and store SHA256SUMS so the PlatformIndexHandler can serve zh: hashes
		// for all upstream platforms, including those not yet downloaded locally.
		if pkgInfo.SHASumsURL != "" {
			if err := s.fetchAndStoreShasums(ctx, client, pv.ID, pkgInfo.SHASumsURL); err != nil {
				slog.Warn("pull-through: failed to store shasums",
					"version", v.Version, "error", err)
			}
		}

		available = append(available, v.Version)
	}

	slog.Info("pull-through: metadata populated",
		"namespace", namespace, "type", providerType,
		"versions_fetched", len(available))
	return available, nil
}

// fetchAndStoreShasums downloads the upstream SHA256SUMS file and stores every
// filename→sha256 entry via UpsertProviderVersionShasums.
func (s *PullThroughService) fetchAndStoreShasums(
	ctx context.Context,
	client *mirror.UpstreamRegistry,
	providerVersionID, shasumURL string,
) error {
	data, err := client.DownloadFile(ctx, shasumURL)
	if err != nil {
		return fmt.Errorf("download SHA256SUMS: %w", err)
	}
	shasums := parseSHASUMContent(string(data))
	if len(shasums) == 0 {
		return nil
	}
	return s.providerRepo.UpsertProviderVersionShasums(ctx, providerVersionID, shasums)
}

// parseSHASUMContent parses a SHA256SUMS file into a filename→sha256hex map.
func parseSHASUMContent(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) == 2 {
			result[parts[1]] = parts[0]
		}
	}
	return result
}

// GetConfigsForProvider returns pull-through-enabled mirror configs for the given org/namespace/type.
// Delegates to the mirror repository which does the filtering.
func (s *PullThroughService) GetConfigsForProvider(
	ctx context.Context,
	orgID, namespace, providerType string,
) ([]*models.MirrorConfiguration, error) {
	return s.mirrorRepo.GetPullThroughConfigsForProvider(ctx, orgID, namespace, providerType)
}
