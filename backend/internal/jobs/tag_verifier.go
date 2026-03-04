// tag_verifier.go implements the TagVerifier background job, which periodically confirms
// that SCM-linked module git tags have not been moved since the module version was published.
package jobs

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// TagVerifier periodically verifies that git tags haven't been moved
type TagVerifier struct {
	scmRepo     *repositories.SCMRepository
	moduleRepo  *repositories.ModuleRepository
	tokenCipher *crypto.TokenCipher
	interval    time.Duration
	stopChan    chan struct{}
}

// NewTagVerifier creates a new tag verification job
func NewTagVerifier(scmRepo *repositories.SCMRepository, moduleRepo *repositories.ModuleRepository, tokenCipher *crypto.TokenCipher, intervalHours int) *TagVerifier {
	if intervalHours <= 0 {
		intervalHours = 24 // Default to daily
	}

	return &TagVerifier{
		scmRepo:     scmRepo,
		moduleRepo:  moduleRepo,
		tokenCipher: tokenCipher,
		interval:    time.Duration(intervalHours) * time.Hour,
		stopChan:    make(chan struct{}),
	}
}

// Start begins the tag verification job
func (v *TagVerifier) Start(ctx context.Context) {
	ticker := time.NewTicker(v.interval)
	defer ticker.Stop()

	log.Printf("Tag verifier started with interval: %v", v.interval)

	// Run immediately on start
	v.runVerification(ctx)

	for {
		select {
		case <-ticker.C:
			v.runVerification(ctx)
		case <-v.stopChan:
			log.Println("Tag verifier stopped")
			return
		case <-ctx.Done():
			log.Println("Tag verifier context cancelled")
			return
		}
	}
}

// Stop stops the tag verification job
func (v *TagVerifier) Stop() {
	close(v.stopChan)
}

// runVerification performs a verification run
func (v *TagVerifier) runVerification(ctx context.Context) {
	if v.moduleRepo == nil || v.scmRepo == nil {
		log.Println("Tag verification: repos not configured, skipping")
		return
	}

	log.Println("Starting tag verification run")

	versions, err := v.moduleRepo.GetAllWithSourceCommit(ctx)
	if err != nil {
		log.Printf("Tag verification: failed to fetch SCM-sourced versions: %v", err)
		return
	}

	if len(versions) == 0 {
		log.Println("Tag verification run completed: no SCM-sourced versions to check")
		return
	}

	checked := 0
	violations := 0

	for _, ver := range versions {
		// Need both a tag name and a commit SHA to verify
		if ver.TagName == nil || ver.CommitSHA == nil || ver.SCMRepoID == nil {
			continue
		}

		moduleUUID, parseErr := uuid.Parse(ver.ModuleID)
		if parseErr != nil {
			log.Printf("Tag verification: invalid module ID %q in version %s: %v", ver.ModuleID, ver.ID, parseErr)
			continue
		}

		// Look up the current SCM link for this module
		link, linkErr := v.scmRepo.GetModuleSourceRepo(ctx, moduleUUID)
		if linkErr != nil || link == nil {
			continue // Module may have been unlinked; skip silently
		}

		// Get the provider
		provider, provErr := v.scmRepo.GetProvider(ctx, link.SCMProviderID)
		if provErr != nil || provider == nil {
			continue
		}

		// Build connector (unauthenticated — enough for public repos; authenticated preferred)
		// NOTE: For private repos, fetching may fail without credentials; those are silently skipped.
		var oauthToken *scm.OAuthToken

		baseURL := ""
		if provider.BaseURL != nil {
			baseURL = *provider.BaseURL
		}
		tenantID := ""
		if provider.TenantID != nil {
			tenantID = *provider.TenantID
		}
		clientSecret, csErr := v.tokenCipher.Open(provider.ClientSecretEncrypted)
		if csErr != nil {
			continue
		}
		connector, connErr := scm.BuildConnector(&scm.ConnectorSettings{
			Kind:            provider.ProviderType,
			InstanceBaseURL: baseURL,
			ClientID:        provider.ClientID,
			ClientSecret:    clientSecret,
			TenantID:        tenantID,
		})
		if connErr != nil {
			log.Printf("Tag verification: failed to build connector for provider %s: %v", link.SCMProviderID, connErr)
			continue
		}

		// Fetch the current tag from the SCM provider
		currentTag, fetchErr := connector.FetchTagByName(ctx, oauthToken, link.RepositoryOwner, link.RepositoryName, *ver.TagName)
		if fetchErr != nil {
			log.Printf("Tag verification: failed to fetch tag %s for version %s/%s: %v",
				*ver.TagName, ver.ModuleID, ver.Version, fetchErr)
			continue
		}

		checked++

		// Compare the current commit SHA against the stored one
		if currentTag.TargetCommit != *ver.CommitSHA {
			violations++
			log.Printf("Tag verification VIOLATION: module_version=%s module=%s version=%s tag=%s stored_commit=%s current_commit=%s",
				ver.ID, ver.ModuleID, ver.Version, *ver.TagName, *ver.CommitSHA, currentTag.TargetCommit)
		}
	}

	log.Printf("Tag verification run completed: checked %d tags, found %d violations", checked, violations)
}
