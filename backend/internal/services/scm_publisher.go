// Package services implements higher-level business logic that coordinates across multiple repositories and external systems.
// The SCM publisher, for example, orchestrates cloning a repository, validating the module archive, storing it in the configured storage backend, and recording the version in the database — a multi-step operation that spans several domain boundaries.
package services

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

const (
	// maxExtractBytes caps the number of bytes copied from any single tar entry
	// during archive extraction to prevent decompression bomb attacks.
	maxExtractBytes = 500 << 20 // 500 MB
)

// SCMPublisher handles automated publishing from SCM repositories
type SCMPublisher struct {
	scmRepo        *repositories.SCMRepository
	moduleRepo     *repositories.ModuleRepository
	storageBackend storage.Storage
	tokenCipher    *crypto.TokenCipher
	tempDir        string
}

// NewSCMPublisher creates a new SCM publisher
func NewSCMPublisher(scmRepo *repositories.SCMRepository, moduleRepo *repositories.ModuleRepository, storageBackend storage.Storage, tokenCipher *crypto.TokenCipher) *SCMPublisher {
	return &SCMPublisher{
		scmRepo:        scmRepo,
		moduleRepo:     moduleRepo,
		storageBackend: storageBackend,
		tokenCipher:    tokenCipher,
		tempDir:        os.TempDir(),
	}
}

// ProcessTagPush processes a tag push webhook and publishes a new version
func (p *SCMPublisher) ProcessTagPush(ctx context.Context, logID uuid.UUID, moduleSourceRepo *scm.ModuleSourceRepoRecord, hook *scm.IncomingHook, connector scm.Connector) {
	// Update webhook log to processing
	if err := p.scmRepo.UpdateWebhookLogState(ctx, logID, "processing", nil, nil); err != nil {
		return
	}

	// Extract version from tag name
	version := p.extractVersionFromTag(hook.TagName, moduleSourceRepo.TagPattern)
	if version == "" {
		errMsg := "could not extract version from tag"
		_ = p.scmRepo.UpdateWebhookLogState(ctx, logID, "failed", &errMsg, nil)
		return
	}

	// Check if this version already exists — skip gracefully
	existingVersion, err := p.moduleRepo.GetVersion(ctx, moduleSourceRepo.ModuleID.String(), version)
	if err != nil {
		errMsg := fmt.Sprintf("failed to check for existing version: %v", err)
		_ = p.scmRepo.UpdateWebhookLogState(ctx, logID, "failed", &errMsg, nil)
		return
	}
	if existingVersion != nil {
		skipMsg := fmt.Sprintf("version %s already exists, skipping", version)
		_ = p.scmRepo.UpdateWebhookLogState(ctx, logID, "skipped", &skipMsg, nil)
		return
	}

	// Look up the module to get namespace/name/system and owner for token lookup
	module, err := p.moduleRepo.GetModuleByID(ctx, moduleSourceRepo.ModuleID.String())
	if err != nil {
		errMsg := fmt.Sprintf("failed to look up module: %v", err)
		_ = p.scmRepo.UpdateWebhookLogState(ctx, logID, "failed", &errMsg, nil)
		return
	}
	if module == nil {
		errMsg := "module not found"
		_ = p.scmRepo.UpdateWebhookLogState(ctx, logID, "failed", &errMsg, nil)
		return
	}

	// Resolve OAuth token so downloads from private repos work.
	// Fall back to nil (unauthenticated) when the module owner has no stored token.
	var oauthToken *scm.OAuthToken
	if module.CreatedBy != nil {
		if createdByUUID, parseErr := uuid.Parse(*module.CreatedBy); parseErr == nil {
			if tokenRecord, tokenErr := p.scmRepo.GetUserToken(ctx, createdByUUID, moduleSourceRepo.SCMProviderID); tokenErr == nil && tokenRecord != nil {
				if accessToken, decryptErr := p.tokenCipher.Open(tokenRecord.AccessTokenEncrypted); decryptErr == nil {
					oauthToken = &scm.OAuthToken{
						AccessToken: accessToken,
						TokenType:   tokenRecord.TokenType,
						ExpiresAt:   tokenRecord.ExpiresAt,
					}
				}
			}
		}
	}

	// Publish the module version (download, upload, create DB record)
	versionID, err := p.publishModuleVersion(ctx, connector, oauthToken, moduleSourceRepo, hook, version)
	if err != nil {
		errMsg := fmt.Sprintf("failed to publish version: %v", err)
		_ = p.scmRepo.UpdateWebhookLogState(ctx, logID, "failed", &errMsg, nil)
		return
	}

	// Update webhook log to success
	versionUUID, _ := uuid.Parse(versionID)
	_ = p.scmRepo.UpdateWebhookLogState(ctx, logID, "completed", nil, &versionUUID)
}

// downloadAndPackage downloads the repository and creates a tarball
func (p *SCMPublisher) downloadAndPackage(ctx context.Context, connector scm.Connector, token *scm.OAuthToken,
	owner, repo, commitSHA, subpath string) (string, string, error) {

	// Download source archive
	archive, err := connector.DownloadSourceArchive(ctx, token, owner, repo, commitSHA, scm.ArchiveTarball)
	if err != nil {
		return "", "", fmt.Errorf("download failed: %w", err)
	}
	defer archive.Close()

	// Create temp directory for extraction
	tempDir := filepath.Join(p.tempDir, fmt.Sprintf("scm-publish-%s", uuid.New().String()))
	if err := os.MkdirAll(tempDir, 0750); err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tempDir)

	// Extract archive
	if err := p.extractTarGz(archive, tempDir); err != nil {
		return "", "", fmt.Errorf("extraction failed: %w", err)
	}

	// Find the module subpath
	modulePath := filepath.Join(tempDir, subpath)
	if _, err := os.Stat(modulePath); os.IsNotExist(err) {
		// Try to find it in subdirectories (GitHub/GitLab wrap in repo name directory)
		entries, _ := os.ReadDir(tempDir)
		if len(entries) == 1 && entries[0].IsDir() {
			modulePath = filepath.Join(tempDir, entries[0].Name(), subpath)
		}
	}

	// Validate module structure
	if err := p.validateModuleStructure(modulePath); err != nil {
		return "", "", fmt.Errorf("invalid module structure: %w", err)
	}

	// Create new tarball with commit SHA manifest
	outputPath := filepath.Join(p.tempDir, fmt.Sprintf("module-%s.tar.gz", uuid.New().String()))
	checksum, err := p.createImmutableTarball(modulePath, outputPath, commitSHA)
	if err != nil {
		return "", "", fmt.Errorf("packaging failed: %w", err)
	}

	return outputPath, checksum, nil
}

// extractTarGz extracts a tar.gz archive
func (p *SCMPublisher) extractTarGz(r io.Reader, dest string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Prevent path traversal
		target := filepath.Join(dest, header.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxExtractBytes)); err != nil {
				_ = f.Close()
				return err
			}
			_ = f.Close()
		}
	}
	return nil
}

// validateModuleStructure validates that the directory contains a valid Terraform module
func (p *SCMPublisher) validateModuleStructure(path string) error {
	// Check for at least one .tf file
	files, err := filepath.Glob(filepath.Join(path, "*.tf"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .tf files found in module directory")
	}
	return nil
}

// createImmutableTarball creates a tarball with a commit manifest
func (p *SCMPublisher) createImmutableTarball(srcPath, destPath, commitSHA string) (string, error) {
	outFile, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	// Calculate checksum while writing
	hasher := sha256.New()
	mw := io.MultiWriter(outFile, hasher)

	gzw := gzip.NewWriter(mw)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Add commit manifest file
	manifestContent := fmt.Sprintf("commit: %s\npublished: %s\n", commitSHA, time.Now().Format(time.RFC3339))
	manifestHeader := &tar.Header{
		Name:    ".terraform-registry-commit",
		Size:    int64(len(manifestContent)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(manifestHeader); err != nil {
		return "", err
	}
	if _, err := tw.Write([]byte(manifestContent)); err != nil {
		return "", err
	}

	// Add all module files
	err = filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(srcPath, path)
		if err != nil {
			return err
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		// Write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Write file content
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(tw, file)
		return err
	})

	if err != nil {
		return "", err
	}

	// Close writers to flush
	if err := tw.Close(); err != nil {
		return "", fmt.Errorf("failed to flush tar writer: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return "", fmt.Errorf("failed to flush gzip writer: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// extractVersionFromTag extracts a semantic version from a tag name
func (p *SCMPublisher) extractVersionFromTag(tag, glob string) string {
	// Convert glob pattern to regex
	pattern := strings.ReplaceAll(glob, "*", "(.*)")
	pattern = fmt.Sprintf("^%s$", pattern)

	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}

	matches := re.FindStringSubmatch(tag)
	if len(matches) < 2 {
		return ""
	}

	version := matches[1]

	// Remove leading 'v' if present
	version = strings.TrimPrefix(version, "v")

	// Validate semantic version format
	semverPattern := `^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z-]+)?(\+[0-9A-Za-z-]+)?$`
	if matched, _ := regexp.MatchString(semverPattern, version); !matched {
		return ""
	}

	return version
}

// TriggerManualSync scans a repository for tags and publishes any matching versions
// This is called when a user manually triggers a sync from the UI
func (p *SCMPublisher) TriggerManualSync(ctx context.Context, moduleSourceRepo *scm.ModuleSourceRepoRecord, connector scm.Connector, token *scm.OAuthToken) error {
	fmt.Printf("[TriggerManualSync] Starting sync for module %s from repo %s/%s\n",
		moduleSourceRepo.ModuleID, moduleSourceRepo.RepositoryOwner, moduleSourceRepo.RepositoryName)

	// List all tags from the repository
	tags, err := connector.FetchTags(ctx, token, moduleSourceRepo.RepositoryOwner, moduleSourceRepo.RepositoryName, scm.DefaultPagination())
	if err != nil {
		return fmt.Errorf("failed to list tags: %w", err)
	}

	fmt.Printf("[TriggerManualSync] Found %d tags in repository\n", len(tags))

	// Filter tags that match the pattern and publish them
	tagPattern := moduleSourceRepo.TagPattern
	if tagPattern == "" {
		tagPattern = "v*"
	}
	fmt.Printf("[TriggerManualSync] Using tag pattern: %s\n", tagPattern)

	matchingTags := 0
	for _, tag := range tags {
		fmt.Printf("[TriggerManualSync] Checking tag: %s\n", tag.TagName)

		// Check if tag matches pattern
		version := p.extractVersionFromTag(tag.TagName, tagPattern)
		if version == "" {
			fmt.Printf("[TriggerManualSync] Tag %s does not match pattern, skipping\n", tag.TagName)
			continue // Skip tags that don't match the pattern
		}

		fmt.Printf("[TriggerManualSync] Tag %s matches! Extracted version: %s\n", tag.TagName, version)

		// Check if this version already exists — skip if so
		existing, err := p.moduleRepo.GetVersion(ctx, moduleSourceRepo.ModuleID.String(), version)
		if err != nil {
			fmt.Printf("[TriggerManualSync] Warning: failed to check existing version %s: %v\n", version, err)
		} else if existing != nil {
			fmt.Printf("[TriggerManualSync] Version %s already exists, skipping\n", version)
			continue
		}

		matchingTags++

		// Create a synthetic webhook event for this tag
		hook := &scm.IncomingHook{
			TagName:   tag.TagName,
			CommitSHA: tag.TargetCommit,
		}

		// Process this tag push (without a webhook log ID since this is manual)
		// We'll pass a nil UUID since webhook logging isn't applicable here
		fmt.Printf("[TriggerManualSync] Starting goroutine to process tag %s (commit: %s)\n", tag.TagName, tag.TargetCommit)
		go p.processTagForManualSync(ctx, moduleSourceRepo, hook, connector, token)
	}

	fmt.Printf("[TriggerManualSync] Found %d matching tags out of %d total\n", matchingTags, len(tags))

	// Update last sync time
	now := time.Now()
	moduleSourceRepo.LastSyncAt = &now
	if err := p.scmRepo.UpdateModuleSourceRepo(ctx, moduleSourceRepo); err != nil {
		return fmt.Errorf("failed to update last sync time: %w", err)
	}

	return nil
}

// processTagForManualSync processes a single tag during manual sync (no webhook logging)
func (p *SCMPublisher) processTagForManualSync(ctx context.Context, moduleSourceRepo *scm.ModuleSourceRepoRecord, hook *scm.IncomingHook, connector scm.Connector, token *scm.OAuthToken) {
	fmt.Printf("[processTagForManualSync] Processing tag %s for module %s\n", hook.TagName, moduleSourceRepo.ModuleID)

	// Extract version from tag name
	version := p.extractVersionFromTag(hook.TagName, moduleSourceRepo.TagPattern)
	if version == "" {
		fmt.Printf("[processTagForManualSync] Failed to extract version from tag %s\n", hook.TagName)
		return
	}
	fmt.Printf("[processTagForManualSync] Extracted version: %s\n", version)

	// Guard against races: the caller (TriggerManualSync) checks for existing versions before
	// spawning goroutines, but a second goroutine may have created it in the meantime.
	if existingVer, checkErr := p.moduleRepo.GetVersion(ctx, moduleSourceRepo.ModuleID.String(), version); checkErr == nil && existingVer != nil {
		fmt.Printf("[processTagForManualSync] Version %s already exists, skipping\n", version)
		return
	}

	versionID, err := p.publishModuleVersion(ctx, connector, token, moduleSourceRepo, hook, version)
	if err != nil {
		fmt.Printf("[processTagForManualSync] Failed to publish version %s: %v\n", version, err)
		return
	}

	fmt.Printf("[processTagForManualSync] Successfully created version %s (ID %s) for module %s\n", version, versionID, moduleSourceRepo.ModuleID)
}

// publishModuleVersion contains the shared logic for publishing a module version
// from an SCM tag. It downloads the source archive, uploads it to storage,
// extracts a README, and creates the database record. Both webhook-driven
// (ProcessTagPush) and manual sync (processTagForManualSync) paths call this.
func (p *SCMPublisher) publishModuleVersion(
	ctx context.Context,
	connector scm.Connector,
	token *scm.OAuthToken,
	moduleSourceRepo *scm.ModuleSourceRepoRecord,
	hook *scm.IncomingHook,
	version string,
) (string, error) {
	// Look up the module to get namespace/name/system
	module, err := p.moduleRepo.GetModuleByID(ctx, moduleSourceRepo.ModuleID.String())
	if err != nil {
		return "", fmt.Errorf("look up module: %w", err)
	}
	if module == nil {
		return "", fmt.Errorf("module %s not found", moduleSourceRepo.ModuleID)
	}

	// Download source archive at the specific commit
	archivePath, checksum, err := p.downloadAndPackage(ctx, connector, token, moduleSourceRepo.RepositoryOwner,
		moduleSourceRepo.RepositoryName, hook.CommitSHA, moduleSourceRepo.ModulePath)
	if err != nil {
		return "", fmt.Errorf("download source: %w", err)
	}
	defer os.Remove(archivePath)

	// Open archive for upload
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open archive: %w", err)
	}
	defer file.Close()

	storagePath := fmt.Sprintf("modules/%s/%s/%s/%s-%s.tar.gz",
		module.Namespace, module.Name, module.System, module.Name, version)

	// Get file size for upload
	fileInfo, err := os.Stat(archivePath)
	if err != nil {
		return "", fmt.Errorf("stat temp file: %w", err)
	}

	if _, err := p.storageBackend.Upload(ctx, storagePath, file, fileInfo.Size()); err != nil {
		return "", fmt.Errorf("upload to storage: %w", err)
	}

	// Extract README from the archive
	var readmeContent *string
	if readmeFile, err := os.Open(archivePath); err == nil {
		if readme, err := validation.ExtractReadme(readmeFile); err == nil && readme != "" {
			readmeContent = &readme
		}
		_ = readmeFile.Close()
	}

	// Create module version record
	versionID := uuid.New().String()
	scmRepoIDStr := moduleSourceRepo.ID.String()
	tagName := hook.TagName
	commitSHA := hook.CommitSHA

	moduleVersion := &models.ModuleVersion{
		ID:             versionID,
		ModuleID:       moduleSourceRepo.ModuleID.String(),
		Version:        version,
		StoragePath:    storagePath,
		StorageBackend: "default",
		SizeBytes:      fileInfo.Size(),
		Checksum:       checksum,
		CreatedAt:      time.Now(),
		Readme:         readmeContent,
		CommitSHA:      &commitSHA,
		TagName:        &tagName,
		SCMRepoID:      &scmRepoIDStr,
	}

	if err := p.moduleRepo.CreateVersion(ctx, moduleVersion); err != nil {
		return "", fmt.Errorf("create version: %w", err)
	}

	return versionID, nil
}
