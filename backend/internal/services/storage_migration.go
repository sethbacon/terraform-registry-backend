// Package services implements the StorageMigrationService which orchestrates
// copying artifacts between storage backends with progress tracking and cancellation.
package services

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// StorageMigrationService manages migrations between storage backends.
type StorageMigrationService struct {
	repo              *repositories.StorageMigrationRepository
	storageConfigRepo *repositories.StorageConfigRepository
	moduleRepo        *repositories.ModuleRepository
	providerRepo      *repositories.ProviderRepository
	tokenCipher       *crypto.TokenCipher
	cfg               *config.Config
	cancelFuncs       sync.Map // migrationID -> context.CancelFunc
}

// NewStorageMigrationService creates a new StorageMigrationService.
func NewStorageMigrationService(
	repo *repositories.StorageMigrationRepository,
	storageConfigRepo *repositories.StorageConfigRepository,
	moduleRepo *repositories.ModuleRepository,
	providerRepo *repositories.ProviderRepository,
	tokenCipher *crypto.TokenCipher,
	cfg *config.Config,
) *StorageMigrationService {
	return &StorageMigrationService{
		repo:              repo,
		storageConfigRepo: storageConfigRepo,
		moduleRepo:        moduleRepo,
		providerRepo:      providerRepo,
		tokenCipher:       tokenCipher,
		cfg:               cfg,
	}
}

// PlanMigration counts artifacts that would be migrated between two storage configs.
// coverage:skip:requires-infrastructure
func (s *StorageMigrationService) PlanMigration(ctx context.Context, sourceConfigID, targetConfigID string) (*models.MigrationPlan, error) {
	srcID, err := uuid.Parse(sourceConfigID)
	if err != nil {
		return nil, fmt.Errorf("invalid source_config_id: %w", err)
	}
	tgtID, err := uuid.Parse(targetConfigID)
	if err != nil {
		return nil, fmt.Errorf("invalid target_config_id: %w", err)
	}

	srcCfg, err := s.storageConfigRepo.GetStorageConfig(ctx, srcID)
	if err != nil {
		return nil, fmt.Errorf("failed to get source config: %w", err)
	}
	if srcCfg == nil {
		return nil, fmt.Errorf("source storage config not found")
	}

	tgtCfg, err := s.storageConfigRepo.GetStorageConfig(ctx, tgtID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target config: %w", err)
	}
	if tgtCfg == nil {
		return nil, fmt.Errorf("target storage config not found")
	}

	moduleArtifacts, err := s.repo.GetModuleArtifacts(ctx, srcCfg.BackendType)
	if err != nil {
		return nil, fmt.Errorf("failed to count module artifacts: %w", err)
	}

	providerArtifacts, err := s.repo.GetProviderArtifacts(ctx, srcCfg.BackendType)
	if err != nil {
		return nil, fmt.Errorf("failed to count provider artifacts: %w", err)
	}

	return &models.MigrationPlan{
		SourceConfigID: sourceConfigID,
		TargetConfigID: targetConfigID,
		ModuleCount:    len(moduleArtifacts),
		ProviderCount:  len(providerArtifacts),
		TotalArtifacts: len(moduleArtifacts) + len(providerArtifacts),
	}, nil
}

// StartMigration creates a migration record, populates items, and launches
// background execution. Returns the migration record immediately.
// coverage:skip:requires-infrastructure
func (s *StorageMigrationService) StartMigration(ctx context.Context, sourceConfigID, targetConfigID, userID string) (*models.StorageMigration, error) {
	srcID, err := uuid.Parse(sourceConfigID)
	if err != nil {
		return nil, fmt.Errorf("invalid source_config_id: %w", err)
	}
	tgtID, err := uuid.Parse(targetConfigID)
	if err != nil {
		return nil, fmt.Errorf("invalid target_config_id: %w", err)
	}

	srcCfg, err := s.storageConfigRepo.GetStorageConfig(ctx, srcID)
	if err != nil || srcCfg == nil {
		return nil, fmt.Errorf("source storage config not found")
	}
	tgtCfg, err := s.storageConfigRepo.GetStorageConfig(ctx, tgtID)
	if err != nil || tgtCfg == nil {
		return nil, fmt.Errorf("target storage config not found")
	}

	// Gather all artifacts from the source backend
	moduleArtifacts, err := s.repo.GetModuleArtifacts(ctx, srcCfg.BackendType)
	if err != nil {
		return nil, fmt.Errorf("failed to list module artifacts: %w", err)
	}
	providerArtifacts, err := s.repo.GetProviderArtifacts(ctx, srcCfg.BackendType)
	if err != nil {
		return nil, fmt.Errorf("failed to list provider artifacts: %w", err)
	}

	totalArtifacts := len(moduleArtifacts) + len(providerArtifacts)
	migrationID := uuid.New().String()
	now := time.Now()
	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}

	migration := &models.StorageMigration{
		ID:             migrationID,
		SourceConfigID: sourceConfigID,
		TargetConfigID: targetConfigID,
		Status:         "pending",
		TotalArtifacts: totalArtifacts,
		CreatedAt:      now,
		CreatedBy:      createdBy,
	}

	if err := s.repo.CreateMigration(ctx, migration); err != nil {
		return nil, fmt.Errorf("failed to create migration: %w", err)
	}

	// Build migration items
	items := make([]*models.StorageMigrationItem, 0, totalArtifacts)
	for _, a := range moduleArtifacts {
		items = append(items, &models.StorageMigrationItem{
			ID:           uuid.New().String(),
			MigrationID:  migrationID,
			ArtifactType: "module",
			ArtifactID:   a.ID,
			SourcePath:   a.StoragePath,
			Status:       "pending",
		})
	}
	for _, a := range providerArtifacts {
		items = append(items, &models.StorageMigrationItem{
			ID:           uuid.New().String(),
			MigrationID:  migrationID,
			ArtifactType: "provider",
			ArtifactID:   a.ID,
			SourcePath:   a.StoragePath,
			Status:       "pending",
		})
	}

	// Batch insert items (chunk to avoid overly large statements)
	const batchSize = 500
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		if err := s.repo.CreateMigrationItems(ctx, items[i:end]); err != nil {
			return nil, fmt.Errorf("failed to create migration items: %w", err)
		}
	}

	// Launch background execution
	bgCtx, cancel := context.WithCancel(context.Background())
	s.cancelFuncs.Store(migrationID, cancel)
	go s.executeMigration(bgCtx, migrationID)

	return migration, nil
}

// GetStatus returns the current migration progress.
// coverage:skip:requires-infrastructure
func (s *StorageMigrationService) GetStatus(ctx context.Context, id string) (*models.StorageMigration, error) {
	return s.repo.GetMigration(ctx, id)
}

// ListMigrations returns a paginated list of migrations.
// coverage:skip:requires-infrastructure
func (s *StorageMigrationService) ListMigrations(ctx context.Context, limit, offset int) ([]*models.StorageMigration, int, error) {
	return s.repo.ListMigrations(ctx, limit, offset)
}

// CancelMigration cancels a running migration.
// coverage:skip:requires-infrastructure
func (s *StorageMigrationService) CancelMigration(ctx context.Context, id string) error {
	m, err := s.repo.GetMigration(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get migration: %w", err)
	}
	if m == nil {
		return fmt.Errorf("migration not found")
	}
	if m.Status != "running" && m.Status != "pending" {
		return fmt.Errorf("migration is not in a cancellable state (status: %s)", m.Status)
	}

	// Signal the background goroutine
	if cancelFn, ok := s.cancelFuncs.LoadAndDelete(id); ok {
		cancelFn.(context.CancelFunc)()
	}

	return s.repo.UpdateMigrationStatus(ctx, id, "cancelled", nil)
}

// buildStorageFromConfig constructs a storage.Storage instance from a DB-persisted StorageConfig.
func (s *StorageMigrationService) buildStorageFromConfig(sc *models.StorageConfig) (storage.Storage, error) {
	cfg := &config.Config{}
	cfg.Storage.DefaultBackend = sc.BackendType

	switch sc.BackendType {
	case "local":
		cfg.Storage.Local = config.LocalStorageConfig{
			BasePath: sc.LocalBasePath.String,
		}
		if sc.LocalServeDirectly.Valid {
			cfg.Storage.Local.ServeDirectly = sc.LocalServeDirectly.Bool
		}

	case "azure":
		acfg := config.AzureStorageConfig{
			AccountName:   sc.AzureAccountName.String,
			ContainerName: sc.AzureContainerName.String,
			CDNURL:        sc.AzureCDNURL.String,
		}
		if sc.AzureAccountKeyEncrypted.Valid && sc.AzureAccountKeyEncrypted.String != "" {
			key, err := s.tokenCipher.Open(sc.AzureAccountKeyEncrypted.String)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt azure account key: %w", err)
			}
			acfg.AccountKey = key
		}
		cfg.Storage.Azure = acfg

	case "s3":
		scfg := config.S3StorageConfig{
			Endpoint:             sc.S3Endpoint.String,
			Region:               sc.S3Region.String,
			Bucket:               sc.S3Bucket.String,
			AuthMethod:           sc.S3AuthMethod.String,
			RoleARN:              sc.S3RoleARN.String,
			RoleSessionName:      sc.S3RoleSessionName.String,
			ExternalID:           sc.S3ExternalID.String,
			WebIdentityTokenFile: sc.S3WebIdentityTokenFile.String,
		}
		if sc.S3AccessKeyIDEncrypted.Valid && sc.S3AccessKeyIDEncrypted.String != "" {
			v, err := s.tokenCipher.Open(sc.S3AccessKeyIDEncrypted.String)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt s3 access key id: %w", err)
			}
			scfg.AccessKeyID = v
		}
		if sc.S3SecretAccessKeyEncrypted.Valid && sc.S3SecretAccessKeyEncrypted.String != "" {
			v, err := s.tokenCipher.Open(sc.S3SecretAccessKeyEncrypted.String)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt s3 secret access key: %w", err)
			}
			scfg.SecretAccessKey = v
		}
		cfg.Storage.S3 = scfg

	case "gcs":
		gcfg := config.GCSStorageConfig{
			Bucket:          sc.GCSBucket.String,
			ProjectID:       sc.GCSProjectID.String,
			AuthMethod:      sc.GCSAuthMethod.String,
			CredentialsFile: sc.GCSCredentialsFile.String,
			Endpoint:        sc.GCSEndpoint.String,
		}
		if sc.GCSCredentialsJSONEncrypted.Valid && sc.GCSCredentialsJSONEncrypted.String != "" {
			v, err := s.tokenCipher.Open(sc.GCSCredentialsJSONEncrypted.String)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt gcs credentials json: %w", err)
			}
			gcfg.CredentialsJSON = v
		}
		cfg.Storage.GCS = gcfg
	}

	return storage.NewStorage(cfg)
}

// executeMigration runs in the background, downloading from source and uploading
// to target for each pending item. It uses a worker pool of 4 goroutines.
// coverage:skip:requires-infrastructure
func (s *StorageMigrationService) executeMigration(ctx context.Context, migrationID string) {
	log := slog.With("migration_id", migrationID)
	log.Info("starting storage migration execution")

	defer func() {
		s.cancelFuncs.Delete(migrationID)
	}()

	// Mark migration as running
	if err := s.repo.SetMigrationStarted(ctx, migrationID); err != nil {
		log.Error("failed to mark migration as started", "error", err)
		errMsg := err.Error()
		_ = s.repo.UpdateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	// Load source and target configs
	m, err := s.repo.GetMigration(ctx, migrationID)
	if err != nil || m == nil {
		log.Error("failed to load migration record", "error", err)
		return
	}

	srcID, _ := uuid.Parse(m.SourceConfigID)
	tgtID, _ := uuid.Parse(m.TargetConfigID)

	srcCfg, err := s.storageConfigRepo.GetStorageConfig(ctx, srcID)
	if err != nil || srcCfg == nil {
		errMsg := "source storage config not found"
		log.Error(errMsg)
		_ = s.repo.UpdateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	tgtCfg, err := s.storageConfigRepo.GetStorageConfig(ctx, tgtID)
	if err != nil || tgtCfg == nil {
		errMsg := "target storage config not found"
		log.Error(errMsg)
		_ = s.repo.UpdateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	srcStorage, err := s.buildStorageFromConfig(srcCfg)
	if err != nil {
		errMsg := fmt.Sprintf("failed to build source storage: %v", err)
		log.Error(errMsg)
		_ = s.repo.UpdateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	tgtStorage, err := s.buildStorageFromConfig(tgtCfg)
	if err != nil {
		errMsg := fmt.Sprintf("failed to build target storage: %v", err)
		log.Error(errMsg)
		_ = s.repo.UpdateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	// Process items with a worker pool
	const workerCount = 4
	const fetchBatch = 100

	var migrated, failed, skipped int64

	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup

	for {
		// Check for cancellation
		select {
		case <-ctx.Done():
			log.Info("migration cancelled, waiting for in-flight workers")
			wg.Wait()
			s.updateProgress(migrationID, &migrated, &failed, &skipped)
			return
		default:
		}

		items, err := s.repo.GetPendingItems(ctx, migrationID, fetchBatch)
		if err != nil {
			errMsg := fmt.Sprintf("failed to fetch pending items: %v", err)
			log.Error(errMsg)
			_ = s.repo.UpdateMigrationStatus(ctx, migrationID, "failed", &errMsg)
			return
		}
		if len(items) == 0 {
			break
		}

		for _, item := range items {
			select {
			case <-ctx.Done():
				wg.Wait()
				s.updateProgress(migrationID, &migrated, &failed, &skipped)
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(itm *models.StorageMigrationItem) {
				defer wg.Done()
				defer func() { <-sem }()

				migrateErr := s.migrateItem(ctx, srcStorage, tgtStorage, itm, tgtCfg.BackendType)
				if migrateErr != nil {
					atomic.AddInt64(&failed, 1)
					errStr := migrateErr.Error()
					_ = s.repo.UpdateItemStatus(ctx, itm.ID, "failed", &errStr)
					log.Warn("item migration failed", "item_id", itm.ID, "path", itm.SourcePath, "error", migrateErr)
				} else {
					atomic.AddInt64(&migrated, 1)
					_ = s.repo.UpdateItemStatus(ctx, itm.ID, "migrated", nil)
				}

				// Periodically update progress in the DB
				total := atomic.LoadInt64(&migrated) + atomic.LoadInt64(&failed) + atomic.LoadInt64(&skipped)
				if total%10 == 0 {
					s.updateProgress(migrationID, &migrated, &failed, &skipped)
				}
			}(item)
		}

		wg.Wait()
		s.updateProgress(migrationID, &migrated, &failed, &skipped)
	}

	wg.Wait()
	s.updateProgress(migrationID, &migrated, &failed, &skipped)

	// Final status
	finalFailed := atomic.LoadInt64(&failed)
	if finalFailed > 0 {
		errMsg := fmt.Sprintf("%d artifacts failed to migrate", finalFailed)
		_ = s.repo.UpdateMigrationStatus(ctx, migrationID, "completed", &errMsg)
		_ = s.repo.SetMigrationCompleted(ctx, migrationID)
	} else {
		_ = s.repo.SetMigrationCompleted(ctx, migrationID)
	}

	log.Info("storage migration completed",
		"migrated", atomic.LoadInt64(&migrated),
		"failed", finalFailed,
		"skipped", atomic.LoadInt64(&skipped),
	)
}

// migrateItem copies a single artifact from source to target storage and updates
// the storage_backend reference in the appropriate table.
// coverage:skip:requires-infrastructure
func (s *StorageMigrationService) migrateItem(
	ctx context.Context,
	srcStorage, tgtStorage storage.Storage,
	item *models.StorageMigrationItem,
	targetBackendType string,
) error {
	// Mark item as migrating
	_ = s.repo.UpdateItemStatus(ctx, item.ID, "migrating", nil)

	// Check if the file already exists in target
	exists, err := tgtStorage.Exists(ctx, item.SourcePath)
	if err == nil && exists {
		// Already present at target — still update the backend reference
		if updateErr := s.updateBackendRef(ctx, item, targetBackendType); updateErr != nil {
			return fmt.Errorf("target file exists but failed to update backend ref: %w", updateErr)
		}
		return nil
	}

	// Download from source
	reader, err := srcStorage.Download(ctx, item.SourcePath)
	if err != nil {
		return fmt.Errorf("download from source failed: %w", err)
	}
	defer func() { _ = reader.Close() }()

	// Get metadata for size information
	meta, metaErr := srcStorage.GetMetadata(ctx, item.SourcePath)
	var size int64
	if metaErr == nil && meta != nil {
		size = meta.Size
	}

	// Use io.Pipe for streaming to avoid buffering large archives in memory
	pr, pw := io.Pipe()
	var uploadErr error
	var uploadDone = make(chan struct{})

	go func() {
		defer close(uploadDone)
		_, uploadErr = tgtStorage.Upload(ctx, item.SourcePath, pr, size)
		if uploadErr != nil {
			_ = pr.CloseWithError(uploadErr)
		}
	}()

	// Copy source reader into the pipe writer
	if _, copyErr := io.Copy(pw, reader); copyErr != nil {
		_ = pw.CloseWithError(copyErr)
		<-uploadDone
		return fmt.Errorf("streaming copy failed: %w", copyErr)
	}
	_ = pw.Close()
	<-uploadDone

	if uploadErr != nil {
		return fmt.Errorf("upload to target failed: %w", uploadErr)
	}

	// Update the backend reference in module_versions or provider_platforms
	if err := s.updateBackendRef(ctx, item, targetBackendType); err != nil {
		return fmt.Errorf("failed to update backend reference: %w", err)
	}

	return nil
}

// updateBackendRef updates the storage_backend column in the appropriate table.
func (s *StorageMigrationService) updateBackendRef(ctx context.Context, item *models.StorageMigrationItem, backend string) error {
	switch item.ArtifactType {
	case "module":
		return s.repo.UpdateModuleVersionBackend(ctx, item.ArtifactID, backend)
	case "provider":
		return s.repo.UpdateProviderPlatformBackend(ctx, item.ArtifactID, backend)
	default:
		return fmt.Errorf("unknown artifact type: %s", item.ArtifactType)
	}
}

// updateProgress writes current counters to the migration record.
func (s *StorageMigrationService) updateProgress(migrationID string, migrated, failed, skipped *int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.repo.UpdateMigrationProgress(ctx, migrationID,
		int(atomic.LoadInt64(migrated)),
		int(atomic.LoadInt64(failed)),
		int(atomic.LoadInt64(skipped)),
	)
}

// ensure sql import is used (referenced by models.StorageConfig using sql.NullString)
var _ = sql.ErrNoRows
