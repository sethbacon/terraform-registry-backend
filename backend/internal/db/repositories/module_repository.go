// module_repository.go implements ModuleRepository, providing database queries for module
// and module version CRUD operations and namespace/name-based search.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ModuleRepository handles database operations for modules
type ModuleRepository struct {
	db *sql.DB
}

// NewModuleRepository creates a new module repository
func NewModuleRepository(db *sql.DB) *ModuleRepository {
	return &ModuleRepository{db: db}
}

// CreateModule inserts a new module record
func (r *ModuleRepository) CreateModule(ctx context.Context, module *models.Module) error {
	query := `
		INSERT INTO modules (organization_id, namespace, name, system, description, source, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRowContext(ctx, query,
		module.OrganizationID,
		module.Namespace,
		module.Name,
		module.System,
		module.Description,
		module.Source,
		module.CreatedBy,
	).Scan(&module.ID, &module.CreatedAt, &module.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create module: %w", err)
	}

	return nil
}

// UpsertModule atomically creates a module or returns the existing one.
// This prevents race conditions when two concurrent uploads target the same
// namespace/name/system combination. Description and source are only set on
// initial insert (not overwritten on conflict) — use UpdateModule for that.
func (r *ModuleRepository) UpsertModule(ctx context.Context, module *models.Module) error {
	query := `
		INSERT INTO modules (organization_id, namespace, name, system, description, source, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (organization_id, namespace, name, system) DO UPDATE
		SET updated_at = NOW()
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRowContext(ctx, query,
		module.OrganizationID,
		module.Namespace,
		module.Name,
		module.System,
		module.Description,
		module.Source,
		module.CreatedBy,
	).Scan(&module.ID, &module.CreatedAt, &module.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to upsert module: %w", err)
	}

	return nil
}

// GetModule retrieves a module by organization, namespace, name, and system
func (r *ModuleRepository) GetModule(ctx context.Context, orgID, namespace, name, system string) (*models.Module, error) {
	query := `
		SELECT m.id, m.organization_id, m.namespace, m.name, m.system, m.description, m.source,
		       m.created_by, m.created_at, m.updated_at, u.name as created_by_name
		FROM modules m
		LEFT JOIN users u ON m.created_by = u.id
		WHERE m.organization_id = $1 AND m.namespace = $2 AND m.name = $3 AND m.system = $4
	`

	module := &models.Module{}
	err := r.db.QueryRowContext(ctx, query, orgID, namespace, name, system).Scan(
		&module.ID,
		&module.OrganizationID,
		&module.Namespace,
		&module.Name,
		&module.System,
		&module.Description,
		&module.Source,
		&module.CreatedBy,
		&module.CreatedAt,
		&module.UpdatedAt,
		&module.CreatedByName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get module: %w", err)
	}

	return module, nil
}

// GetModuleByID retrieves a module by its UUID
func (r *ModuleRepository) GetModuleByID(ctx context.Context, id string) (*models.Module, error) {
	query := `
		SELECT m.id, m.organization_id, m.namespace, m.name, m.system, m.description, m.source,
		       m.created_by, m.created_at, m.updated_at, u.name as created_by_name
		FROM modules m
		LEFT JOIN users u ON m.created_by = u.id
		WHERE m.id = $1
	`

	module := &models.Module{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&module.ID,
		&module.OrganizationID,
		&module.Namespace,
		&module.Name,
		&module.System,
		&module.Description,
		&module.Source,
		&module.CreatedBy,
		&module.CreatedAt,
		&module.UpdatedAt,
		&module.CreatedByName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get module by ID: %w", err)
	}

	return module, nil
}

// UpdateModule updates an existing module's metadata
func (r *ModuleRepository) UpdateModule(ctx context.Context, module *models.Module) error {
	query := `
		UPDATE modules
		SET description = $1, source = $2, updated_at = NOW()
		WHERE id = $3
		RETURNING updated_at
	`

	err := r.db.QueryRowContext(ctx, query,
		module.Description,
		module.Source,
		module.ID,
	).Scan(&module.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to update module: %w", err)
	}

	return nil
}

// CreateVersion inserts a new module version
func (r *ModuleRepository) CreateVersion(ctx context.Context, version *models.ModuleVersion) error {
	query := `
		INSERT INTO module_versions
		  (module_id, version, storage_path, storage_backend, size_bytes, checksum, readme, published_by,
		   commit_sha, tag_name, scm_repo_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at
	`

	err := r.db.QueryRowContext(ctx, query,
		version.ModuleID,
		version.Version,
		version.StoragePath,
		version.StorageBackend,
		version.SizeBytes,
		version.Checksum,
		version.Readme,
		version.PublishedBy,
		version.CommitSHA,
		version.TagName,
		version.SCMRepoID,
	).Scan(&version.ID, &version.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create module version: %w", err)
	}

	return nil
}

// GetVersion retrieves a specific module version
func (r *ModuleRepository) GetVersion(ctx context.Context, moduleID, version string) (*models.ModuleVersion, error) {
	query := `
		SELECT id, module_id, version, storage_path, storage_backend, size_bytes, checksum, readme, published_by, download_count,
		       COALESCE(deprecated, false), deprecated_at, deprecation_message, created_at,
		       commit_sha, tag_name, scm_repo_id::text
		FROM module_versions
		WHERE module_id = $1 AND version = $2
	`

	v := &models.ModuleVersion{}
	err := r.db.QueryRowContext(ctx, query, moduleID, version).Scan(
		&v.ID,
		&v.ModuleID,
		&v.Version,
		&v.StoragePath,
		&v.StorageBackend,
		&v.SizeBytes,
		&v.Checksum,
		&v.Readme,
		&v.PublishedBy,
		&v.DownloadCount,
		&v.Deprecated,
		&v.DeprecatedAt,
		&v.DeprecationMessage,
		&v.CreatedAt,
		&v.CommitSHA,
		&v.TagName,
		&v.SCMRepoID,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get module version: %w", err)
	}

	return v, nil
}

// ListVersions retrieves all versions for a module, ordered by version DESC
func (r *ModuleRepository) ListVersions(ctx context.Context, moduleID string) ([]*models.ModuleVersion, error) {
	query := `
		SELECT mv.id, mv.module_id, mv.version, mv.storage_path, mv.storage_backend, mv.size_bytes, mv.checksum, mv.readme,
		       mv.published_by, u.name as published_by_name, mv.download_count,
		       COALESCE(mv.deprecated, false), mv.deprecated_at, mv.deprecation_message, mv.created_at,
		       mv.commit_sha, mv.tag_name, mv.scm_repo_id::text
		FROM module_versions mv
		LEFT JOIN users u ON mv.published_by = u.id
		WHERE mv.module_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, moduleID)
	if err != nil {
		return nil, fmt.Errorf("failed to list module versions: %w", err)
	}
	defer rows.Close()

	var versions []*models.ModuleVersion
	for rows.Next() {
		v := &models.ModuleVersion{}
		err := rows.Scan(
			&v.ID,
			&v.ModuleID,
			&v.Version,
			&v.StoragePath,
			&v.StorageBackend,
			&v.SizeBytes,
			&v.Checksum,
			&v.Readme,
			&v.PublishedBy,
			&v.PublishedByName,
			&v.DownloadCount,
			&v.Deprecated,
			&v.DeprecatedAt,
			&v.DeprecationMessage,
			&v.CreatedAt,
			&v.CommitSHA,
			&v.TagName,
			&v.SCMRepoID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan module version: %w", err)
		}
		versions = append(versions, v)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating module versions: %w", err)
	}

	// Sort by semver descending (highest version first)
	sort.Slice(versions, func(i, j int) bool {
		return moduleCompareSemver(versions[i].Version, versions[j].Version) > 0
	})

	return versions, nil
}

// GetAllWithSourceCommit returns all module versions that have a commit SHA recorded,
// which means they were published from an SCM source and can be verified.
func (r *ModuleRepository) GetAllWithSourceCommit(ctx context.Context) ([]*models.ModuleVersion, error) {
	query := `
		SELECT id, module_id, version, storage_path, storage_backend, size_bytes, checksum, readme,
		       published_by, download_count,
		       COALESCE(deprecated, false), deprecated_at, deprecation_message, created_at,
		       commit_sha, tag_name, scm_repo_id::text
		FROM module_versions
		WHERE commit_sha IS NOT NULL AND scm_repo_id IS NOT NULL
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query SCM-sourced versions: %w", err)
	}
	defer rows.Close()

	var versions []*models.ModuleVersion
	for rows.Next() {
		v := &models.ModuleVersion{}
		err := rows.Scan(
			&v.ID,
			&v.ModuleID,
			&v.Version,
			&v.StoragePath,
			&v.StorageBackend,
			&v.SizeBytes,
			&v.Checksum,
			&v.Readme,
			&v.PublishedBy,
			&v.DownloadCount,
			&v.Deprecated,
			&v.DeprecatedAt,
			&v.DeprecationMessage,
			&v.CreatedAt,
			&v.CommitSHA,
			&v.TagName,
			&v.SCMRepoID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SCM-sourced version: %w", err)
		}
		versions = append(versions, v)
	}

	return versions, rows.Err()
}

// moduleCompareSemver compares two semver strings for module version sorting.
// Returns 1 if a > b, -1 if a < b, 0 if equal.
func moduleCompareSemver(a, b string) int {
	aParts := moduleParseSemverParts(a)
	bParts := moduleParseSemverParts(b)
	for i := 0; i < 3; i++ {
		if aParts[i] > bParts[i] {
			return 1
		}
		if aParts[i] < bParts[i] {
			return -1
		}
	}
	return 0
}

// moduleParseSemverParts extracts [major, minor, patch] from a version string.
func moduleParseSemverParts(version string) [3]int {
	version = strings.TrimPrefix(version, "v")
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}
	parts := strings.Split(version, ".")
	var result [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		result[i], _ = strconv.Atoi(parts[i])
	}
	return result
}

// IncrementDownloadCount increments the download counter for a version
func (r *ModuleRepository) IncrementDownloadCount(ctx context.Context, versionID string) error {
	query := `
		UPDATE module_versions
		SET download_count = download_count + 1
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, versionID)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	return nil
}

// SearchModules searches for modules matching the query
func (r *ModuleRepository) SearchModules(ctx context.Context, orgID, query, namespace, system string, limit, offset int) ([]*models.Module, int, error) {
	// Build WHERE clause
	var whereClause string
	var args []interface{}
	argCount := 0

	// Only filter by organization if orgID is provided (multi-tenant mode)
	if orgID != "" {
		argCount++
		whereClause = fmt.Sprintf("WHERE m.organization_id = $%d", argCount)
		args = append(args, orgID)
	} else {
		whereClause = "WHERE 1=1" // No org filter in single-tenant mode
	}

	if query != "" {
		argCount++
		whereClause += fmt.Sprintf(" AND (m.namespace ILIKE $%d OR m.name ILIKE $%d OR m.description ILIKE $%d)", argCount, argCount, argCount)
		args = append(args, "%"+query+"%")
	}

	if namespace != "" {
		argCount++
		whereClause += fmt.Sprintf(" AND m.namespace = $%d", argCount)
		args = append(args, namespace)
	}

	if system != "" {
		argCount++
		whereClause += fmt.Sprintf(" AND m.system = $%d", argCount)
		args = append(args, system)
	}

	// Count total results
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM modules %s", whereClause)
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count modules: %w", err)
	}

	// Query with pagination and JOIN for created_by_name
	query = fmt.Sprintf(`
		SELECT m.id, m.organization_id, m.namespace, m.name, m.system, m.description, m.source,
		       m.created_by, u.name as created_by_name, m.created_at, m.updated_at
		FROM modules m
		LEFT JOIN users u ON m.created_by = u.id
		%s
		ORDER BY m.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount+1, argCount+2)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search modules: %w", err)
	}
	defer rows.Close()

	var modules []*models.Module
	for rows.Next() {
		m := &models.Module{}
		err := rows.Scan(
			&m.ID,
			&m.OrganizationID,
			&m.Namespace,
			&m.Name,
			&m.System,
			&m.Description,
			&m.Source,
			&m.CreatedBy,
			&m.CreatedByName,
			&m.CreatedAt,
			&m.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan module: %w", err)
		}
		modules = append(modules, m)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating modules: %w", err)
	}

	return modules, total, nil
}

// SearchModulesWithStats returns modules matching the search criteria along with
// their latest version and total download count in a single query, eliminating
// the N+1 query pattern from the original SearchModules + per-module ListVersions.
func (r *ModuleRepository) SearchModulesWithStats(ctx context.Context, orgID, searchQuery, namespace, system string, limit, offset int) ([]*models.ModuleSearchResult, int, error) {
	var whereClauses []string
	var args []interface{}
	argCount := 0

	if orgID != "" {
		argCount++
		whereClauses = append(whereClauses, fmt.Sprintf("m.organization_id = $%d", argCount))
		args = append(args, orgID)
	}
	if searchQuery != "" {
		argCount++
		whereClauses = append(whereClauses, fmt.Sprintf("(m.namespace ILIKE $%d OR m.name ILIKE $%d OR m.description ILIKE $%d)", argCount, argCount, argCount))
		args = append(args, "%"+searchQuery+"%")
	}
	if namespace != "" {
		argCount++
		whereClauses = append(whereClauses, fmt.Sprintf("m.namespace = $%d", argCount))
		args = append(args, namespace)
	}
	if system != "" {
		argCount++
		whereClauses = append(whereClauses, fmt.Sprintf("m.system = $%d", argCount))
		args = append(args, system)
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Count total results
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM modules m %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count modules: %w", err)
	}

	// Single query: modules + latest version + total downloads via lateral join.
	// The lateral subquery fetches the latest version (by created_at) and sums
	// download counts across ALL versions — replacing the per-module ListVersions loop.
	searchSQL := fmt.Sprintf(`
		SELECT m.id, m.organization_id, m.namespace, m.name, m.system, m.description, m.source,
		       m.created_by, u.name AS created_by_name, m.created_at, m.updated_at,
		       agg.latest_version, COALESCE(agg.total_downloads, 0) AS total_downloads
		FROM modules m
		LEFT JOIN users u ON m.created_by = u.id
		LEFT JOIN LATERAL (
			SELECT
				(SELECT mv2.version FROM module_versions mv2 WHERE mv2.module_id = m.id ORDER BY mv2.created_at DESC LIMIT 1) AS latest_version,
				SUM(mv.download_count) AS total_downloads
			FROM module_versions mv
			WHERE mv.module_id = m.id
		) agg ON true
		%s
		ORDER BY m.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount+1, argCount+2)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, searchSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search modules: %w", err)
	}
	defer rows.Close()

	var results []*models.ModuleSearchResult
	for rows.Next() {
		res := &models.ModuleSearchResult{}
		err := rows.Scan(
			&res.ID, &res.OrganizationID, &res.Namespace, &res.Name, &res.System,
			&res.Description, &res.Source, &res.CreatedBy, &res.CreatedByName,
			&res.CreatedAt, &res.UpdatedAt,
			&res.LatestVersion, &res.TotalDownloads,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan module search result: %w", err)
		}
		results = append(results, res)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating module search results: %w", err)
	}

	return results, total, nil
}

// DeleteModule deletes a module and all its versions (cascade)
func (r *ModuleRepository) DeleteModule(ctx context.Context, moduleID string) error {
	query := `DELETE FROM modules WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, moduleID)
	if err != nil {
		return fmt.Errorf("failed to delete module: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("module not found")
	}

	return nil
}

// DeleteVersion deletes a specific module version
func (r *ModuleRepository) DeleteVersion(ctx context.Context, versionID string) error {
	query := `DELETE FROM module_versions WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, versionID)
	if err != nil {
		return fmt.Errorf("failed to delete module version: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("module version not found")
	}

	return nil
}

// DeprecateVersion marks a module version as deprecated
func (r *ModuleRepository) DeprecateVersion(ctx context.Context, versionID string, message *string) error {
	query := `
		UPDATE module_versions
		SET deprecated = true, deprecated_at = NOW(), deprecation_message = $2
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, versionID, message)
	if err != nil {
		return fmt.Errorf("failed to deprecate module version: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("module version not found")
	}

	return nil
}

// UndeprecateVersion removes the deprecated status from a module version
func (r *ModuleRepository) UndeprecateVersion(ctx context.Context, versionID string) error {
	query := `
		UPDATE module_versions
		SET deprecated = false, deprecated_at = NULL, deprecation_message = NULL
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, versionID)
	if err != nil {
		return fmt.Errorf("failed to undeprecate module version: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("module version not found")
	}

	return nil
}
