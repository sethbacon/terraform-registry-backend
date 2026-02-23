// provider_repository.go implements ProviderRepository, providing database queries for
// provider and provider version CRUD operations and namespace/type-based search.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ProviderRepository handles database operations for providers
type ProviderRepository struct {
	db *sql.DB
}

// NewProviderRepository creates a new provider repository
func NewProviderRepository(db *sql.DB) *ProviderRepository {
	return &ProviderRepository{db: db}
}

// CreateProvider inserts a new provider record
func (r *ProviderRepository) CreateProvider(ctx context.Context, provider *models.Provider) error {
	query := `
		INSERT INTO providers (organization_id, namespace, type, description, source, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`

	// Handle empty organization ID (single-tenant mode) by passing nil instead
	var orgID interface{}
	if provider.OrganizationID == "" {
		orgID = nil
	} else {
		orgID = provider.OrganizationID
	}

	err := r.db.QueryRowContext(ctx, query,
		orgID,
		provider.Namespace,
		provider.Type,
		provider.Description,
		provider.Source,
		provider.CreatedBy,
	).Scan(&provider.ID, &provider.CreatedAt, &provider.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	return nil
}

// GetProvider retrieves a provider by organization, namespace, and type
// In single-tenant mode (or when provider has NULL org_id), also matches providers with NULL organization_id
func (r *ProviderRepository) GetProvider(ctx context.Context, orgID, namespace, providerType string) (*models.Provider, error) {
	// Query that matches either the specific org ID or NULL org ID (for mirrored/single-tenant providers)
	query := `
		SELECT p.id, p.organization_id, p.namespace, p.type, p.description, p.source,
		       p.created_by, p.created_at, p.updated_at, u.name as created_by_name
		FROM providers p
		LEFT JOIN users u ON p.created_by = u.id
		WHERE (p.organization_id = $1 OR p.organization_id IS NULL) AND p.namespace = $2 AND p.type = $3
		LIMIT 1
	`

	provider := &models.Provider{}
	var scannedOrgID sql.NullString
	err := r.db.QueryRowContext(ctx, query, orgID, namespace, providerType).Scan(
		&provider.ID,
		&scannedOrgID,
		&provider.Namespace,
		&provider.Type,
		&provider.Description,
		&provider.Source,
		&provider.CreatedBy,
		&provider.CreatedAt,
		&provider.UpdatedAt,
		&provider.CreatedByName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	if scannedOrgID.Valid {
		provider.OrganizationID = scannedOrgID.String
	}

	return provider, nil
}

// GetProviderByNamespaceType retrieves a provider by namespace and type only (for single-tenant mode)
// If orgID is provided and not empty, it filters by organization as well
func (r *ProviderRepository) GetProviderByNamespaceType(ctx context.Context, orgID, namespace, providerType string) (*models.Provider, error) {
	var query string
	var args []interface{}

	if orgID != "" {
		query = `
			SELECT id, organization_id, namespace, type, description, source, created_at, updated_at
			FROM providers
			WHERE organization_id = $1 AND namespace = $2 AND type = $3
		`
		args = []interface{}{orgID, namespace, providerType}
	} else {
		// Single-tenant mode: find by namespace and type only
		query = `
			SELECT id, organization_id, namespace, type, description, source, created_at, updated_at
			FROM providers
			WHERE namespace = $1 AND type = $2
			LIMIT 1
		`
		args = []interface{}{namespace, providerType}
	}

	provider := &models.Provider{}
	var scannedOrgID sql.NullString
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&provider.ID,
		&scannedOrgID,
		&provider.Namespace,
		&provider.Type,
		&provider.Description,
		&provider.Source,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	if scannedOrgID.Valid {
		provider.OrganizationID = scannedOrgID.String
	}

	return provider, nil
}

// UpdateProvider updates an existing provider's metadata
func (r *ProviderRepository) UpdateProvider(ctx context.Context, provider *models.Provider) error {
	query := `
		UPDATE providers
		SET description = $1, source = $2, updated_at = NOW()
		WHERE id = $3
		RETURNING updated_at
	`

	err := r.db.QueryRowContext(ctx, query,
		provider.Description,
		provider.Source,
		provider.ID,
	).Scan(&provider.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}

	return nil
}

// DeleteProvider deletes a provider and all its versions/platforms (cascade)
func (r *ProviderRepository) DeleteProvider(ctx context.Context, providerID string) error {
	query := `DELETE FROM providers WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, providerID)
	if err != nil {
		return fmt.Errorf("failed to delete provider: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("provider not found")
	}

	return nil
}

// CreateVersion inserts a new provider version
func (r *ProviderRepository) CreateVersion(ctx context.Context, version *models.ProviderVersion) error {
	// Convert protocols slice to JSON
	protocolsJSON, err := json.Marshal(version.Protocols)
	if err != nil {
		return fmt.Errorf("failed to marshal protocols: %w", err)
	}

	query := `
		INSERT INTO provider_versions (provider_id, version, protocols, gpg_public_key, shasums_url, shasums_signature_url, published_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`

	err = r.db.QueryRowContext(ctx, query,
		version.ProviderID,
		version.Version,
		protocolsJSON,
		version.GPGPublicKey,
		version.ShasumURL,
		version.ShasumSignatureURL,
		version.PublishedBy,
	).Scan(&version.ID, &version.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create provider version: %w", err)
	}

	return nil
}

// GetVersion retrieves a specific provider version
func (r *ProviderRepository) GetVersion(ctx context.Context, providerID, version string) (*models.ProviderVersion, error) {
	query := `
		SELECT id, provider_id, version, protocols, gpg_public_key, shasums_url, shasums_signature_url, published_by,
		       COALESCE(deprecated, false), deprecated_at, deprecation_message, created_at
		FROM provider_versions
		WHERE provider_id = $1 AND version = $2
	`

	v := &models.ProviderVersion{}
	var protocolsJSON []byte

	err := r.db.QueryRowContext(ctx, query, providerID, version).Scan(
		&v.ID,
		&v.ProviderID,
		&v.Version,
		&protocolsJSON,
		&v.GPGPublicKey,
		&v.ShasumURL,
		&v.ShasumSignatureURL,
		&v.PublishedBy,
		&v.Deprecated,
		&v.DeprecatedAt,
		&v.DeprecationMessage,
		&v.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get provider version: %w", err)
	}

	// Unmarshal protocols
	if err := json.Unmarshal(protocolsJSON, &v.Protocols); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protocols: %w", err)
	}

	return v, nil
}

// ListVersions retrieves all versions for a provider, sorted by semver (highest first)
func (r *ProviderRepository) ListVersions(ctx context.Context, providerID string) ([]*models.ProviderVersion, error) {
	query := `
		SELECT pv.id, pv.provider_id, pv.version, pv.protocols, pv.gpg_public_key, pv.shasums_url, pv.shasums_signature_url,
		       pv.published_by, u.name as published_by_name,
		       COALESCE(pv.deprecated, false), pv.deprecated_at, pv.deprecation_message, pv.created_at
		FROM provider_versions pv
		LEFT JOIN users u ON pv.published_by = u.id
		WHERE pv.provider_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to list provider versions: %w", err)
	}
	defer rows.Close()

	var versions []*models.ProviderVersion
	for rows.Next() {
		v := &models.ProviderVersion{}
		var protocolsJSON []byte

		err := rows.Scan(
			&v.ID,
			&v.ProviderID,
			&v.Version,
			&protocolsJSON,
			&v.GPGPublicKey,
			&v.ShasumURL,
			&v.ShasumSignatureURL,
			&v.PublishedBy,
			&v.PublishedByName,
			&v.Deprecated,
			&v.DeprecatedAt,
			&v.DeprecationMessage,
			&v.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan provider version: %w", err)
		}

		// Unmarshal protocols
		if err := json.Unmarshal(protocolsJSON, &v.Protocols); err != nil {
			return nil, fmt.Errorf("failed to unmarshal protocols: %w", err)
		}

		versions = append(versions, v)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating provider versions: %w", err)
	}

	// Sort by semver (highest first)
	sort.Slice(versions, func(i, j int) bool {
		return compareSemver(versions[i].Version, versions[j].Version) > 0
	})

	return versions, nil
}

// DeleteVersion deletes a specific provider version and all its platforms (cascade)
func (r *ProviderRepository) DeleteVersion(ctx context.Context, versionID string) error {
	query := `DELETE FROM provider_versions WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, versionID)
	if err != nil {
		return fmt.Errorf("failed to delete provider version: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("provider version not found")
	}

	return nil
}

// DeprecateVersion marks a provider version as deprecated
func (r *ProviderRepository) DeprecateVersion(ctx context.Context, versionID string, message *string) error {
	query := `
		UPDATE provider_versions
		SET deprecated = true, deprecated_at = NOW(), deprecation_message = $2
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, versionID, message)
	if err != nil {
		return fmt.Errorf("failed to deprecate provider version: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("provider version not found")
	}

	return nil
}

// UndeprecateVersion removes the deprecated status from a provider version
func (r *ProviderRepository) UndeprecateVersion(ctx context.Context, versionID string) error {
	query := `
		UPDATE provider_versions
		SET deprecated = false, deprecated_at = NULL, deprecation_message = NULL
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, versionID)
	if err != nil {
		return fmt.Errorf("failed to undeprecate provider version: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("provider version not found")
	}

	return nil
}

// CreatePlatform inserts a new platform binary record
func (r *ProviderRepository) CreatePlatform(ctx context.Context, platform *models.ProviderPlatform) error {
	query := `
		INSERT INTO provider_platforms (provider_version_id, os, arch, filename, storage_path, storage_backend, size_bytes, shasum)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		platform.ProviderVersionID,
		platform.OS,
		platform.Arch,
		platform.Filename,
		platform.StoragePath,
		platform.StorageBackend,
		platform.SizeBytes,
		platform.Shasum,
	).Scan(&platform.ID)

	if err != nil {
		return fmt.Errorf("failed to create provider platform: %w", err)
	}

	return nil
}

// GetPlatform retrieves a specific platform binary by version ID, OS, and arch
func (r *ProviderRepository) GetPlatform(ctx context.Context, versionID, os, arch string) (*models.ProviderPlatform, error) {
	query := `
		SELECT id, provider_version_id, os, arch, filename, storage_path, storage_backend, size_bytes, shasum, download_count
		FROM provider_platforms
		WHERE provider_version_id = $1 AND os = $2 AND arch = $3
	`

	platform := &models.ProviderPlatform{}
	err := r.db.QueryRowContext(ctx, query, versionID, os, arch).Scan(
		&platform.ID,
		&platform.ProviderVersionID,
		&platform.OS,
		&platform.Arch,
		&platform.Filename,
		&platform.StoragePath,
		&platform.StorageBackend,
		&platform.SizeBytes,
		&platform.Shasum,
		&platform.DownloadCount,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get provider platform: %w", err)
	}

	return platform, nil
}

// ListPlatforms retrieves all platform binaries for a provider version
func (r *ProviderRepository) ListPlatforms(ctx context.Context, versionID string) ([]*models.ProviderPlatform, error) {
	query := `
		SELECT id, provider_version_id, os, arch, filename, storage_path, storage_backend, size_bytes, shasum, download_count
		FROM provider_platforms
		WHERE provider_version_id = $1
		ORDER BY os, arch
	`

	rows, err := r.db.QueryContext(ctx, query, versionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list provider platforms: %w", err)
	}
	defer rows.Close()

	var platforms []*models.ProviderPlatform
	for rows.Next() {
		p := &models.ProviderPlatform{}
		err := rows.Scan(
			&p.ID,
			&p.ProviderVersionID,
			&p.OS,
			&p.Arch,
			&p.Filename,
			&p.StoragePath,
			&p.StorageBackend,
			&p.SizeBytes,
			&p.Shasum,
			&p.DownloadCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan provider platform: %w", err)
		}
		platforms = append(platforms, p)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating provider platforms: %w", err)
	}

	return platforms, nil
}

// IncrementDownloadCount increments the download counter for a platform
func (r *ProviderRepository) IncrementDownloadCount(ctx context.Context, platformID string) error {
	query := `
		UPDATE provider_platforms
		SET download_count = download_count + 1
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, platformID)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	return nil
}

// GetTotalDownloadCount returns the total download count for a provider (sum of all platforms across all versions)
func (r *ProviderRepository) GetTotalDownloadCount(ctx context.Context, providerID string) (int64, error) {
	query := `
		SELECT COALESCE(SUM(pp.download_count), 0)
		FROM provider_platforms pp
		INNER JOIN provider_versions pv ON pp.provider_version_id = pv.id
		WHERE pv.provider_id = $1
	`

	var totalDownloads int64
	err := r.db.QueryRowContext(ctx, query, providerID).Scan(&totalDownloads)
	if err != nil {
		return 0, fmt.Errorf("failed to get total download count: %w", err)
	}

	return totalDownloads, nil
}

// DeletePlatform deletes a specific platform binary
func (r *ProviderRepository) DeletePlatform(ctx context.Context, platformID string) error {
	query := `DELETE FROM provider_platforms WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, platformID)
	if err != nil {
		return fmt.Errorf("failed to delete provider platform: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("provider platform not found")
	}

	return nil
}

// SearchProviders searches for providers matching the query
func (r *ProviderRepository) SearchProviders(ctx context.Context, orgID, query, namespace string, limit, offset int) ([]*models.Provider, int, error) {
	// Build WHERE clause
	var whereClause string
	var args []interface{}
	argCount := 0

	// Only filter by organization if orgID is provided (multi-tenant mode)
	if orgID != "" {
		argCount++
		whereClause = fmt.Sprintf("WHERE p.organization_id = $%d", argCount)
		args = append(args, orgID)
	} else {
		whereClause = "WHERE 1=1" // No org filter in single-tenant mode
	}

	if query != "" {
		argCount++
		whereClause += fmt.Sprintf(" AND (p.namespace ILIKE $%d OR p.type ILIKE $%d OR p.description ILIKE $%d)", argCount, argCount, argCount)
		args = append(args, "%"+query+"%")
	}

	if namespace != "" {
		argCount++
		whereClause += fmt.Sprintf(" AND p.namespace = $%d", argCount)
		args = append(args, namespace)
	}

	// Count total results
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM providers p %s", whereClause)
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count providers: %w", err)
	}

	// Query with pagination and JOIN for created_by_name
	searchQuery := fmt.Sprintf(`
		SELECT p.id, p.organization_id, p.namespace, p.type, p.description, p.source,
		       p.created_by, u.name as created_by_name, p.created_at, p.updated_at
		FROM providers p
		LEFT JOIN users u ON p.created_by = u.id
		%s
		ORDER BY p.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount+1, argCount+2)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, searchQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search providers: %w", err)
	}
	defer rows.Close()

	var providers []*models.Provider
	for rows.Next() {
		p := &models.Provider{}
		var scannedOrgID sql.NullString
		err := rows.Scan(
			&p.ID,
			&scannedOrgID,
			&p.Namespace,
			&p.Type,
			&p.Description,
			&p.Source,
			&p.CreatedBy,
			&p.CreatedByName,
			&p.CreatedAt,
			&p.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan provider: %w", err)
		}
		if scannedOrgID.Valid {
			p.OrganizationID = scannedOrgID.String
		}
		providers = append(providers, p)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating providers: %w", err)
	}

	return providers, total, nil
}

// SearchProvidersWithStats returns providers matching the search criteria along with
// their latest version and total download count in a single query, eliminating the
// N+1 query pattern from SearchProviders + per-provider ListVersions/GetTotalDownloadCount.
func (r *ProviderRepository) SearchProvidersWithStats(ctx context.Context, orgID, searchQuery, namespace string, limit, offset int) ([]*models.ProviderSearchResult, int, error) {
	var whereClauses []string
	var args []interface{}
	argCount := 0

	if orgID != "" {
		argCount++
		whereClauses = append(whereClauses, fmt.Sprintf("p.organization_id = $%d", argCount))
		args = append(args, orgID)
	}
	if searchQuery != "" {
		argCount++
		whereClauses = append(whereClauses, fmt.Sprintf("(p.namespace ILIKE $%d OR p.type ILIKE $%d OR p.description ILIKE $%d)", argCount, argCount, argCount))
		args = append(args, "%"+searchQuery+"%")
	}
	if namespace != "" {
		argCount++
		whereClauses = append(whereClauses, fmt.Sprintf("p.namespace = $%d", argCount))
		args = append(args, namespace)
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Count total results
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM providers p %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count providers: %w", err)
	}

	// Single query: providers + latest version + total platform downloads via lateral join
	searchSQL := fmt.Sprintf(`
		SELECT p.id, p.organization_id, p.namespace, p.type, p.description, p.source,
		       p.created_by, u.name AS created_by_name, p.created_at, p.updated_at,
		       agg.latest_version, COALESCE(agg.total_downloads, 0) AS total_downloads
		FROM providers p
		LEFT JOIN users u ON p.created_by = u.id
		LEFT JOIN LATERAL (
			SELECT
				(SELECT pv2.version FROM provider_versions pv2 WHERE pv2.provider_id = p.id ORDER BY pv2.created_at DESC LIMIT 1) AS latest_version,
				(SELECT COALESCE(SUM(pp.download_count), 0) FROM provider_platforms pp
				 JOIN provider_versions pv3 ON pp.provider_version_id = pv3.id
				 WHERE pv3.provider_id = p.id) AS total_downloads
		) agg ON true
		%s
		ORDER BY p.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount+1, argCount+2)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, searchSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search providers: %w", err)
	}
	defer rows.Close()

	var results []*models.ProviderSearchResult
	for rows.Next() {
		res := &models.ProviderSearchResult{}
		var scannedOrgID sql.NullString
		err := rows.Scan(
			&res.ID, &scannedOrgID, &res.Namespace, &res.Type,
			&res.Description, &res.Source, &res.CreatedBy, &res.CreatedByName,
			&res.CreatedAt, &res.UpdatedAt,
			&res.LatestVersion, &res.TotalDownloads,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan provider search result: %w", err)
		}
		if scannedOrgID.Valid {
			res.OrganizationID = scannedOrgID.String
		}
		results = append(results, res)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating provider search results: %w", err)
	}

	return results, total, nil
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
	// Remove leading 'v' if present
	version = strings.TrimPrefix(version, "v")

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
