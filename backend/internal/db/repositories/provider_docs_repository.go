// provider_docs_repository.go implements ProviderDocsRepository, providing database
// queries for provider version documentation metadata (doc index entries synced from
// the upstream registry).
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ProviderDocsRepository handles database operations for provider documentation metadata.
type ProviderDocsRepository struct {
	db *sql.DB
}

// NewProviderDocsRepository creates a new provider docs repository.
func NewProviderDocsRepository(db *sql.DB) *ProviderDocsRepository {
	return &ProviderDocsRepository{db: db}
}

// BulkCreateProviderVersionDocs inserts multiple doc index entries for a provider version.
// Existing entries with the same (provider_version_id, upstream_doc_id) are skipped.
func (r *ProviderDocsRepository) BulkCreateProviderVersionDocs(ctx context.Context, versionID string, docs []models.ProviderVersionDoc) error {
	if len(docs) == 0 {
		return nil
	}

	// Build a batched INSERT with ON CONFLICT DO NOTHING
	const batchSize = 500
	for i := 0; i < len(docs); i += batchSize {
		end := i + batchSize
		if end > len(docs) {
			end = len(docs)
		}
		batch := docs[i:end]

		var b strings.Builder
		b.WriteString(`INSERT INTO provider_version_docs (provider_version_id, upstream_doc_id, title, slug, category, subcategory, path, language) VALUES `)
		args := make([]interface{}, 0, len(batch)*8)
		for j, doc := range batch {
			if j > 0 {
				b.WriteString(", ")
			}
			base := j * 8
			fmt.Fprintf(&b, "($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8)
			args = append(args, versionID, doc.UpstreamDocID, doc.Title, doc.Slug, doc.Category, doc.Subcategory, doc.Path, doc.Language)
		}
		b.WriteString(" ON CONFLICT (provider_version_id, upstream_doc_id) DO NOTHING")

		if _, err := r.db.ExecContext(ctx, b.String(), args...); err != nil {
			return fmt.Errorf("failed to bulk insert provider version docs: %w", err)
		}
	}

	return nil
}

// ListProviderVersionDocs returns doc index entries for a provider version,
// optionally filtered by category and/or language.
func (r *ProviderDocsRepository) ListProviderVersionDocs(ctx context.Context, versionID string, category, language *string) ([]models.ProviderVersionDoc, error) {
	var b strings.Builder
	b.WriteString(`SELECT id, provider_version_id, upstream_doc_id, title, slug, category, subcategory, path, language
		FROM provider_version_docs WHERE provider_version_id = $1`)
	args := []interface{}{versionID}
	argIdx := 2

	if category != nil && *category != "" {
		fmt.Fprintf(&b, " AND category = $%d", argIdx)
		args = append(args, *category)
		argIdx++
	}
	if language != nil && *language != "" {
		fmt.Fprintf(&b, " AND language = $%d", argIdx)
		args = append(args, *language)
		argIdx++
	}
	_ = argIdx

	b.WriteString(" ORDER BY category, title")

	rows, err := r.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list provider version docs: %w", err)
	}
	defer rows.Close()

	var docs []models.ProviderVersionDoc
	for rows.Next() {
		var doc models.ProviderVersionDoc
		if err := rows.Scan(
			&doc.ID, &doc.ProviderVersionID, &doc.UpstreamDocID,
			&doc.Title, &doc.Slug, &doc.Category, &doc.Subcategory,
			&doc.Path, &doc.Language,
		); err != nil {
			return nil, fmt.Errorf("failed to scan provider version doc: %w", err)
		}
		docs = append(docs, doc)
	}
	return docs, rows.Err()
}

// ListProviderVersionDocsPaginated retrieves docs with limit/offset pagination and total count.
func (r *ProviderDocsRepository) ListProviderVersionDocsPaginated(ctx context.Context, versionID string, category, language *string, limit, offset int) ([]models.ProviderVersionDoc, int, error) {
	// Build count query
	var cb strings.Builder
	cb.WriteString(`SELECT COUNT(*) FROM provider_version_docs WHERE provider_version_id = $1`)
	args := []interface{}{versionID}
	argIdx := 2

	if category != nil && *category != "" {
		fmt.Fprintf(&cb, " AND category = $%d", argIdx)
		args = append(args, *category)
		argIdx++
	}
	if language != nil && *language != "" {
		fmt.Fprintf(&cb, " AND language = $%d", argIdx)
		args = append(args, *language)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, cb.String(), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count provider version docs: %w", err)
	}

	// Build data query
	var b strings.Builder
	b.WriteString(`SELECT id, provider_version_id, upstream_doc_id, title, slug, category, subcategory, path, language
		FROM provider_version_docs WHERE provider_version_id = $1`)
	dataArgs := []interface{}{versionID}
	dataArgIdx := 2

	if category != nil && *category != "" {
		fmt.Fprintf(&b, " AND category = $%d", dataArgIdx)
		dataArgs = append(dataArgs, *category)
		dataArgIdx++
	}
	if language != nil && *language != "" {
		fmt.Fprintf(&b, " AND language = $%d", dataArgIdx)
		dataArgs = append(dataArgs, *language)
		dataArgIdx++
	}

	fmt.Fprintf(&b, " ORDER BY category, title LIMIT $%d OFFSET $%d", dataArgIdx, dataArgIdx+1)
	dataArgs = append(dataArgs, limit, offset)

	rows, err := r.db.QueryContext(ctx, b.String(), dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list provider version docs: %w", err)
	}
	defer rows.Close()

	var docs []models.ProviderVersionDoc
	for rows.Next() {
		var doc models.ProviderVersionDoc
		if err := rows.Scan(
			&doc.ID, &doc.ProviderVersionID, &doc.UpstreamDocID,
			&doc.Title, &doc.Slug, &doc.Category, &doc.Subcategory,
			&doc.Path, &doc.Language,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan provider version doc: %w", err)
		}
		docs = append(docs, doc)
	}
	return docs, total, rows.Err()
}

// GetProviderVersionDocBySlug retrieves a single doc entry by category and slug.
func (r *ProviderDocsRepository) GetProviderVersionDocBySlug(ctx context.Context, versionID, category, slug string) (*models.ProviderVersionDoc, error) {
	query := `SELECT id, provider_version_id, upstream_doc_id, title, slug, category, subcategory, path, language
		FROM provider_version_docs
		WHERE provider_version_id = $1 AND category = $2 AND slug = $3
		LIMIT 1`

	doc := &models.ProviderVersionDoc{}
	err := r.db.QueryRowContext(ctx, query, versionID, category, slug).Scan(
		&doc.ID, &doc.ProviderVersionID, &doc.UpstreamDocID,
		&doc.Title, &doc.Slug, &doc.Category, &doc.Subcategory,
		&doc.Path, &doc.Language,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get provider version doc by slug: %w", err)
	}
	return doc, nil
}

// DeleteProviderVersionDocs removes all doc entries for a provider version.
func (r *ProviderDocsRepository) DeleteProviderVersionDocs(ctx context.Context, versionID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM provider_version_docs WHERE provider_version_id = $1`, versionID)
	if err != nil {
		return fmt.Errorf("failed to delete provider version docs: %w", err)
	}
	return nil
}

// CountProviderVersionDocs returns the number of doc index entries stored for a
// provider version. A count of zero means the doc index was never populated (or
// was cleared), allowing callers to decide whether a backfill is needed.
func (r *ProviderDocsRepository) CountProviderVersionDocs(ctx context.Context, versionID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM provider_version_docs WHERE provider_version_id = $1`,
		versionID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count provider version docs: %w", err)
	}
	return count, nil
}
