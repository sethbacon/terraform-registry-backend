// module_docs_repository.go implements database operations for module_version_docs.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/terraform-registry/terraform-registry/internal/analyzer"
)

// ModuleDocsRepository handles database operations for module_version_docs.
type ModuleDocsRepository struct {
	db *sql.DB
}

// NewModuleDocsRepository constructs a ModuleDocsRepository.
func NewModuleDocsRepository(db *sql.DB) *ModuleDocsRepository {
	return &ModuleDocsRepository{db: db}
}

// UpsertModuleDocs stores or replaces the terraform-docs metadata for a module version.
// The operation is idempotent — it uses ON CONFLICT DO UPDATE.
func (r *ModuleDocsRepository) UpsertModuleDocs(
	ctx context.Context, moduleVersionID string, doc *analyzer.ModuleDoc,
) error {
	if doc == nil {
		return nil
	}

	inputsJSON, err := json.Marshal(doc.Inputs)
	if err != nil {
		return fmt.Errorf("marshal inputs: %w", err)
	}
	outputsJSON, err := json.Marshal(doc.Outputs)
	if err != nil {
		return fmt.Errorf("marshal outputs: %w", err)
	}
	providersJSON, err := json.Marshal(doc.Providers)
	if err != nil {
		return fmt.Errorf("marshal providers: %w", err)
	}

	var reqJSON interface{}
	if doc.Requirements != nil {
		b, err := json.Marshal(doc.Requirements)
		if err != nil {
			return fmt.Errorf("marshal requirements: %w", err)
		}
		reqJSON = b
	}

	const q = `
		INSERT INTO module_version_docs (module_version_id, inputs, outputs, providers, requirements)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (module_version_id) DO UPDATE SET
			inputs       = EXCLUDED.inputs,
			outputs      = EXCLUDED.outputs,
			providers    = EXCLUDED.providers,
			requirements = EXCLUDED.requirements,
			generated_at = NOW()
	`
	_, err = r.db.ExecContext(ctx, q, moduleVersionID, inputsJSON, outputsJSON, providersJSON, reqJSON)
	if err != nil {
		return fmt.Errorf("upsert module docs: %w", err)
	}
	return nil
}

// GetModuleDocs returns the stored docs for a module version, or nil if none exist.
func (r *ModuleDocsRepository) GetModuleDocs(
	ctx context.Context, moduleVersionID string,
) (*analyzer.ModuleDoc, error) {
	const q = `
		SELECT inputs, outputs, providers, requirements
		FROM module_version_docs
		WHERE module_version_id = $1
	`
	var inputsJSON, outputsJSON, providersJSON []byte
	var reqJSON []byte

	err := r.db.QueryRowContext(ctx, q, moduleVersionID).Scan(
		&inputsJSON, &outputsJSON, &providersJSON, &reqJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get module docs: %w", err)
	}

	doc := &analyzer.ModuleDoc{}
	if len(inputsJSON) > 0 {
		if err := json.Unmarshal(inputsJSON, &doc.Inputs); err != nil {
			return nil, fmt.Errorf("unmarshal inputs: %w", err)
		}
	}
	if len(outputsJSON) > 0 {
		if err := json.Unmarshal(outputsJSON, &doc.Outputs); err != nil {
			return nil, fmt.Errorf("unmarshal outputs: %w", err)
		}
	}
	if len(providersJSON) > 0 {
		if err := json.Unmarshal(providersJSON, &doc.Providers); err != nil {
			return nil, fmt.Errorf("unmarshal providers: %w", err)
		}
	}
	if len(reqJSON) > 0 {
		req := &analyzer.Requirements{}
		if err := json.Unmarshal(reqJSON, req); err != nil {
			return nil, fmt.Errorf("unmarshal requirements: %w", err)
		}
		doc.Requirements = req
	}
	return doc, nil
}

// HasDocs returns true if docs exist for the given module version ID.
func (r *ModuleDocsRepository) HasDocs(ctx context.Context, moduleVersionID string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM module_version_docs WHERE module_version_id = $1)`
	var exists bool
	if err := r.db.QueryRowContext(ctx, q, moduleVersionID).Scan(&exists); err != nil {
		return false, fmt.Errorf("has docs: %w", err)
	}
	return exists, nil
}
