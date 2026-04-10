CREATE TABLE module_version_docs (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_version_id UUID        NOT NULL REFERENCES module_versions(id) ON DELETE CASCADE,
    inputs            JSONB,
    outputs           JSONB,
    providers         JSONB,
    requirements      JSONB,
    generated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (module_version_id)
);

CREATE INDEX idx_mvd_version ON module_version_docs(module_version_id);
