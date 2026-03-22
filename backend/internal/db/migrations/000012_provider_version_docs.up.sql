CREATE TABLE provider_version_docs (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_version_id UUID         NOT NULL REFERENCES provider_versions(id) ON DELETE CASCADE,
    upstream_doc_id     VARCHAR(50)  NOT NULL,
    title               VARCHAR(255) NOT NULL,
    slug                VARCHAR(255) NOT NULL,
    category            VARCHAR(50)  NOT NULL,
    subcategory         VARCHAR(255),
    path                VARCHAR(512),
    language            VARCHAR(20)  NOT NULL DEFAULT 'hcl',
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (provider_version_id, upstream_doc_id)
);

CREATE INDEX idx_pvd_version  ON provider_version_docs(provider_version_id);
CREATE INDEX idx_pvd_category ON provider_version_docs(provider_version_id, category);
