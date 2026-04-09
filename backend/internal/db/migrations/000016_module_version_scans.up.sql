CREATE TABLE module_version_scans (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_version_id UUID        NOT NULL REFERENCES module_versions(id) ON DELETE CASCADE,
    scanner           VARCHAR(50) NOT NULL,
    scanner_version   VARCHAR(50),
    expected_version  VARCHAR(50),
    status            VARCHAR(20) NOT NULL DEFAULT 'pending',
    scanned_at        TIMESTAMPTZ,
    critical_count    INT         NOT NULL DEFAULT 0,
    high_count        INT         NOT NULL DEFAULT 0,
    medium_count      INT         NOT NULL DEFAULT 0,
    low_count         INT         NOT NULL DEFAULT 0,
    raw_results       JSONB,
    error_message     TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (module_version_id)
);

CREATE INDEX idx_mvs_pending ON module_version_scans(created_at)
    WHERE status = 'pending';
CREATE INDEX idx_mvs_version ON module_version_scans(module_version_id);
