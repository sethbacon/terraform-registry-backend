-- Add module-level deprecation support
ALTER TABLE modules ADD COLUMN deprecated BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE modules ADD COLUMN deprecated_at TIMESTAMP;
ALTER TABLE modules ADD COLUMN deprecation_message TEXT;
ALTER TABLE modules ADD COLUMN successor_module_id UUID REFERENCES modules(id) ON DELETE SET NULL;

CREATE INDEX idx_modules_deprecated ON modules(deprecated);
