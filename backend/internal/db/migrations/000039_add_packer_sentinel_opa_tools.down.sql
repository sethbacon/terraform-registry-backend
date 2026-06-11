-- Revert to original tool CHECK constraint (will fail if rows with packer/sentinel/opa exist).
ALTER TABLE terraform_mirror_configs
    DROP CONSTRAINT IF EXISTS terraform_mirror_configs_tool_check;

ALTER TABLE terraform_mirror_configs
    ADD CONSTRAINT terraform_mirror_configs_tool_check CHECK (
        tool IN ('terraform', 'opentofu', 'custom')
    );
