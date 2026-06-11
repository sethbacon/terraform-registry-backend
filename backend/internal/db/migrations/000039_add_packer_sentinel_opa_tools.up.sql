-- Expand the tool CHECK constraint to include packer, sentinel, and opa.
ALTER TABLE terraform_mirror_configs
    DROP CONSTRAINT IF EXISTS terraform_mirror_configs_tool_check;

ALTER TABLE terraform_mirror_configs
    ADD CONSTRAINT terraform_mirror_configs_tool_check CHECK (
        tool IN ('terraform', 'opentofu', 'packer', 'sentinel', 'opa', 'custom')
    );
