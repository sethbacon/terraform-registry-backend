-- Add replacement_source to module_versions for Terraform CLI >=1.10 deprecation protocol.
-- This field stores a module source address (e.g. "registry.example.com/acme/newmod/aws")
-- that Terraform CLI surfaces as a replacement suggestion when a deprecated version is used.
ALTER TABLE module_versions ADD COLUMN replacement_source TEXT;
