# Example: Consuming a module from a private Terraform Registry
#
# This configuration demonstrates how to use a module published to
# your private Terraform Registry. Update the source URL to match
# your registry hostname and the module coordinates you published.
#
# Prerequisites:
#   1. A running Terraform Registry (see docs/getting-started.md)
#   2. A published module (e.g., myorg/my-module/generic version 1.0.0)
#   3. An API key configured in ~/.terraformrc (see ../terraformrc-example)
#
# Usage:
#   terraform init
#   terraform plan
#   terraform apply

terraform {
  required_version = ">= 1.0"
}

# Consume a module from the private registry.
# Replace "localhost:8080" with your registry's hostname.
# Replace "myorg/my-module/generic" with your module's namespace/name/system.
module "example" {
  source  = "localhost:8080/myorg/my-module/generic"
  version = "1.0.0"

  # Pass variables defined by the module
  name = "world"
}

output "module_output" {
  description = "Output from the private registry module"
  value       = module.example.greeting
}
