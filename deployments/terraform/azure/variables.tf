variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "terraform-registry-rg"
}

variable "name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "terraform-registry"
}

variable "environment" {
  description = "Environment name (e.g., production, staging)"
  type        = string
  default     = "production"
}

variable "domain" {
  description = "Custom domain name. Leave empty to use Container Apps default domain."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Container image tag"
  type        = string
  default     = "latest"
}

variable "db_sku" {
  description = "PostgreSQL Flexible Server SKU name"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "backend_min_replicas" {
  description = "Backend minimum replicas"
  type        = number
  default     = 1
}

variable "backend_max_replicas" {
  description = "Backend maximum replicas"
  type        = number
  default     = 10
}

variable "frontend_min_replicas" {
  description = "Frontend minimum replicas"
  type        = number
  default     = 1
}

variable "frontend_max_replicas" {
  description = "Frontend maximum replicas"
  type        = number
  default     = 5
}

variable "database_password" {
  description = "PostgreSQL admin password"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "JWT signing secret (min 32 chars)"
  type        = string
  sensitive   = true
}

variable "encryption_key" {
  description = "AES-256 encryption key (32 bytes)"
  type        = string
  sensitive   = true
}

# ---------------------------------------------------------------------------
# Storage Configuration
# ---------------------------------------------------------------------------
variable "storage_backend" {
  description = "Storage backend: azure (default), s3, gcs, local"
  type        = string
  default     = "azure"

  validation {
    condition     = contains(["s3", "azure", "gcs", "local"], var.storage_backend)
    error_message = "storage_backend must be one of: s3, azure, gcs, local"
  }
}

# Azure Blob Storage options (native default)
variable "storage_azure_cdn_url" {
  description = "Azure CDN URL for the storage container"
  type        = string
  default     = ""
}

# S3/S3-compatible options
variable "storage_s3_endpoint" {
  description = "Custom S3 endpoint URL (for MinIO, DigitalOcean Spaces, etc.)"
  type        = string
  default     = ""
}

variable "storage_s3_region" {
  description = "AWS region for S3 bucket"
  type        = string
  default     = ""
}

variable "storage_s3_bucket" {
  description = "S3 bucket name"
  type        = string
  default     = ""
}

variable "storage_s3_auth_method" {
  description = "S3 auth method: default, static, oidc, assume_role"
  type        = string
  default     = "static"
}

variable "storage_s3_access_key_id" {
  description = "S3 access key ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "storage_s3_secret_access_key" {
  description = "S3 secret access key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "storage_s3_role_arn" {
  description = "IAM role ARN for assume_role or oidc auth"
  type        = string
  default     = ""
}

variable "storage_s3_role_session_name" {
  description = "Session name when assuming role"
  type        = string
  default     = "terraform-registry"
}

variable "storage_s3_external_id" {
  description = "External ID for cross-account role assumption"
  type        = string
  default     = ""
}

variable "storage_s3_web_identity_token_file" {
  description = "Path to OIDC token file (for oidc auth method)"
  type        = string
  default     = ""
}

# GCS options
variable "storage_gcs_bucket" {
  description = "GCS bucket name"
  type        = string
  default     = ""
}

variable "storage_gcs_project_id" {
  description = "GCS project ID"
  type        = string
  default     = ""
}

variable "storage_gcs_auth_method" {
  description = "GCS auth method: default, service_account, workload_identity"
  type        = string
  default     = "default"
}

variable "storage_gcs_credentials_json" {
  description = "GCS service account JSON key (for service_account auth)"
  type        = string
  default     = ""
  sensitive   = true
}

# Local storage options
variable "storage_local_base_path" {
  description = "Base path for local file storage"
  type        = string
  default     = "/app/storage"
}
