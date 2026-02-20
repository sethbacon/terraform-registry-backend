variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
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
  description = "Custom domain name. Leave empty to use Cloud Run default URL."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Container image tag"
  type        = string
  default     = "latest"
}

variable "db_tier" {
  description = "Cloud SQL instance tier"
  type        = string
  default     = "db-f1-micro"
}

variable "backend_min_instances" {
  description = "Backend minimum instances"
  type        = number
  default     = 1
}

variable "backend_max_instances" {
  description = "Backend maximum instances"
  type        = number
  default     = 10
}

variable "frontend_min_instances" {
  description = "Frontend minimum instances"
  type        = number
  default     = 1
}

variable "frontend_max_instances" {
  description = "Frontend maximum instances"
  type        = number
  default     = 5
}

variable "database_password" {
  description = "PostgreSQL password"
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
  description = "Storage backend: gcs (default), s3, azure, local"
  type        = string
  default     = "gcs"

  validation {
    condition     = contains(["s3", "azure", "gcs", "local"], var.storage_backend)
    error_message = "storage_backend must be one of: s3, azure, gcs, local"
  }
}

# GCS options (native default)
variable "storage_gcs_auth_method" {
  description = "GCS auth method: default (Workload Identity), service_account, workload_identity"
  type        = string
  default     = "default"
}

variable "storage_gcs_credentials_json" {
  description = "GCS service account JSON key (for service_account auth)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "storage_gcs_endpoint" {
  description = "Custom GCS endpoint (for emulators or compatible services)"
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

# Azure Blob Storage options
variable "storage_azure_account_name" {
  description = "Azure storage account name"
  type        = string
  default     = ""
}

variable "storage_azure_account_key" {
  description = "Azure storage account key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "storage_azure_container_name" {
  description = "Azure blob container name"
  type        = string
  default     = "registry"
}

variable "storage_azure_cdn_url" {
  description = "Azure CDN URL for the storage container"
  type        = string
  default     = ""
}

# Local storage options
variable "storage_local_base_path" {
  description = "Base path for local file storage"
  type        = string
  default     = "/app/storage"
}
