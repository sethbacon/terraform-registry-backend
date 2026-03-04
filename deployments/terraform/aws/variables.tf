variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
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

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "domain" {
  description = "Custom domain name (e.g., registry.example.com). Leave empty to use ALB DNS."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS. Leave empty for HTTP only."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Container image tag"
  type        = string
  default     = "latest"
}

variable "backend_desired_count" {
  description = "Number of backend ECS tasks"
  type        = number
  default     = 2
}

variable "frontend_desired_count" {
  description = "Number of frontend ECS tasks"
  type        = number
  default     = 2
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "db_instance_count" {
  description = "Number of Aurora DB instances"
  type        = number
  default     = 1
}

variable "database_password" {
  description = "Database master password"
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
  description = "Storage backend: s3 (default), azure, gcs, local"
  type        = string
  default     = "s3"

  validation {
    condition     = contains(["s3", "azure", "gcs", "local"], var.storage_backend)
    error_message = "storage_backend must be one of: s3, azure, gcs, local"
  }
}

# S3 options (native default for AWS)
variable "storage_s3_auth_method" {
  description = "S3 auth method: default (IAM role), static, oidc, assume_role"
  type        = string
  default     = "default"
}

variable "storage_s3_endpoint" {
  description = "Custom S3 endpoint URL (for MinIO, DigitalOcean Spaces, etc.). Leave empty for AWS S3."
  type        = string
  default     = ""
}

variable "storage_s3_access_key_id" {
  description = "S3 access key ID (required when storage_s3_auth_method = static)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "storage_s3_secret_access_key" {
  description = "S3 secret access key (required when storage_s3_auth_method = static)"
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
  description = "Azure storage account name (required when storage_backend = azure)"
  type        = string
  default     = ""
}

variable "storage_azure_account_key" {
  description = "Azure storage account key (required when storage_backend = azure)"
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

# GCS options
variable "storage_gcs_bucket" {
  description = "GCS bucket name (required when storage_backend = gcs)"
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
