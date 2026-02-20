// Package models - storage_config.go defines the StorageConfig and SystemSettings models
// for the active storage backend configuration and its credentials across supported backends.
package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// SystemSettings holds global system settings (singleton)
type SystemSettings struct {
	ID                   int            `db:"id" json:"id"`
	StorageConfigured    bool           `db:"storage_configured" json:"storage_configured"`
	StorageConfiguredAt  sql.NullTime   `db:"storage_configured_at" json:"storage_configured_at,omitempty"`
	StorageConfiguredBy  uuid.NullUUID  `db:"storage_configured_by" json:"storage_configured_by,omitempty"`
	CreatedAt            time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt            time.Time      `db:"updated_at" json:"updated_at"`
}

// StorageConfig holds storage backend configuration
type StorageConfig struct {
	ID          uuid.UUID `db:"id" json:"id"`
	BackendType string    `db:"backend_type" json:"backend_type"`
	IsActive    bool      `db:"is_active" json:"is_active"`

	// Local storage settings
	LocalBasePath       sql.NullString `db:"local_base_path" json:"local_base_path,omitempty"`
	LocalServeDirectly  sql.NullBool   `db:"local_serve_directly" json:"local_serve_directly,omitempty"`

	// Azure Blob Storage settings
	AzureAccountName        sql.NullString `db:"azure_account_name" json:"azure_account_name,omitempty"`
	AzureAccountKeyEncrypted sql.NullString `db:"azure_account_key_encrypted" json:"-"` // Never expose in JSON
	AzureContainerName      sql.NullString `db:"azure_container_name" json:"azure_container_name,omitempty"`
	AzureCDNURL             sql.NullString `db:"azure_cdn_url" json:"azure_cdn_url,omitempty"`

	// S3 settings
	S3Endpoint                  sql.NullString `db:"s3_endpoint" json:"s3_endpoint,omitempty"`
	S3Region                    sql.NullString `db:"s3_region" json:"s3_region,omitempty"`
	S3Bucket                    sql.NullString `db:"s3_bucket" json:"s3_bucket,omitempty"`
	S3AuthMethod                sql.NullString `db:"s3_auth_method" json:"s3_auth_method,omitempty"`
	S3AccessKeyIDEncrypted      sql.NullString `db:"s3_access_key_id_encrypted" json:"-"` // Never expose
	S3SecretAccessKeyEncrypted  sql.NullString `db:"s3_secret_access_key_encrypted" json:"-"` // Never expose
	S3RoleARN                   sql.NullString `db:"s3_role_arn" json:"s3_role_arn,omitempty"`
	S3RoleSessionName           sql.NullString `db:"s3_role_session_name" json:"s3_role_session_name,omitempty"`
	S3ExternalID                sql.NullString `db:"s3_external_id" json:"s3_external_id,omitempty"`
	S3WebIdentityTokenFile      sql.NullString `db:"s3_web_identity_token_file" json:"s3_web_identity_token_file,omitempty"`

	// GCS settings
	GCSBucket                  sql.NullString `db:"gcs_bucket" json:"gcs_bucket,omitempty"`
	GCSProjectID               sql.NullString `db:"gcs_project_id" json:"gcs_project_id,omitempty"`
	GCSAuthMethod              sql.NullString `db:"gcs_auth_method" json:"gcs_auth_method,omitempty"`
	GCSCredentialsFile         sql.NullString `db:"gcs_credentials_file" json:"gcs_credentials_file,omitempty"`
	GCSCredentialsJSONEncrypted sql.NullString `db:"gcs_credentials_json_encrypted" json:"-"` // Never expose
	GCSEndpoint                sql.NullString `db:"gcs_endpoint" json:"gcs_endpoint,omitempty"`

	// Metadata
	CreatedAt time.Time     `db:"created_at" json:"created_at"`
	UpdatedAt time.Time     `db:"updated_at" json:"updated_at"`
	CreatedBy uuid.NullUUID `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy uuid.NullUUID `db:"updated_by" json:"updated_by,omitempty"`
}

// StorageConfigInput is used for creating/updating storage configuration
type StorageConfigInput struct {
	BackendType string `json:"backend_type" binding:"required,oneof=local azure s3 gcs"`

	// Local storage settings
	LocalBasePath      string `json:"local_base_path,omitempty"`
	LocalServeDirectly *bool  `json:"local_serve_directly,omitempty"`

	// Azure Blob Storage settings
	AzureAccountName   string `json:"azure_account_name,omitempty"`
	AzureAccountKey    string `json:"azure_account_key,omitempty"` // Plain text input, encrypted before storage
	AzureContainerName string `json:"azure_container_name,omitempty"`
	AzureCDNURL        string `json:"azure_cdn_url,omitempty"`

	// S3 settings
	S3Endpoint             string `json:"s3_endpoint,omitempty"`
	S3Region               string `json:"s3_region,omitempty"`
	S3Bucket               string `json:"s3_bucket,omitempty"`
	S3AuthMethod           string `json:"s3_auth_method,omitempty"`
	S3AccessKeyID          string `json:"s3_access_key_id,omitempty"` // Plain text input
	S3SecretAccessKey      string `json:"s3_secret_access_key,omitempty"` // Plain text input
	S3RoleARN              string `json:"s3_role_arn,omitempty"`
	S3RoleSessionName      string `json:"s3_role_session_name,omitempty"`
	S3ExternalID           string `json:"s3_external_id,omitempty"`
	S3WebIdentityTokenFile string `json:"s3_web_identity_token_file,omitempty"`

	// GCS settings
	GCSBucket          string `json:"gcs_bucket,omitempty"`
	GCSProjectID       string `json:"gcs_project_id,omitempty"`
	GCSAuthMethod      string `json:"gcs_auth_method,omitempty"`
	GCSCredentialsFile string `json:"gcs_credentials_file,omitempty"`
	GCSCredentialsJSON string `json:"gcs_credentials_json,omitempty"` // Plain text input
	GCSEndpoint        string `json:"gcs_endpoint,omitempty"`
}

// StorageConfigResponse is the API response for storage configuration
// It masks sensitive fields but indicates if they are set
type StorageConfigResponse struct {
	ID          uuid.UUID `json:"id"`
	BackendType string    `json:"backend_type"`
	IsActive    bool      `json:"is_active"`

	// Local storage settings
	LocalBasePath      string `json:"local_base_path,omitempty"`
	LocalServeDirectly *bool  `json:"local_serve_directly,omitempty"`

	// Azure Blob Storage settings
	AzureAccountName   string `json:"azure_account_name,omitempty"`
	AzureAccountKeySet bool   `json:"azure_account_key_set"` // Indicates if key is configured
	AzureContainerName string `json:"azure_container_name,omitempty"`
	AzureCDNURL        string `json:"azure_cdn_url,omitempty"`

	// S3 settings
	S3Endpoint             string `json:"s3_endpoint,omitempty"`
	S3Region               string `json:"s3_region,omitempty"`
	S3Bucket               string `json:"s3_bucket,omitempty"`
	S3AuthMethod           string `json:"s3_auth_method,omitempty"`
	S3AccessKeyIDSet       bool   `json:"s3_access_key_id_set"`
	S3SecretAccessKeySet   bool   `json:"s3_secret_access_key_set"`
	S3RoleARN              string `json:"s3_role_arn,omitempty"`
	S3RoleSessionName      string `json:"s3_role_session_name,omitempty"`
	S3ExternalID           string `json:"s3_external_id,omitempty"`
	S3WebIdentityTokenFile string `json:"s3_web_identity_token_file,omitempty"`

	// GCS settings
	GCSBucket             string `json:"gcs_bucket,omitempty"`
	GCSProjectID          string `json:"gcs_project_id,omitempty"`
	GCSAuthMethod         string `json:"gcs_auth_method,omitempty"`
	GCSCredentialsFile    string `json:"gcs_credentials_file,omitempty"`
	GCSCredentialsJSONSet bool   `json:"gcs_credentials_json_set"`
	GCSEndpoint           string `json:"gcs_endpoint,omitempty"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ToResponse converts StorageConfig to StorageConfigResponse (masking secrets)
func (s *StorageConfig) ToResponse() StorageConfigResponse {
	resp := StorageConfigResponse{
		ID:          s.ID,
		BackendType: s.BackendType,
		IsActive:    s.IsActive,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
	}

	// Local
	if s.LocalBasePath.Valid {
		resp.LocalBasePath = s.LocalBasePath.String
	}
	if s.LocalServeDirectly.Valid {
		val := s.LocalServeDirectly.Bool
		resp.LocalServeDirectly = &val
	}

	// Azure
	if s.AzureAccountName.Valid {
		resp.AzureAccountName = s.AzureAccountName.String
	}
	resp.AzureAccountKeySet = s.AzureAccountKeyEncrypted.Valid && s.AzureAccountKeyEncrypted.String != ""
	if s.AzureContainerName.Valid {
		resp.AzureContainerName = s.AzureContainerName.String
	}
	if s.AzureCDNURL.Valid {
		resp.AzureCDNURL = s.AzureCDNURL.String
	}

	// S3
	if s.S3Endpoint.Valid {
		resp.S3Endpoint = s.S3Endpoint.String
	}
	if s.S3Region.Valid {
		resp.S3Region = s.S3Region.String
	}
	if s.S3Bucket.Valid {
		resp.S3Bucket = s.S3Bucket.String
	}
	if s.S3AuthMethod.Valid {
		resp.S3AuthMethod = s.S3AuthMethod.String
	}
	resp.S3AccessKeyIDSet = s.S3AccessKeyIDEncrypted.Valid && s.S3AccessKeyIDEncrypted.String != ""
	resp.S3SecretAccessKeySet = s.S3SecretAccessKeyEncrypted.Valid && s.S3SecretAccessKeyEncrypted.String != ""
	if s.S3RoleARN.Valid {
		resp.S3RoleARN = s.S3RoleARN.String
	}
	if s.S3RoleSessionName.Valid {
		resp.S3RoleSessionName = s.S3RoleSessionName.String
	}
	if s.S3ExternalID.Valid {
		resp.S3ExternalID = s.S3ExternalID.String
	}
	if s.S3WebIdentityTokenFile.Valid {
		resp.S3WebIdentityTokenFile = s.S3WebIdentityTokenFile.String
	}

	// GCS
	if s.GCSBucket.Valid {
		resp.GCSBucket = s.GCSBucket.String
	}
	if s.GCSProjectID.Valid {
		resp.GCSProjectID = s.GCSProjectID.String
	}
	if s.GCSAuthMethod.Valid {
		resp.GCSAuthMethod = s.GCSAuthMethod.String
	}
	if s.GCSCredentialsFile.Valid {
		resp.GCSCredentialsFile = s.GCSCredentialsFile.String
	}
	resp.GCSCredentialsJSONSet = s.GCSCredentialsJSONEncrypted.Valid && s.GCSCredentialsJSONEncrypted.String != ""
	if s.GCSEndpoint.Valid {
		resp.GCSEndpoint = s.GCSEndpoint.String
	}

	return resp
}
