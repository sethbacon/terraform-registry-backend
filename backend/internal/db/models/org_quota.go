// Package models — org_quota.go defines the per-organization quota model
// for storage, publish rate, and download rate limits.
package models

import "time"

// OrgQuota defines resource limits for an organization.
type OrgQuota struct {
	ID                int64     `json:"id"`
	OrganizationID    string    `json:"organization_id"`
	StorageBytesLimit int64     `json:"storage_bytes_limit"` // 0 = unlimited
	PublishesPerDay   int       `json:"publishes_per_day"`   // 0 = unlimited
	DownloadsPerDay   int       `json:"downloads_per_day"`   // 0 = unlimited
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// OrgQuotaUsage tracks daily resource usage for quota enforcement.
type OrgQuotaUsage struct {
	ID               int64     `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	Date             time.Time `json:"date"`
	StorageBytesUsed int64     `json:"storage_bytes_used"`
	PublishesToday   int       `json:"publishes_today"`
	DownloadsToday   int       `json:"downloads_today"`
}

// QuotaStatus represents the current quota utilization for an organization.
type QuotaStatus struct {
	OrganizationID    string  `json:"organization_id"`
	StorageBytesLimit int64   `json:"storage_bytes_limit"`
	StorageBytesUsed  int64   `json:"storage_bytes_used"`
	StorageRatio      float64 `json:"storage_utilization_ratio"`
	PublishesPerDay   int     `json:"publishes_per_day_limit"`
	PublishesToday    int     `json:"publishes_today"`
	PublishRatio      float64 `json:"publish_utilization_ratio"`
	DownloadsPerDay   int     `json:"downloads_per_day_limit"`
	DownloadsToday    int     `json:"downloads_today"`
	DownloadRatio     float64 `json:"download_utilization_ratio"`
}

// IsStorageExceeded returns true if the storage quota is exceeded.
func (q *QuotaStatus) IsStorageExceeded() bool {
	return q.StorageBytesLimit > 0 && q.StorageBytesUsed >= q.StorageBytesLimit
}

// IsPublishExceeded returns true if the daily publish quota is exceeded.
func (q *QuotaStatus) IsPublishExceeded() bool {
	return q.PublishesPerDay > 0 && q.PublishesToday >= q.PublishesPerDay
}

// IsDownloadExceeded returns true if the daily download quota is exceeded.
func (q *QuotaStatus) IsDownloadExceeded() bool {
	return q.DownloadsPerDay > 0 && q.DownloadsToday >= q.DownloadsPerDay
}

// IsNearLimit returns true if any quota is at or above 80% utilization.
func (q *QuotaStatus) IsNearLimit() bool {
	return q.StorageRatio >= 0.8 || q.PublishRatio >= 0.8 || q.DownloadRatio >= 0.8
}
