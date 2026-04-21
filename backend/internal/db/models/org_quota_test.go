package models

import "testing"

func TestQuotaStatus_IsStorageExceeded(t *testing.T) {
	tests := []struct {
		name string
		q    QuotaStatus
		want bool
	}{
		{"zero limit", QuotaStatus{StorageBytesLimit: 0, StorageBytesUsed: 100}, false},
		{"under limit", QuotaStatus{StorageBytesLimit: 1000, StorageBytesUsed: 500}, false},
		{"at limit", QuotaStatus{StorageBytesLimit: 1000, StorageBytesUsed: 1000}, true},
		{"over limit", QuotaStatus{StorageBytesLimit: 1000, StorageBytesUsed: 1500}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.q.IsStorageExceeded(); got != tt.want {
				t.Errorf("IsStorageExceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuotaStatus_IsPublishExceeded(t *testing.T) {
	tests := []struct {
		name string
		q    QuotaStatus
		want bool
	}{
		{"zero limit", QuotaStatus{PublishesPerDay: 0, PublishesToday: 5}, false},
		{"under limit", QuotaStatus{PublishesPerDay: 10, PublishesToday: 5}, false},
		{"at limit", QuotaStatus{PublishesPerDay: 10, PublishesToday: 10}, true},
		{"over limit", QuotaStatus{PublishesPerDay: 10, PublishesToday: 15}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.q.IsPublishExceeded(); got != tt.want {
				t.Errorf("IsPublishExceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuotaStatus_IsDownloadExceeded(t *testing.T) {
	tests := []struct {
		name string
		q    QuotaStatus
		want bool
	}{
		{"zero limit", QuotaStatus{DownloadsPerDay: 0, DownloadsToday: 5}, false},
		{"under limit", QuotaStatus{DownloadsPerDay: 100, DownloadsToday: 50}, false},
		{"at limit", QuotaStatus{DownloadsPerDay: 100, DownloadsToday: 100}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.q.IsDownloadExceeded(); got != tt.want {
				t.Errorf("IsDownloadExceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuotaStatus_IsNearLimit(t *testing.T) {
	tests := []struct {
		name string
		q    QuotaStatus
		want bool
	}{
		{"all zero", QuotaStatus{}, false},
		{"all below", QuotaStatus{StorageRatio: 0.5, PublishRatio: 0.5, DownloadRatio: 0.5}, false},
		{"storage near", QuotaStatus{StorageRatio: 0.85}, true},
		{"publish near", QuotaStatus{PublishRatio: 0.8}, true},
		{"download near", QuotaStatus{DownloadRatio: 0.9}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.q.IsNearLimit(); got != tt.want {
				t.Errorf("IsNearLimit() = %v, want %v", got, tt.want)
			}
		})
	}
}
