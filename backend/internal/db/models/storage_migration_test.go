package models

import (
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// StorageMigration JSON serialization
// ---------------------------------------------------------------------------

func TestStorageMigration_JSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	errMsg := "some error"
	userID := "user-123"
	m := StorageMigration{
		ID:                "mig-1",
		SourceConfigID:    "src-cfg",
		TargetConfigID:    "tgt-cfg",
		Status:            "running",
		TotalArtifacts:    10,
		MigratedArtifacts: 5,
		FailedArtifacts:   1,
		SkippedArtifacts:  0,
		ErrorMessage:      &errMsg,
		StartedAt:         &now,
		CreatedAt:         now,
		CreatedBy:         &userID,
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got StorageMigration
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ID != m.ID {
		t.Errorf("ID = %q, want %q", got.ID, m.ID)
	}
	if got.SourceConfigID != m.SourceConfigID {
		t.Errorf("SourceConfigID = %q, want %q", got.SourceConfigID, m.SourceConfigID)
	}
	if got.TargetConfigID != m.TargetConfigID {
		t.Errorf("TargetConfigID = %q, want %q", got.TargetConfigID, m.TargetConfigID)
	}
	if got.Status != m.Status {
		t.Errorf("Status = %q, want %q", got.Status, m.Status)
	}
	if got.TotalArtifacts != m.TotalArtifacts {
		t.Errorf("TotalArtifacts = %d, want %d", got.TotalArtifacts, m.TotalArtifacts)
	}
	if got.MigratedArtifacts != m.MigratedArtifacts {
		t.Errorf("MigratedArtifacts = %d, want %d", got.MigratedArtifacts, m.MigratedArtifacts)
	}
	if got.FailedArtifacts != m.FailedArtifacts {
		t.Errorf("FailedArtifacts = %d, want %d", got.FailedArtifacts, m.FailedArtifacts)
	}
	if got.SkippedArtifacts != m.SkippedArtifacts {
		t.Errorf("SkippedArtifacts = %d, want %d", got.SkippedArtifacts, m.SkippedArtifacts)
	}
	if got.ErrorMessage == nil || *got.ErrorMessage != errMsg {
		t.Errorf("ErrorMessage = %v, want %q", got.ErrorMessage, errMsg)
	}
	if got.CreatedBy == nil || *got.CreatedBy != userID {
		t.Errorf("CreatedBy = %v, want %q", got.CreatedBy, userID)
	}
}

func TestStorageMigration_JSONOmitsNilOptionals(t *testing.T) {
	m := StorageMigration{
		ID:             "mig-2",
		SourceConfigID: "src",
		TargetConfigID: "tgt",
		Status:         "pending",
		CreatedAt:      time.Now(),
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	for _, key := range []string{"error_message", "started_at", "completed_at", "created_by"} {
		if _, exists := raw[key]; exists {
			t.Errorf("expected %q to be omitted when nil, but it was present", key)
		}
	}
}

func TestStorageMigration_JSONIncludesZeroInts(t *testing.T) {
	m := StorageMigration{
		ID:                "mig-3",
		SourceConfigID:    "src",
		TargetConfigID:    "tgt",
		Status:            "pending",
		TotalArtifacts:    0,
		MigratedArtifacts: 0,
		FailedArtifacts:   0,
		SkippedArtifacts:  0,
		CreatedAt:         time.Now(),
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	// Zero-value ints should still be present (no omitempty on int fields)
	for _, key := range []string{"total_artifacts", "migrated_artifacts", "failed_artifacts", "skipped_artifacts"} {
		if _, exists := raw[key]; !exists {
			t.Errorf("expected %q to be present even when zero", key)
		}
	}
}

// ---------------------------------------------------------------------------
// StorageMigrationItem JSON serialization
// ---------------------------------------------------------------------------

func TestStorageMigrationItem_JSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	errMsg := "download failed"
	item := StorageMigrationItem{
		ID:           "item-1",
		MigrationID:  "mig-1",
		ArtifactType: "module",
		ArtifactID:   "mod-v1",
		SourcePath:   "modules/vpc/1.0.0/archive.tar.gz",
		Status:       "failed",
		ErrorMessage: &errMsg,
		MigratedAt:   &now,
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got StorageMigrationItem
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ID != item.ID {
		t.Errorf("ID = %q, want %q", got.ID, item.ID)
	}
	if got.MigrationID != item.MigrationID {
		t.Errorf("MigrationID = %q, want %q", got.MigrationID, item.MigrationID)
	}
	if got.ArtifactType != item.ArtifactType {
		t.Errorf("ArtifactType = %q, want %q", got.ArtifactType, item.ArtifactType)
	}
	if got.ArtifactID != item.ArtifactID {
		t.Errorf("ArtifactID = %q, want %q", got.ArtifactID, item.ArtifactID)
	}
	if got.SourcePath != item.SourcePath {
		t.Errorf("SourcePath = %q, want %q", got.SourcePath, item.SourcePath)
	}
	if got.Status != item.Status {
		t.Errorf("Status = %q, want %q", got.Status, item.Status)
	}
	if got.ErrorMessage == nil || *got.ErrorMessage != errMsg {
		t.Errorf("ErrorMessage = %v, want %q", got.ErrorMessage, errMsg)
	}
}

func TestStorageMigrationItem_JSONOmitsNilOptionals(t *testing.T) {
	item := StorageMigrationItem{
		ID:           "item-2",
		MigrationID:  "mig-1",
		ArtifactType: "provider",
		ArtifactID:   "prov-1",
		SourcePath:   "providers/aws/5.0.0/linux_amd64.zip",
		Status:       "pending",
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	for _, key := range []string{"error_message", "migrated_at"} {
		if _, exists := raw[key]; exists {
			t.Errorf("expected %q to be omitted when nil, but it was present", key)
		}
	}
}

// ---------------------------------------------------------------------------
// MigrationPlan JSON serialization
// ---------------------------------------------------------------------------

func TestMigrationPlan_JSONRoundTrip(t *testing.T) {
	plan := MigrationPlan{
		SourceConfigID: "src-cfg-id",
		TargetConfigID: "tgt-cfg-id",
		ModuleCount:    5,
		ProviderCount:  3,
		TotalArtifacts: 8,
	}

	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got MigrationPlan
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.SourceConfigID != plan.SourceConfigID {
		t.Errorf("SourceConfigID = %q, want %q", got.SourceConfigID, plan.SourceConfigID)
	}
	if got.TargetConfigID != plan.TargetConfigID {
		t.Errorf("TargetConfigID = %q, want %q", got.TargetConfigID, plan.TargetConfigID)
	}
	if got.ModuleCount != plan.ModuleCount {
		t.Errorf("ModuleCount = %d, want %d", got.ModuleCount, plan.ModuleCount)
	}
	if got.ProviderCount != plan.ProviderCount {
		t.Errorf("ProviderCount = %d, want %d", got.ProviderCount, plan.ProviderCount)
	}
	if got.TotalArtifacts != plan.TotalArtifacts {
		t.Errorf("TotalArtifacts = %d, want %d", got.TotalArtifacts, plan.TotalArtifacts)
	}
}

func TestMigrationPlan_JSONKeys(t *testing.T) {
	plan := MigrationPlan{
		SourceConfigID: "src",
		TargetConfigID: "tgt",
		ModuleCount:    1,
		ProviderCount:  2,
		TotalArtifacts: 3,
	}

	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	expectedKeys := []string{"source_config_id", "target_config_id", "module_count", "provider_count", "total_artifacts"}
	for _, key := range expectedKeys {
		if _, exists := raw[key]; !exists {
			t.Errorf("expected JSON key %q to be present", key)
		}
	}
}

// ---------------------------------------------------------------------------
// ArtifactInfo struct fields
// ---------------------------------------------------------------------------

func TestArtifactInfo_Fields(t *testing.T) {
	a := ArtifactInfo{
		ID:          "artifact-1",
		StoragePath: "modules/vpc/1.0.0/archive.tar.gz",
	}
	if a.ID != "artifact-1" {
		t.Errorf("ID = %q, want artifact-1", a.ID)
	}
	if a.StoragePath != "modules/vpc/1.0.0/archive.tar.gz" {
		t.Errorf("StoragePath = %q, want modules/vpc/1.0.0/archive.tar.gz", a.StoragePath)
	}
}
