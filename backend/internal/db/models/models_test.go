package models

import (
	"database/sql"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// MirrorApprovalRequest.IsExpired / IsValid
// ---------------------------------------------------------------------------

func TestMirrorApproval_IsExpired_NilExpiresAt(t *testing.T) {
	m := &MirrorApprovalRequest{ExpiresAt: nil}
	if m.IsExpired() {
		t.Error("IsExpired() should be false when ExpiresAt is nil")
	}
}

func TestMirrorApproval_IsExpired_FutureTime(t *testing.T) {
	future := time.Now().Add(time.Hour)
	m := &MirrorApprovalRequest{ExpiresAt: &future}
	if m.IsExpired() {
		t.Error("IsExpired() should be false for a future expiry")
	}
}

func TestMirrorApproval_IsExpired_PastTime(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	m := &MirrorApprovalRequest{ExpiresAt: &past}
	if !m.IsExpired() {
		t.Error("IsExpired() should be true for a past expiry")
	}
}

func TestMirrorApproval_IsValid_ApprovedNotExpired(t *testing.T) {
	future := time.Now().Add(time.Hour)
	m := &MirrorApprovalRequest{Status: ApprovalStatusApproved, ExpiresAt: &future}
	if !m.IsValid() {
		t.Error("IsValid() should be true for approved and not expired")
	}
}

func TestMirrorApproval_IsValid_ApprovedNoExpiry(t *testing.T) {
	m := &MirrorApprovalRequest{Status: ApprovalStatusApproved, ExpiresAt: nil}
	if !m.IsValid() {
		t.Error("IsValid() should be true for approved with no expiry")
	}
}

func TestMirrorApproval_IsValid_Pending(t *testing.T) {
	m := &MirrorApprovalRequest{Status: ApprovalStatusPending, ExpiresAt: nil}
	if m.IsValid() {
		t.Error("IsValid() should be false for pending status")
	}
}

func TestMirrorApproval_IsValid_Rejected(t *testing.T) {
	m := &MirrorApprovalRequest{Status: ApprovalStatusRejected, ExpiresAt: nil}
	if m.IsValid() {
		t.Error("IsValid() should be false for rejected status")
	}
}

func TestMirrorApproval_IsValid_ApprovedButExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	m := &MirrorApprovalRequest{Status: ApprovalStatusApproved, ExpiresAt: &past}
	if m.IsValid() {
		t.Error("IsValid() should be false when approved but expired")
	}
}

// ---------------------------------------------------------------------------
// MirrorPolicy.Matches
// ---------------------------------------------------------------------------

func TestMirrorPolicy_Matches_AllNil(t *testing.T) {
	p := &MirrorPolicy{} // all patterns nil → matches everything
	if !p.Matches("registry.terraform.io", "hashicorp", "aws") {
		t.Error("Matches() should return true when all patterns are nil")
	}
}

func TestMirrorPolicy_Matches_SpecificRegistry_Match(t *testing.T) {
	reg := "registry.terraform.io"
	p := &MirrorPolicy{UpstreamRegistry: &reg}
	if !p.Matches("registry.terraform.io", "hashicorp", "aws") {
		t.Error("Matches() should return true for matching registry")
	}
}

func TestMirrorPolicy_Matches_SpecificRegistry_NoMatch(t *testing.T) {
	reg := "registry.terraform.io"
	p := &MirrorPolicy{UpstreamRegistry: &reg}
	if p.Matches("other.registry.io", "hashicorp", "aws") {
		t.Error("Matches() should return false for non-matching registry")
	}
}

func TestMirrorPolicy_Matches_NamespaceWildcard(t *testing.T) {
	star := "*"
	p := &MirrorPolicy{NamespacePattern: &star}
	if !p.Matches("any.registry", "any-namespace", "any-provider") {
		t.Error("Matches() should return true for wildcard namespace")
	}
}

func TestMirrorPolicy_Matches_SpecificNamespace_Match(t *testing.T) {
	ns := "hashicorp"
	p := &MirrorPolicy{NamespacePattern: &ns}
	if !p.Matches("registry.terraform.io", "hashicorp", "aws") {
		t.Error("Matches() should return true for matching namespace")
	}
}

func TestMirrorPolicy_Matches_SpecificNamespace_NoMatch(t *testing.T) {
	ns := "hashicorp"
	p := &MirrorPolicy{NamespacePattern: &ns}
	if p.Matches("registry.terraform.io", "other-namespace", "aws") {
		t.Error("Matches() should return false for non-matching namespace")
	}
}

func TestMirrorPolicy_Matches_ProviderWildcard(t *testing.T) {
	star := "*"
	p := &MirrorPolicy{ProviderPattern: &star}
	if !p.Matches("any.registry", "any-namespace", "any-provider") {
		t.Error("Matches() should return true for wildcard provider")
	}
}

func TestMirrorPolicy_Matches_SpecificProvider_NoMatch(t *testing.T) {
	prov := "aws"
	p := &MirrorPolicy{ProviderPattern: &prov}
	if p.Matches("registry.terraform.io", "hashicorp", "gcp") {
		t.Error("Matches() should return false for non-matching provider")
	}
}

func TestMirrorPolicy_Matches_AllSpecific_Match(t *testing.T) {
	reg := "registry.terraform.io"
	ns := "hashicorp"
	prov := "aws"
	p := &MirrorPolicy{UpstreamRegistry: &reg, NamespacePattern: &ns, ProviderPattern: &prov}
	if !p.Matches("registry.terraform.io", "hashicorp", "aws") {
		t.Error("Matches() should return true when all patterns match")
	}
}

func TestMirrorPolicy_Matches_EmptyPatternStrings(t *testing.T) {
	empty := ""
	p := &MirrorPolicy{UpstreamRegistry: &empty, NamespacePattern: &empty, ProviderPattern: &empty}
	// Empty string patterns are treated as "match all"
	if !p.Matches("any.registry", "any-namespace", "any-provider") {
		t.Error("Matches() should return true for empty pattern strings")
	}
}

// ---------------------------------------------------------------------------
// PredefinedRoleTemplates
// ---------------------------------------------------------------------------

func TestPredefinedRoleTemplates_Count(t *testing.T) {
	templates := PredefinedRoleTemplates()
	if len(templates) != 4 {
		t.Errorf("expected 4 role templates, got %d", len(templates))
	}
}

func TestPredefinedRoleTemplates_Names(t *testing.T) {
	templates := PredefinedRoleTemplates()
	expected := map[string]bool{"viewer": true, "publisher": true, "devops": true, "admin": true}
	for _, tmpl := range templates {
		if !expected[tmpl.Name] {
			t.Errorf("unexpected template name: %q", tmpl.Name)
		}
		if !tmpl.IsSystem {
			t.Errorf("template %q should be a system template", tmpl.Name)
		}
		if tmpl.Description == nil {
			t.Errorf("template %q should have a description", tmpl.Name)
		}
		if len(tmpl.Scopes) == 0 {
			t.Errorf("template %q should have at least one scope", tmpl.Name)
		}
	}
}

func TestPredefinedRoleTemplates_AdminHasAdminScope(t *testing.T) {
	templates := PredefinedRoleTemplates()
	for _, tmpl := range templates {
		if tmpl.Name == "admin" {
			found := false
			for _, s := range tmpl.Scopes {
				if s == "admin" {
					found = true
					break
				}
			}
			if !found {
				t.Error("admin role template should have 'admin' scope")
			}
			return
		}
	}
	t.Error("admin role template not found")
}

// ---------------------------------------------------------------------------
// StorageConfig.ToResponse
// ---------------------------------------------------------------------------

func TestStorageConfig_ToResponse_LocalFields(t *testing.T) {
	cfg := &StorageConfig{
		BackendType:        "local",
		IsActive:           true,
		LocalBasePath:      sql.NullString{String: "/data", Valid: true},
		LocalServeDirectly: sql.NullBool{Bool: true, Valid: true},
	}
	resp := cfg.ToResponse()
	if resp.BackendType != "local" {
		t.Errorf("BackendType = %q, want local", resp.BackendType)
	}
	if !resp.IsActive {
		t.Error("IsActive should be true")
	}
	if resp.LocalBasePath != "/data" {
		t.Errorf("LocalBasePath = %q, want /data", resp.LocalBasePath)
	}
	if resp.LocalServeDirectly == nil || !*resp.LocalServeDirectly {
		t.Error("LocalServeDirectly should be *true")
	}
}

func TestStorageConfig_ToResponse_LocalFields_NotValid(t *testing.T) {
	cfg := &StorageConfig{
		BackendType:        "local",
		LocalBasePath:      sql.NullString{Valid: false},
		LocalServeDirectly: sql.NullBool{Valid: false},
	}
	resp := cfg.ToResponse()
	if resp.LocalBasePath != "" {
		t.Errorf("LocalBasePath should be empty, got %q", resp.LocalBasePath)
	}
	if resp.LocalServeDirectly != nil {
		t.Error("LocalServeDirectly should be nil")
	}
}

func TestStorageConfig_ToResponse_AzureFields(t *testing.T) {
	cfg := &StorageConfig{
		BackendType:              "azure",
		AzureAccountName:        sql.NullString{String: "myaccount", Valid: true},
		AzureAccountKeyEncrypted: sql.NullString{String: "encrypted-key", Valid: true},
		AzureContainerName:      sql.NullString{String: "mycontainer", Valid: true},
		AzureCDNURL:             sql.NullString{String: "https://cdn.example.com", Valid: true},
	}
	resp := cfg.ToResponse()
	if resp.AzureAccountName != "myaccount" {
		t.Errorf("AzureAccountName = %q, want myaccount", resp.AzureAccountName)
	}
	if !resp.AzureAccountKeySet {
		t.Error("AzureAccountKeySet should be true when key is set")
	}
	if resp.AzureContainerName != "mycontainer" {
		t.Errorf("AzureContainerName = %q, want mycontainer", resp.AzureContainerName)
	}
	if resp.AzureCDNURL != "https://cdn.example.com" {
		t.Errorf("AzureCDNURL = %q, want https://cdn.example.com", resp.AzureCDNURL)
	}
}

func TestStorageConfig_ToResponse_AzureKeyNotSet(t *testing.T) {
	cfg := &StorageConfig{
		BackendType:              "azure",
		AzureAccountKeyEncrypted: sql.NullString{Valid: false},
	}
	resp := cfg.ToResponse()
	if resp.AzureAccountKeySet {
		t.Error("AzureAccountKeySet should be false when key is not set")
	}
}

func TestStorageConfig_ToResponse_S3Fields(t *testing.T) {
	cfg := &StorageConfig{
		BackendType:                "s3",
		S3Region:                   sql.NullString{String: "us-east-1", Valid: true},
		S3Bucket:                   sql.NullString{String: "my-bucket", Valid: true},
		S3AuthMethod:               sql.NullString{String: "access_key", Valid: true},
		S3AccessKeyIDEncrypted:     sql.NullString{String: "encrypted-key-id", Valid: true},
		S3SecretAccessKeyEncrypted: sql.NullString{String: "encrypted-secret", Valid: true},
	}
	resp := cfg.ToResponse()
	if resp.S3Region != "us-east-1" {
		t.Errorf("S3Region = %q, want us-east-1", resp.S3Region)
	}
	if resp.S3Bucket != "my-bucket" {
		t.Errorf("S3Bucket = %q, want my-bucket", resp.S3Bucket)
	}
	if !resp.S3AccessKeyIDSet {
		t.Error("S3AccessKeyIDSet should be true")
	}
	if !resp.S3SecretAccessKeySet {
		t.Error("S3SecretAccessKeySet should be true")
	}
}

func TestStorageConfig_ToResponse_GCSFields(t *testing.T) {
	cfg := &StorageConfig{
		BackendType:                 "gcs",
		GCSBucket:                   sql.NullString{String: "my-gcs-bucket", Valid: true},
		GCSProjectID:                sql.NullString{String: "my-project", Valid: true},
		GCSAuthMethod:               sql.NullString{String: "service_account", Valid: true},
		GCSCredentialsJSONEncrypted: sql.NullString{String: "encrypted-creds", Valid: true},
	}
	resp := cfg.ToResponse()
	if resp.GCSBucket != "my-gcs-bucket" {
		t.Errorf("GCSBucket = %q, want my-gcs-bucket", resp.GCSBucket)
	}
	if resp.GCSProjectID != "my-project" {
		t.Errorf("GCSProjectID = %q, want my-project", resp.GCSProjectID)
	}
	if !resp.GCSCredentialsJSONSet {
		t.Error("GCSCredentialsJSONSet should be true when credentials are set")
	}
}
