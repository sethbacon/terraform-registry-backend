package models

import (
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// CVEAdvisory.DecodeRefs
// ---------------------------------------------------------------------------

func TestCVEAdvisory_DecodeRefs_Populated(t *testing.T) {
	refs := []string{"https://example.com/a", "https://example.com/b"}
	raw, _ := json.Marshal(refs)
	a := &CVEAdvisory{RefsJSON: raw}
	a.DecodeRefs()
	if len(a.References) != 2 {
		t.Fatalf("expected 2 references, got %d", len(a.References))
	}
	if a.References[0] != refs[0] || a.References[1] != refs[1] {
		t.Errorf("unexpected references: %v", a.References)
	}
}

func TestCVEAdvisory_DecodeRefs_Empty(t *testing.T) {
	a := &CVEAdvisory{}
	a.DecodeRefs() // should be a no-op
	if len(a.References) != 0 {
		t.Errorf("expected no references, got %v", a.References)
	}
}

func TestCVEAdvisory_DecodeRefs_EmptyArray(t *testing.T) {
	a := &CVEAdvisory{RefsJSON: []byte("[]")}
	a.DecodeRefs()
	if a.References == nil {
		t.Error("expected non-nil slice after decoding empty array")
	}
	if len(a.References) != 0 {
		t.Errorf("expected 0 references, got %d", len(a.References))
	}
}

// ---------------------------------------------------------------------------
// CVEAdvisory.IsActive
// ---------------------------------------------------------------------------

func TestCVEAdvisory_IsActive_NilWithdrawnAt(t *testing.T) {
	a := &CVEAdvisory{WithdrawnAt: nil}
	if !a.IsActive() {
		t.Error("IsActive() should be true when WithdrawnAt is nil")
	}
}

func TestCVEAdvisory_IsActive_SetWithdrawnAt(t *testing.T) {
	now := time.Now()
	a := &CVEAdvisory{WithdrawnAt: &now}
	if a.IsActive() {
		t.Error("IsActive() should be false when WithdrawnAt is set")
	}
}

// ---------------------------------------------------------------------------
// CVEAffectedTarget.DecodeRef
// ---------------------------------------------------------------------------

func TestCVEAffectedTarget_DecodeRef_Populated(t *testing.T) {
	ref := CVETargetRef{Tool: "terraform", Version: "1.5.0"}
	raw, _ := json.Marshal(ref)
	target := &CVEAffectedTarget{TargetRefJSON: raw}
	target.DecodeRef()
	if target.TargetRef.Tool != "terraform" {
		t.Errorf("expected Tool=terraform, got %q", target.TargetRef.Tool)
	}
	if target.TargetRef.Version != "1.5.0" {
		t.Errorf("expected Version=1.5.0, got %q", target.TargetRef.Version)
	}
}

func TestCVEAffectedTarget_DecodeRef_Empty(t *testing.T) {
	target := &CVEAffectedTarget{}
	target.DecodeRef() // no-op
	if target.TargetRef.Tool != "" {
		t.Errorf("expected empty Tool, got %q", target.TargetRef.Tool)
	}
}

// ---------------------------------------------------------------------------
// CVETargetRef.FingerprintFor
// ---------------------------------------------------------------------------

func TestCVETargetRef_FingerprintFor_Binary(t *testing.T) {
	ref := CVETargetRef{MirrorConfigID: "cfg-1", TerraformVersionID: "ver-1"}
	fp := ref.FingerprintFor(CVETargetKindBinary)
	if fp != "cfg-1:ver-1" {
		t.Errorf("expected 'cfg-1:ver-1', got %q", fp)
	}
}

func TestCVETargetRef_FingerprintFor_Provider(t *testing.T) {
	ref := CVETargetRef{ProviderVersionID: "prov-ver-99"}
	fp := ref.FingerprintFor(CVETargetKindProvider)
	if fp != "prov-ver-99" {
		t.Errorf("expected 'prov-ver-99', got %q", fp)
	}
}

func TestCVETargetRef_FingerprintFor_Scanner(t *testing.T) {
	ref := CVETargetRef{Tool: "trivy", Version: "0.50.0"}
	fp := ref.FingerprintFor(CVETargetKindScanner)
	if fp != "trivy:0.50.0" {
		t.Errorf("expected 'trivy:0.50.0', got %q", fp)
	}
}

func TestCVETargetRef_FingerprintFor_Default(t *testing.T) {
	ref := CVETargetRef{Tool: "unknown-tool", Version: "1.0.0"}
	fp := ref.FingerprintFor("other-kind")
	if fp != "unknown-tool:1.0.0" {
		t.Errorf("expected 'unknown-tool:1.0.0', got %q", fp)
	}
}

func TestCVETargetRef_FingerprintFor_ProviderEmpty(t *testing.T) {
	ref := CVETargetRef{}
	fp := ref.FingerprintFor(CVETargetKindProvider)
	if fp != "" {
		t.Errorf("expected empty fingerprint for empty provider ref, got %q", fp)
	}
}
