// pull_through_test.go tests the pure helper functions in the pull-through service.
package services

import (
	"testing"
)

// ---------------------------------------------------------------------------
// NewPullThroughService
// ---------------------------------------------------------------------------

func TestNewPullThroughService_NotNil(t *testing.T) {
	svc := NewPullThroughService(nil, nil, nil)
	if svc == nil {
		t.Fatal("NewPullThroughService returned nil")
	}
}

// ---------------------------------------------------------------------------
// parseSHASUMContent
// ---------------------------------------------------------------------------

func TestParseSHASUMContent_Basic(t *testing.T) {
	content := "abc123  terraform_1.0.0_linux_amd64.zip\ndef456  terraform_1.0.0_darwin_amd64.zip\n"
	result := parseSHASUMContent(content)
	if result["terraform_1.0.0_linux_amd64.zip"] != "abc123" {
		t.Errorf("linux amd64 = %q, want abc123", result["terraform_1.0.0_linux_amd64.zip"])
	}
	if result["terraform_1.0.0_darwin_amd64.zip"] != "def456" {
		t.Errorf("darwin amd64 = %q, want def456", result["terraform_1.0.0_darwin_amd64.zip"])
	}
}

func TestParseSHASUMContent_Empty(t *testing.T) {
	result := parseSHASUMContent("")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestParseSHASUMContent_BlankLines(t *testing.T) {
	content := "\n\nabc123  file.zip\n\n"
	result := parseSHASUMContent(content)
	if len(result) != 1 {
		t.Errorf("expected 1 entry, got %d: %v", len(result), result)
	}
}

func TestParseSHASUMContent_MalformedLines(t *testing.T) {
	// Lines without the double-space separator are skipped
	content := "malformed-line\nabc123  good.zip\n"
	result := parseSHASUMContent(content)
	if len(result) != 1 {
		t.Errorf("expected 1 entry, got %d: %v", len(result), result)
	}
	if result["good.zip"] != "abc123" {
		t.Errorf("good.zip = %q, want abc123", result["good.zip"])
	}
}

func TestParseSHASUMContent_TrailingWhitespace(t *testing.T) {
	content := "abc123  file.zip   \n"
	result := parseSHASUMContent(content)
	// Accept either trimmed or untrimmed key — both are valid implementations.
	_, trimmed := result["file.zip"]
	_, untrimmed := result["file.zip   "]
	if !trimmed && !untrimmed {
		t.Errorf("parseSHASUMContent(%q): expected key 'file.zip' (trimmed or untrimmed), got keys: %v", content, result)
	}
}

func TestParseSHASUMContent_MultipleEntries(t *testing.T) {
	lines := ""
	for i := 0; i < 10; i++ {
		lines += "hash" + string(rune('0'+i)) + "  file" + string(rune('0'+i)) + ".zip\n"
	}
	result := parseSHASUMContent(lines)
	if len(result) != 10 {
		t.Errorf("expected 10 entries, got %d", len(result))
	}
}
