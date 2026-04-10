// scanner_test.go tests all scanner implementations.
// The test binary doubles as a fake scanner subprocess: when FAKE_SCANNER_MODE is set
// it outputs mock scanner output and exits, allowing Version() and ScanDirectory()
// to be exercised without installing any real scanner binaries.
package scanner

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// TestMain — fake scanner subprocess
// ---------------------------------------------------------------------------

// TestMain intercepts the test binary when it is re-invoked as a fake scanner.
// Any test that wants to call Version() or ScanDirectory() sets FAKE_SCANNER_MODE
// via t.Setenv; the child process (this same binary) reads that env var here and
// emits the appropriate mock output instead of running the test suite.
func TestMain(m *testing.M) {
	if mode := os.Getenv("FAKE_SCANNER_MODE"); mode != "" {
		os.Exit(fakeScanner(mode))
	}
	os.Exit(m.Run())
}

// fakeScanner writes mock scanner output to stdout and returns an exit code.
func fakeScanner(mode string) int {
	switch mode {
	// --- trivy ---
	case "trivy-version":
		fmt.Print(`{"Version": "0.45.0"}`)
		return 0
	case "trivy-scan-pass":
		fmt.Print(`{"Results": []}`)
		return 0
	case "trivy-scan-fail":
		fmt.Print(`{"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}, {"Severity": "HIGH"}], "Misconfigurations": [{"Severity": "MEDIUM"}]}]}`)
		return 0

	// --- terrascan ---
	case "terrascan-version":
		fmt.Print("Terrascan v1.18.3")
		return 0
	case "terrascan-scan-pass":
		fmt.Print(`{"results": {"violations": []}}`)
		return 0
	case "terrascan-scan-fail":
		// terrascan exits 3 when violations are found
		fmt.Print(`{"results": {"violations": [{"severity": "HIGH"}, {"severity": "MEDIUM"}]}}`)
		return 3

	// --- snyk ---
	case "snyk-version":
		fmt.Print("1.1234.0")
		return 0
	case "snyk-scan-pass":
		fmt.Print(`[{"vulnerabilities": []}]`)
		return 0
	case "snyk-scan-fail":
		// snyk exits 1 when issues are found
		fmt.Print(`[{"vulnerabilities": [{"severity": "HIGH"}, {"severity": "CRITICAL"}]}]`)
		return 1

	// --- checkov ---
	case "checkov-version":
		fmt.Print("3.2.100")
		return 0
	case "checkov-scan-pass":
		fmt.Print(`{"results": {"failed_checks": []}}`)
		return 0
	case "checkov-scan-fail":
		// checkov exits 1 when checks fail
		fmt.Print(`[{"results": {"failed_checks": [{"check": {"severity": "HIGH"}}, {"check": {"severity": "CRITICAL"}}]}}]`)
		return 1

	// --- custom (SARIF) ---
	case "custom-version":
		fmt.Print("custom-scanner 1.0.0")
		return 0
	case "custom-scan-sarif-pass":
		fmt.Print(`{"runs": [{"results": []}]}`)
		return 0
	case "custom-scan-sarif-fail":
		fmt.Print(`{"runs": [{"results": [{"level": "error"}, {"level": "warning"}]}]}`)
		return 0
	case "custom-scan-json":
		fmt.Print(`{"status": "ok", "findings": []}`)
		return 0
	}

	fmt.Fprintf(os.Stderr, "unknown FAKE_SCANNER_MODE: %s\n", mode)
	return 1
}

// ---------------------------------------------------------------------------
// incrementBySeverity
// ---------------------------------------------------------------------------

func TestIncrementBySeverity(t *testing.T) {
	tests := []struct {
		severity string
		wantCrit int
		wantHigh int
		wantMed  int
		wantLow  int
	}{
		{"CRITICAL", 1, 0, 0, 0},
		{"HIGH", 0, 1, 0, 0},
		{"MEDIUM", 0, 0, 1, 0},
		{"LOW", 0, 0, 0, 1},
		{"UNKNOWN", 0, 0, 0, 0},
		{"", 0, 0, 0, 0},
		{"info", 0, 0, 0, 0},
	}
	for _, tt := range tests {
		r := &ScanResult{}
		incrementBySeverity(r, tt.severity)
		if r.CriticalCount != tt.wantCrit || r.HighCount != tt.wantHigh ||
			r.MediumCount != tt.wantMed || r.LowCount != tt.wantLow {
			t.Errorf("incrementBySeverity(%q) = {%d,%d,%d,%d}, want {%d,%d,%d,%d}",
				tt.severity,
				r.CriticalCount, r.HighCount, r.MediumCount, r.LowCount,
				tt.wantCrit, tt.wantHigh, tt.wantMed, tt.wantLow)
		}
	}
}

// ---------------------------------------------------------------------------
// Scanner Name() methods (no binary required)
// ---------------------------------------------------------------------------

func TestScannerNames(t *testing.T) {
	timeout := 5 * time.Minute
	tests := []struct {
		name    string
		scanner Scanner
	}{
		{"trivy", newTrivyScanner("/fake/trivy", timeout)},
		{"terrascan", newTerrascanScanner("/fake/terrascan", timeout)},
		{"snyk", newSnykScanner("/fake/snyk", timeout)},
		{"checkov", newCheckovScanner("/fake/checkov", timeout)},
		{"custom", newCustomScanner("/fake/custom", nil, nil, "json", timeout)},
	}
	for _, tt := range tests {
		if got := tt.scanner.Name(); got != tt.name {
			t.Errorf("Name() = %q, want %q", got, tt.name)
		}
	}
}

// ---------------------------------------------------------------------------
// New() factory
// ---------------------------------------------------------------------------

// selfPath returns the path to the currently running test binary, which is
// guaranteed to exist.  This allows New() to pass the os.Stat check and reach
// the switch statement that selects the Scanner implementation.
func selfPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot determine test executable path: %v", err)
	}
	return exe
}

func TestNew_AllValidTools(t *testing.T) {
	tools := []string{"trivy", "terrascan", "snyk", "checkov"}
	bin := selfPath(t)
	for _, tool := range tools {
		cfg := &config.ScanningConfig{BinaryPath: bin, Tool: tool}
		s, err := New(cfg)
		if err != nil {
			t.Errorf("New(%q): unexpected error: %v", tool, err)
			continue
		}
		if s.Name() != tool {
			t.Errorf("New(%q).Name() = %q, want %q", tool, s.Name(), tool)
		}
	}
}

func TestNew_CustomTool(t *testing.T) {
	bin := selfPath(t)
	cfg := &config.ScanningConfig{
		BinaryPath:   bin,
		Tool:         "custom",
		VersionArgs:  []string{"--version"},
		ScanArgs:     []string{"scan"},
		OutputFormat: "sarif",
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New(custom): unexpected error: %v", err)
	}
	if s.Name() != "custom" {
		t.Errorf("Name() = %q, want custom", s.Name())
	}
}

func TestNew_DefaultTimeout(t *testing.T) {
	// Zero timeout should be replaced with 5 minutes — this is an internal
	// detail but we verify New() does not error when Timeout is unset.
	bin := selfPath(t)
	cfg := &config.ScanningConfig{BinaryPath: bin, Tool: "trivy", Timeout: 0}
	_, err := New(cfg)
	if err != nil {
		t.Fatalf("New with zero timeout: unexpected error: %v", err)
	}
}

func TestNew_UnknownTool(t *testing.T) {
	bin := selfPath(t)
	cfg := &config.ScanningConfig{BinaryPath: bin, Tool: "unknown-tool"}
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for unknown tool, got nil")
	}
}

func TestNew_InaccessibleBinary(t *testing.T) {
	cfg := &config.ScanningConfig{
		BinaryPath: "/nonexistent/path/to/scanner",
		Tool:       "trivy",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for inaccessible binary, got nil")
	}
}

// ---------------------------------------------------------------------------
// parseTrivyJSON
// ---------------------------------------------------------------------------

func TestParseTrivyJSON_Empty(t *testing.T) {
	result, err := parseTrivyJSON("trivy", []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false for empty data")
	}
}

func TestParseTrivyJSON_CleanScan(t *testing.T) {
	data := []byte(`{"Results": []}`)
	result, err := parseTrivyJSON("trivy", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false for clean scan")
	}
	if result.CriticalCount+result.HighCount+result.MediumCount+result.LowCount != 0 {
		t.Error("expected zero counts for clean scan")
	}
}

func TestParseTrivyJSON_WithVulnerabilities(t *testing.T) {
	data := []byte(`{
		"Results": [{
			"Vulnerabilities": [
				{"Severity": "CRITICAL"},
				{"Severity": "HIGH"},
				{"Severity": "HIGH"},
				{"Severity": "MEDIUM"},
				{"Severity": "LOW"}
			],
			"Misconfigurations": []
		}]
	}`)
	result, err := parseTrivyJSON("trivy", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
	if result.HighCount != 2 {
		t.Errorf("HighCount = %d, want 2", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
	if result.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", result.LowCount)
	}
}

func TestParseTrivyJSON_WithMisconfigurations(t *testing.T) {
	data := []byte(`{
		"Results": [{
			"Vulnerabilities": [],
			"Misconfigurations": [
				{"Severity": "HIGH"},
				{"Severity": "MEDIUM"}
			]
		}]
	}`)
	result, err := parseTrivyJSON("trivy", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

func TestParseTrivyJSON_MultipleResults(t *testing.T) {
	data := []byte(`{
		"Results": [
			{"Vulnerabilities": [{"Severity": "CRITICAL"}], "Misconfigurations": []},
			{"Vulnerabilities": [], "Misconfigurations": [{"Severity": "HIGH"}]}
		]
	}`)
	result, err := parseTrivyJSON("trivy", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
}

func TestParseTrivyJSON_InvalidJSON(t *testing.T) {
	_, err := parseTrivyJSON("trivy", []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseTrivyJSON_RawJSONPreserved(t *testing.T) {
	data := []byte(`{"Results": []}`)
	result, err := parseTrivyJSON("trivy", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.RawJSON) != string(data) {
		t.Errorf("RawJSON = %s, want %s", result.RawJSON, data)
	}
}

// ---------------------------------------------------------------------------
// parseTerrascanJSON
// ---------------------------------------------------------------------------

func TestParseTerrascanJSON_NoViolations(t *testing.T) {
	data := []byte(`{"results": {"violations": []}}`)
	result, err := parseTerrascanJSON("terrascan", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false")
	}
}

func TestParseTerrascanJSON_WithViolations(t *testing.T) {
	data := []byte(`{
		"results": {
			"violations": [
				{"severity": "CRITICAL"},
				{"severity": "HIGH"},
				{"severity": "MEDIUM"},
				{"severity": "LOW"},
				{"severity": "LOW"}
			]
		}
	}`)
	result, err := parseTerrascanJSON("terrascan", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
	if result.LowCount != 2 {
		t.Errorf("LowCount = %d, want 2", result.LowCount)
	}
}

func TestParseTerrascanJSON_InvalidJSON(t *testing.T) {
	_, err := parseTerrascanJSON("terrascan", []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseTerrascanJSON_LowercaseSeverity(t *testing.T) {
	// terrascan sometimes emits lowercase severity
	data := []byte(`{"results": {"violations": [{"severity": "high"}, {"severity": "medium"}]}}`)
	result, err := parseTerrascanJSON("terrascan", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

// ---------------------------------------------------------------------------
// parseSnykJSON
// ---------------------------------------------------------------------------

func TestParseSnykJSON_ArrayForm_Clean(t *testing.T) {
	data := []byte(`[{"vulnerabilities": []}]`)
	result, err := parseSnykJSON("snyk", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false")
	}
}

func TestParseSnykJSON_ArrayForm_WithFindings(t *testing.T) {
	data := []byte(`[
		{"vulnerabilities": [{"severity": "HIGH"}, {"severity": "MEDIUM"}]},
		{"vulnerabilities": [{"severity": "CRITICAL"}]}
	]`)
	result, err := parseSnykJSON("snyk", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
}

func TestParseSnykJSON_SingleObject(t *testing.T) {
	data := []byte(`{"vulnerabilities": [{"severity": "HIGH"}, {"severity": "LOW"}]}`)
	result, err := parseSnykJSON("snyk", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", result.LowCount)
	}
}

func TestParseSnykJSON_EmptyArray(t *testing.T) {
	data := []byte(`[]`)
	result, err := parseSnykJSON("snyk", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false for empty array")
	}
}

func TestParseSnykJSON_InvalidJSON(t *testing.T) {
	_, err := parseSnykJSON("snyk", []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseSnykJSON_LowercaseSeverity(t *testing.T) {
	data := []byte(`{"vulnerabilities": [{"severity": "critical"}, {"severity": "medium"}]}`)
	result, err := parseSnykJSON("snyk", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

// ---------------------------------------------------------------------------
// parseCheckovJSON
// ---------------------------------------------------------------------------

func TestParseCheckovJSON_SingleObject_NoFailures(t *testing.T) {
	data := []byte(`{"results": {"failed_checks": []}}`)
	result, err := parseCheckovJSON("checkov", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false")
	}
}

func TestParseCheckovJSON_SingleObject_WithFailures(t *testing.T) {
	data := []byte(`{
		"results": {
			"failed_checks": [
				{"check": {"severity": "HIGH"}},
				{"check": {"severity": "CRITICAL"}},
				{"check": {"severity": "MEDIUM"}}
			]
		}
	}`)
	result, err := parseCheckovJSON("checkov", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
}

func TestParseCheckovJSON_ArrayForm(t *testing.T) {
	// Multi-framework output is an array of framework result objects
	data := []byte(`[
		{"results": {"failed_checks": [{"check": {"severity": "HIGH"}}]}},
		{"results": {"failed_checks": [{"check": {"severity": "LOW"}}]}}
	]`)
	result, err := parseCheckovJSON("checkov", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", result.LowCount)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
}

func TestParseCheckovJSON_InvalidJSON(t *testing.T) {
	_, err := parseCheckovJSON("checkov", []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseCheckovJSON_LowercaseSeverity(t *testing.T) {
	data := []byte(`{"results": {"failed_checks": [{"check": {"severity": "high"}}]}}`)
	result, err := parseCheckovJSON("checkov", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
}

// ---------------------------------------------------------------------------
// parseSARIF
// ---------------------------------------------------------------------------

func TestParseSARIF_Empty(t *testing.T) {
	data := []byte(`{"runs": []}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false for empty runs")
	}
}

func TestParseSARIF_ErrorLevel(t *testing.T) {
	// "error" → high
	data := []byte(`{"runs": [{"results": [{"level": "error"}, {"level": "error"}]}]}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 2 {
		t.Errorf("HighCount = %d, want 2", result.HighCount)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
}

func TestParseSARIF_WarningLevel(t *testing.T) {
	// "warning" → medium
	data := []byte(`{"runs": [{"results": [{"level": "warning"}]}]}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

func TestParseSARIF_NoteLevel(t *testing.T) {
	// "note" → low
	data := []byte(`{"runs": [{"results": [{"level": "note"}]}]}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", result.LowCount)
	}
}

func TestParseSARIF_NoneLevel(t *testing.T) {
	// "none" is ignored
	data := []byte(`{"runs": [{"results": [{"level": "none"}]}]}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false for 'none' level")
	}
}

func TestParseSARIF_MixedLevels(t *testing.T) {
	data := []byte(`{
		"runs": [{
			"results": [
				{"level": "error"},
				{"level": "warning"},
				{"level": "note"},
				{"level": "none"}
			]
		}]
	}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
	if result.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", result.LowCount)
	}
}

func TestParseSARIF_MultipleRuns(t *testing.T) {
	data := []byte(`{
		"runs": [
			{"results": [{"level": "error"}]},
			{"results": [{"level": "warning"}]}
		]
	}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

func TestParseSARIF_InvalidJSON(t *testing.T) {
	_, err := parseSARIF("custom", []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseSARIF_CaseInsensitiveLevel(t *testing.T) {
	data := []byte(`{"runs": [{"results": [{"level": "ERROR"}, {"level": "WARNING"}]}]}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

func TestParseSARIF_RawJSONPreserved(t *testing.T) {
	data := []byte(`{"runs": []}`)
	result, err := parseSARIF("custom", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.RawJSON) != string(data) {
		t.Errorf("RawJSON = %s, want %s", result.RawJSON, data)
	}
}

// ---------------------------------------------------------------------------
// trivy Version() and ScanDirectory() — uses fake scanner subprocess
// ---------------------------------------------------------------------------

func TestTrivyScanner_Version(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "trivy-version")
	s := newTrivyScanner(selfPath(t), 30*time.Second)
	ver, err := s.Version(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "0.45.0" {
		t.Errorf("Version = %q, want 0.45.0", ver)
	}
}

func TestTrivyScanner_ScanDirectory_Pass(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "trivy-scan-pass")
	s := newTrivyScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false for clean scan")
	}
}

func TestTrivyScanner_ScanDirectory_Fail(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "trivy-scan-fail")
	s := newTrivyScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

// ---------------------------------------------------------------------------
// terrascan Version() and ScanDirectory()
// ---------------------------------------------------------------------------

func TestTerrascanScanner_Version(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "terrascan-version")
	s := newTerrascanScanner(selfPath(t), 30*time.Second)
	ver, err := s.Version(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "v1.18.3" {
		t.Errorf("Version = %q, want v1.18.3", ver)
	}
}

func TestTerrascanScanner_ScanDirectory_Pass(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "terrascan-scan-pass")
	s := newTerrascanScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false")
	}
}

func TestTerrascanScanner_ScanDirectory_Fail(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "terrascan-scan-fail")
	s := newTerrascanScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

// ---------------------------------------------------------------------------
// snyk Version() and ScanDirectory()
// ---------------------------------------------------------------------------

func TestSnykScanner_Version(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "snyk-version")
	s := newSnykScanner(selfPath(t), 30*time.Second)
	ver, err := s.Version(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "1.1234.0" {
		t.Errorf("Version = %q, want 1.1234.0", ver)
	}
}

func TestSnykScanner_ScanDirectory_Pass(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "snyk-scan-pass")
	s := newSnykScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false")
	}
}

func TestSnykScanner_ScanDirectory_Fail(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "snyk-scan-fail")
	s := newSnykScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
}

// ---------------------------------------------------------------------------
// checkov Version() and ScanDirectory()
// ---------------------------------------------------------------------------

func TestCheckovScanner_Version(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "checkov-version")
	s := newCheckovScanner(selfPath(t), 30*time.Second)
	ver, err := s.Version(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "3.2.100" {
		t.Errorf("Version = %q, want 3.2.100", ver)
	}
}

func TestCheckovScanner_ScanDirectory_Pass(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "checkov-scan-pass")
	s := newCheckovScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false")
	}
}

func TestCheckovScanner_ScanDirectory_Fail(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "checkov-scan-fail")
	s := newCheckovScanner(selfPath(t), 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", result.CriticalCount)
	}
}

// ---------------------------------------------------------------------------
// custom Version() and ScanDirectory() — SARIF and JSON output formats
// ---------------------------------------------------------------------------

func TestCustomScanner_Version(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "custom-version")
	s := newCustomScanner(selfPath(t), nil, nil, "json", 30*time.Second)
	ver, err := s.Version(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "custom-scanner 1.0.0" {
		t.Errorf("Version = %q, want 'custom-scanner 1.0.0'", ver)
	}
}

func TestCustomScanner_ScanDirectory_SARIFPass(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "custom-scan-sarif-pass")
	s := newCustomScanner(selfPath(t), nil, nil, "sarif", 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasFindings {
		t.Error("expected HasFindings=false")
	}
}

func TestCustomScanner_ScanDirectory_SARIFFail(t *testing.T) {
	t.Setenv("FAKE_SCANNER_MODE", "custom-scan-sarif-fail")
	s := newCustomScanner(selfPath(t), nil, nil, "sarif", 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings=true")
	}
	if result.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", result.HighCount)
	}
	if result.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", result.MediumCount)
	}
}

func TestCustomScanner_ScanDirectory_JSONFormat(t *testing.T) {
	// JSON output format stores raw JSON without severity parsing
	t.Setenv("FAKE_SCANNER_MODE", "custom-scan-json")
	s := newCustomScanner(selfPath(t), nil, []string{"scan"}, "json", 30*time.Second)
	result, err := s.ScanDirectory(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RawJSON) == 0 {
		t.Error("expected non-empty RawJSON for json output format")
	}
}
