// terrascan.go implements the Scanner interface for Accurics Terrascan.
// Terrascan is purpose-built for IaC security analysis and natively understands
// Terraform, Kubernetes, Helm, and other IaC formats.
//
// Invocation: terrascan scan -t terraform -d <dir> -o json
// Output schema: {"results": {"violations": [{"severity": "HIGH"}]}}
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type terrascanScanner struct {
	binaryPath string
	timeout    time.Duration
}

func newTerrascanScanner(binaryPath string, timeout time.Duration) Scanner {
	return &terrascanScanner{binaryPath: binaryPath, timeout: timeout}
}

func (s *terrascanScanner) Name() string { return "terrascan" }

func (s *terrascanScanner) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, s.binaryPath, "version").Output() // #nosec G204 -- binaryPath is operator-configured, not user input
	if err != nil {
		return "", fmt.Errorf("terrascan version: %w", err)
	}
	// Output is e.g. "Terrascan v1.18.3" or "v1.18.3"
	line := strings.TrimSpace(string(out))
	if idx := strings.Index(line, "v"); idx >= 0 {
		return strings.Fields(line[idx:])[0], nil
	}
	return line, nil
}

func (s *terrascanScanner) ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// terrascan exits 3 when violations are found; that is expected, not an error.
	// #nosec G204
	out, _ := exec.CommandContext(ctx, s.binaryPath,
		"scan", "-t", "terraform", "-d", dir, "-o", "json",
	).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("terrascan timed out after %s", s.timeout)
	}
	if len(out) == 0 {
		return &ScanResult{}, nil
	}
	return parseTerrascanJSON(s.Name(), out)
}

type terrascanOutput struct {
	Results struct {
		Violations []struct {
			Severity string `json:"severity"`
		} `json:"violations"`
	} `json:"results"`
}

func parseTerrascanJSON(scannerName string, data []byte) (*ScanResult, error) {
	var raw terrascanOutput
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: failed to parse output: %w", scannerName, err)
	}
	result := &ScanResult{RawJSON: json.RawMessage(data)}
	for _, v := range raw.Results.Violations {
		incrementBySeverity(result, strings.ToUpper(v.Severity))
	}
	result.HasFindings = result.CriticalCount+result.HighCount+result.MediumCount+result.LowCount > 0
	return result, nil
}
