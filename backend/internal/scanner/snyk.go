// snyk.go implements the Scanner interface for Snyk IaC scanning.
// Snyk IaC detects misconfigurations in Terraform and other IaC formats.
//
// Invocation: snyk iac test <dir> --json
// Output schema: {"vulnerabilities": [{"severity": "high"}]} or array thereof
// Note: snyk exits 1 when issues are found; exit 0 means clean.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type snykScanner struct {
	binaryPath string
	timeout    time.Duration
}

func newSnykScanner(binaryPath string, timeout time.Duration) Scanner {
	return &snykScanner{binaryPath: binaryPath, timeout: timeout}
}

func (s *snykScanner) Name() string { return "snyk" }

func (s *snykScanner) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, s.binaryPath, "--version").Output() // #nosec G204 -- binaryPath is operator-configured, not user input
	if err != nil {
		return "", fmt.Errorf("snyk version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *snykScanner) ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// snyk exits 1 when issues found; we capture output regardless.
	// #nosec G204
	out, _ := exec.CommandContext(ctx, s.binaryPath,
		"iac", "test", dir, "--json",
	).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("snyk timed out after %s", s.timeout)
	}
	if len(out) == 0 {
		return &ScanResult{}, nil
	}
	return parseSnykJSON(s.Name(), out)
}

// snyk output may be a single object or an array when scanning multiple files
type snykSingleResult struct {
	Vulnerabilities []struct {
		Severity string `json:"severity"`
	} `json:"vulnerabilities"`
}

func parseSnykJSON(scannerName string, data []byte) (*ScanResult, error) {
	result := &ScanResult{RawJSON: json.RawMessage(data)}

	// Try array form first (multiple files)
	var arr []snykSingleResult
	if err := json.Unmarshal(data, &arr); err == nil {
		for _, item := range arr {
			for _, v := range item.Vulnerabilities {
				incrementBySeverity(result, strings.ToUpper(v.Severity))
			}
		}
		result.HasFindings = result.CriticalCount+result.HighCount+result.MediumCount+result.LowCount > 0
		return result, nil
	}

	// Fall back to single object
	var single snykSingleResult
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("%s: failed to parse output: %w", scannerName, err)
	}
	for _, v := range single.Vulnerabilities {
		incrementBySeverity(result, strings.ToUpper(v.Severity))
	}
	result.HasFindings = result.CriticalCount+result.HighCount+result.MediumCount+result.LowCount > 0
	return result, nil
}
