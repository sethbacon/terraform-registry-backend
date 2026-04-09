// checkov.go implements the Scanner interface for Bridgecrew/Palo Alto Checkov.
// Checkov is a popular open-source IaC static analysis tool with broad Terraform support.
//
// Invocation: checkov -d <dir> -o json --quiet
// Output schema: {"results": {"failed_checks": [{"check_result": {"result": "failed"},
//
//	"check": {"severity": "HIGH"}}]}}
//
// Checkov exits 1 when checks fail; exit 0 means all checks passed.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type checkovScanner struct {
	binaryPath string
	timeout    time.Duration
}

func newCheckovScanner(binaryPath string, timeout time.Duration) Scanner {
	return &checkovScanner{binaryPath: binaryPath, timeout: timeout}
}

func (s *checkovScanner) Name() string { return "checkov" }

func (s *checkovScanner) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, s.binaryPath, "--version").Output() // #nosec G204 -- binaryPath is operator-configured, not user input
	if err != nil {
		return "", fmt.Errorf("checkov version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *checkovScanner) ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// checkov exits 1 on findings; capture output regardless.
	// #nosec G204
	out, _ := exec.CommandContext(ctx, s.binaryPath,
		"-d", dir, "-o", "json", "--quiet",
	).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("checkov timed out after %s", s.timeout)
	}
	if len(out) == 0 {
		return &ScanResult{}, nil
	}
	return parseCheckovJSON(s.Name(), out)
}

type checkovOutput struct {
	Results struct {
		FailedChecks []struct {
			Check struct {
				Severity string `json:"severity"`
			} `json:"check"`
		} `json:"failed_checks"`
	} `json:"results"`
}

// checkov may also output an array when multiple frameworks are scanned
type checkovArrayOutput []checkovOutput

func parseCheckovJSON(scannerName string, data []byte) (*ScanResult, error) {
	result := &ScanResult{RawJSON: json.RawMessage(data)}

	// Try array form first (multi-framework output)
	var arr checkovArrayOutput
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		for _, item := range arr {
			for _, fc := range item.Results.FailedChecks {
				incrementBySeverity(result, strings.ToUpper(fc.Check.Severity))
			}
		}
		result.HasFindings = result.CriticalCount+result.HighCount+result.MediumCount+result.LowCount > 0
		return result, nil
	}

	var single checkovOutput
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("%s: failed to parse output: %w", scannerName, err)
	}
	for _, fc := range single.Results.FailedChecks {
		incrementBySeverity(result, strings.ToUpper(fc.Check.Severity))
	}
	result.HasFindings = result.CriticalCount+result.HighCount+result.MediumCount+result.LowCount > 0
	return result, nil
}
