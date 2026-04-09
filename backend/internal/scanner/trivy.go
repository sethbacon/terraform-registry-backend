// trivy.go implements the Scanner interface for Aqua Security Trivy.
// Trivy is the default tool choice; it supports filesystem scanning for vulnerabilities,
// secrets, and IaC misconfigurations in a single invocation.
//
// Invocation: trivy fs --format json --scanners vuln,secret,misconfig --exit-code 0 --quiet <dir>
// Output schema: {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}], "Misconfigurations": [...]}]}
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type trivyScanner struct {
	binaryPath string
	timeout    time.Duration
}

func newTrivyScanner(binaryPath string, timeout time.Duration) Scanner {
	return &trivyScanner{binaryPath: binaryPath, timeout: timeout}
}

func (s *trivyScanner) Name() string { return "trivy" }

func (s *trivyScanner) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, s.binaryPath, "version", "--format", "json").Output()
	if err != nil {
		// Fall back to plain version output
		out, err = exec.CommandContext(ctx, s.binaryPath, "--version").Output()
		if err != nil {
			return "", fmt.Errorf("trivy version: %w", err)
		}
		return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Version: ")), nil
	}
	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return strings.TrimSpace(string(out)), nil
	}
	return v.Version, nil
}

func (s *trivyScanner) ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// #nosec G204 -- binaryPath is set from operator config, not user input
	out, err := exec.CommandContext(ctx, s.binaryPath,
		"fs", "--format", "json",
		"--scanners", "vuln,secret,misconfig",
		"--exit-code", "0",
		"--quiet",
		dir,
	).Output()
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("trivy timed out after %s", s.timeout)
	}
	// trivy exits non-zero on findings when --exit-code is not 0, but we set it to 0
	// so non-zero exit here means a genuine error (binary not found, etc.)
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("trivy: %w", err)
	}
	return parseTrivyJSON(s.Name(), out)
}

// trivyResult mirrors the relevant portions of Trivy's JSON output schema.
type trivyResult struct {
	Results []struct {
		Vulnerabilities []struct {
			Severity string `json:"Severity"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			Severity string `json:"Severity"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func parseTrivyJSON(scannerName string, data []byte) (*ScanResult, error) {
	if len(data) == 0 {
		return &ScanResult{}, nil
	}
	var raw trivyResult
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: failed to parse output: %w", scannerName, err)
	}

	result := &ScanResult{RawJSON: json.RawMessage(data)}
	for _, r := range raw.Results {
		for _, v := range r.Vulnerabilities {
			incrementBySeverity(result, strings.ToUpper(v.Severity))
		}
		for _, m := range r.Misconfigurations {
			incrementBySeverity(result, strings.ToUpper(m.Severity))
		}
	}
	result.HasFindings = result.CriticalCount+result.HighCount+result.MediumCount+result.LowCount > 0
	return result, nil
}

func incrementBySeverity(r *ScanResult, severity string) {
	switch severity {
	case "CRITICAL":
		r.CriticalCount++
	case "HIGH":
		r.HighCount++
	case "MEDIUM":
		r.MediumCount++
	case "LOW":
		r.LowCount++
	}
}
