// Package scanner provides a pluggable interface for running IaC security scanners
// against extracted Terraform module archives.  Supported tools: trivy, terrascan,
// snyk, checkov, custom.
//
// All implementations follow the same contract: accept a directory path, run the
// tool, parse its output into a normalized ScanResult, and return.  Binary selection,
// version pinning, and invocation details are encapsulated in each implementation.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Scanner is the interface all scanning backends must implement.
type Scanner interface {
	// Name returns the human-readable tool name stored in the DB with results.
	Name() string
	// Version returns the actual installed binary version string.
	// Used for record-keeping and to enforce ExpectedVersion pinning.
	Version(ctx context.Context) (string, error)
	// ScanDirectory scans the extracted module directory and returns structured results.
	// Implementations apply their own timeout via context.
	ScanDirectory(ctx context.Context, dir string) (*ScanResult, error)
}

// ScanResult is the normalised output produced by any scanner implementation.
type ScanResult struct {
	ScannerVersion string // actual binary version at scan time
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	HasFindings    bool
	RawJSON        json.RawMessage // raw output from the tool stored as-is
}

// New constructs the appropriate Scanner implementation based on the operator config.
// Returns an error if the tool is unknown or the binary is not accessible.
func New(cfg *config.ScanningConfig) (Scanner, error) {
	if _, err := os.Stat(cfg.BinaryPath); err != nil {
		return nil, fmt.Errorf("scanner binary not accessible at %q: %w", cfg.BinaryPath, err)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	switch cfg.Tool {
	case "trivy":
		return newTrivyScanner(cfg.BinaryPath, timeout), nil
	case "terrascan":
		return newTerrascanScanner(cfg.BinaryPath, timeout), nil
	case "snyk":
		return newSnykScanner(cfg.BinaryPath, timeout), nil
	case "checkov":
		return newCheckovScanner(cfg.BinaryPath, timeout), nil
	case "custom":
		return newCustomScanner(cfg.BinaryPath, cfg.VersionArgs, cfg.ScanArgs, cfg.OutputFormat, timeout), nil
	default:
		return nil, fmt.Errorf("unknown scanner tool %q (supported: trivy, terrascan, snyk, checkov, custom)", cfg.Tool)
	}
}
