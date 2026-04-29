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
	"log/slog"
	"os"
	"path/filepath"
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
	ExecutionLog   string          // stderr captured during execution (truncated to 10 KiB)
}

// truncateExecutionLog caps the log at 10 KiB to prevent unbounded DB growth.
func truncateExecutionLog(s string) string {
	const maxBytes = 10 * 1024
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + "\n... (truncated)"
}

// ResolveBinaryPath returns the path to the scanner binary that should actually
// be invoked. It prefers the operator-configured cfg.BinaryPath when that file
// exists, and falls back to the auto-installer's symlink at
// {InstallDir}/{Tool} when BinaryPath is missing.  This lets installations that
// rely on the in-app auto-installer keep working even if BinaryPath in the chart
// values still points at the legacy /usr/local/bin/<tool> default.
//
// The second return value is the path that was actually checked successfully,
// which may differ from cfg.BinaryPath when the fallback was used.  An empty
// string means no usable binary was found.
func ResolveBinaryPath(cfg *config.ScanningConfig) (string, bool) {
	if cfg.BinaryPath != "" {
		if _, err := os.Stat(cfg.BinaryPath); err == nil {
			return cfg.BinaryPath, true
		}
	}
	if cfg.InstallDir != "" && cfg.Tool != "" {
		fallback := filepath.Join(cfg.InstallDir, cfg.Tool)
		if _, err := os.Stat(fallback); err == nil {
			return fallback, true
		}
	}
	return "", false
}

// New constructs the appropriate Scanner implementation based on the operator config.
// Returns an error if the tool is unknown or no usable binary can be located.
//
// When cfg.BinaryPath does not exist but {InstallDir}/{Tool} does, the latter is
// used and a warning is logged.  This handles the common case where the chart
// default BinaryPath (e.g. /usr/local/bin/trivy) is wrong for installations that
// rely on the in-app auto-installer.
func New(cfg *config.ScanningConfig) (Scanner, error) {
	resolved, ok := ResolveBinaryPath(cfg)
	if !ok {
		return nil, fmt.Errorf("scanner binary not accessible at %q (also checked %s): no usable binary found",
			cfg.BinaryPath, filepath.Join(cfg.InstallDir, cfg.Tool))
	}
	if resolved != cfg.BinaryPath {
		slog.Warn("scanner: configured binary_path missing, using auto-installed binary",
			"tool", cfg.Tool,
			"configured_path", cfg.BinaryPath,
			"resolved_path", resolved,
			"hint", "update scanning.binary_path in your config to "+resolved)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	switch cfg.Tool {
	case "trivy":
		return newTrivyScanner(resolved, timeout), nil
	case "terrascan":
		return newTerrascanScanner(resolved, timeout), nil
	case "snyk":
		return newSnykScanner(resolved, timeout), nil
	case "checkov":
		return newCheckovScanner(resolved, timeout), nil
	case "custom":
		return newCustomScanner(resolved, cfg.VersionArgs, cfg.ScanArgs, cfg.OutputFormat, timeout), nil
	default:
		return nil, fmt.Errorf("unknown scanner tool %q (supported: trivy, terrascan, snyk, checkov, custom)", cfg.Tool)
	}
}
