// custom.go implements the Scanner interface for operator-provided tools.
// Any binary that writes JSON or SARIF to stdout can be used.
// Operators configure: version_args, scan_args, output_format ("sarif" or "json").
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type customScanner struct {
	binaryPath   string
	versionArgs  []string
	scanArgs     []string
	outputFormat string // "sarif" or "json"
	timeout      time.Duration
}

func newCustomScanner(binaryPath string, versionArgs, scanArgs []string, outputFormat string, timeout time.Duration) Scanner {
	return &customScanner{
		binaryPath:   binaryPath,
		versionArgs:  versionArgs,
		scanArgs:     scanArgs,
		outputFormat: outputFormat,
		timeout:      timeout,
	}
}

func (s *customScanner) Name() string { return "custom" }

func (s *customScanner) Version(ctx context.Context) (string, error) {
	args := s.versionArgs
	if len(args) == 0 {
		args = []string{"--version"}
	}
	// #nosec G204
	out, err := exec.CommandContext(ctx, s.binaryPath, args...).Output()
	if err != nil {
		return "", fmt.Errorf("custom scanner version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *customScanner) ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	args := append(s.scanArgs, dir)
	// #nosec G204
	out, _ := exec.CommandContext(ctx, s.binaryPath, args...).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("custom scanner timed out after %s", s.timeout)
	}
	if len(out) == 0 {
		return &ScanResult{}, nil
	}

	switch strings.ToLower(s.outputFormat) {
	case "sarif":
		return parseSARIF(s.Name(), out)
	default:
		// Generic JSON: store raw, no severity parsing
		result := &ScanResult{RawJSON: json.RawMessage(out)}
		return result, nil
	}
}
