// sarif.go provides a SARIF 2.1.0 parser shared by the custom scanner.
// SARIF is an OASIS standard JSON format for static analysis results.
//
// Severity mapping:
//   - "error"   → high
//   - "warning" → medium
//   - "note"    → low
//   - "none"    → ignored
package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
)

// sarifLog is a minimal SARIF 2.1.0 document.
type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Results []sarifResult `json:"results"`
}

type sarifResult struct {
	Level string `json:"level"` // "error", "warning", "note", "none"
}

// parseSARIF parses a SARIF 2.1.0 JSON document and returns normalised counts.
func parseSARIF(scannerName string, data []byte) (*ScanResult, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("%s: failed to parse SARIF output: %w", scannerName, err)
	}

	result := &ScanResult{RawJSON: json.RawMessage(data)}
	for _, run := range log.Runs {
		for _, r := range run.Results {
			switch strings.ToLower(r.Level) {
			case "error":
				result.HighCount++
			case "warning":
				result.MediumCount++
			case "note":
				result.LowCount++
			}
		}
	}
	result.HasFindings = result.HighCount+result.MediumCount+result.LowCount > 0
	return result, nil
}
