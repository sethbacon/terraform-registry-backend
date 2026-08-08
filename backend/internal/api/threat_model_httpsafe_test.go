package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Issue #762: docs/threat-model.md recorded I-8 as
// "⚠️ Partial — not yet routed through `httpsafe`" for the suite proxy in
// suite.go, months after suite.go started using httpsafe.NewClient.
//
// This is the inverse of the usual documentation defect — the doc UNDERSTATES
// the mitigation — but it is still a compliance artifact that is wrong. An
// auditor reading it records an open SSRF gap that does not exist, and a
// reviewer trusting the doc over the code re-verifies an item that was closed.
//
// The issue asked for the row to be corrected AND for something to keep it in
// sync. This is that something, generalised: no row may claim a file is not
// routed through httpsafe while that file demonstrably calls it. The rule holds
// for any future row of the same shape, not just I-8.
//
// It deliberately checks only the one direction that can be established from
// the source. "Claims routed, actually is not" would require deciding which
// call sites a row covers, which is a judgement the file cannot answer — so
// this guard does not pretend to.

// notRoutedClaim matches a threat-model assertion that something is NOT routed
// through httpsafe, in the phrasings the document actually uses.
var notRoutedClaim = regexp.MustCompile(`(?i)(not yet routed through|does not (?:use|go through)|rather than the centrali[sz]ed)\s*` + "`?httpsafe`?")

// goFileRef finds backtick-quoted Go filenames in a table row, e.g. `suite.go`.
var goFileRef = regexp.MustCompile("`([a-z0-9_]+\\.go)`")

func TestThreatModelDoesNotUnderstateHTTPSafeCoverage(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "threat-model.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("threat model not readable at %s: %v", path, err)
	}

	var rows []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			rows = append(rows, line)
		}
	}
	// An empty scan would make the assertions below vacuous. The document is a
	// table; finding no table rows means the parse is wrong, not that the
	// document is clean.
	if len(rows) == 0 {
		t.Fatalf("found no table rows in %s; this guard is proving nothing", path)
	}

	for _, row := range rows {
		if !notRoutedClaim.MatchString(row) {
			continue
		}
		for _, m := range goFileRef.FindAllStringSubmatch(row, -1) {
			name := m[1]
			hits := filesCallingHTTPSafe(t, name)
			if len(hits) > 0 {
				t.Errorf("threat-model.md claims %s is not routed through httpsafe, but "+
					"it calls httpsafe here: %s. Update the row's status (issue #762) — a "+
					"compliance artifact that understates a mitigation still misstates the "+
					"system.\n  row: %s", name, strings.Join(hits, ", "), strings.TrimSpace(row))
			}
		}
	}
}

// filesCallingHTTPSafe returns the paths of files named `name` under backend/
// that reference httpsafe.
func filesCallingHTTPSafe(t *testing.T, name string) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	var hits []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Name() != name || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(src), "httpsafe.") {
			hits = append(hits, path)
		}
		return nil
	})
	return hits
}
