package maintenance

// uncovered_wiring_class_test.go guards the WIRING, not the report.
//
// uncovered_test.go proves ReportUncovered counts the right rows. It says
// nothing about whether anyone calls it -- and an uncalled report is exactly the
// silence #878 is about, restored, while every other test stays green. That is
// the shape of an inert guard: correct machinery nothing invokes.
//
// Checked at the source level because the thing being asserted is a wiring fact
// about a command, and the alternative (execute the command against a real
// database) tests the report a second time rather than the wiring once.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryRekeySecretsRunReportsUncoveredColumns asserts the operator-facing
// rekey command still tells the operator what it does not certify.
//
// BOTH MODES, deliberately. A re-encrypt run is where an operator forms the
// belief that everything has been converted, so restricting the report to
// `verify` would leave the more dangerous half silent.
func TestEveryRekeySecretsRunReportsUncoveredColumns(t *testing.T) {
	const cmd = "../../cmd/server/main.go"
	b, err := os.ReadFile(cmd)
	if err != nil {
		t.Fatalf("read %s: %v", cmd, err)
	}
	body, ok := funcBody(string(b), "runRekeySecrets")
	if !ok {
		t.Fatalf("runRekeySecrets not found in %s.\n"+
			"If it was renamed or moved, point this guard at the new one -- do not delete it: "+
			"it is the only thing keeping `rekey-secrets` from going silent about its uncovered columns again.",
			filepath.Base(cmd))
	}
	if !strings.Contains(body, "maintenance.ReportUncovered(") {
		t.Errorf("runRekeySecrets does not call maintenance.ReportUncovered.\n" +
			"Both `rekey-secrets` and `rekey-secrets verify` must print the population of every column " +
			"the sweep does not convert (#878). Without it an operator sees a zero exit, drops " +
			"ENCRYPTION_KEY_PREVIOUS, and leaves unrefreshed user SCM links unreadable.")
	}
	// The count is only useful if it is loud. slog.Info scrolls past in a
	// deploy log; the whole point is that a non-zero count interrupts someone.
	if !regexp.MustCompile(`slog\.Warn\(\s*"rekey-secrets: rows NOT covered`).MatchString(body) {
		t.Errorf("the non-zero uncovered-row count is not reported at WARN.\n" +
			"An operator about to delete a key reads warnings; they scroll past info lines.")
	}

	// AND THE REPORT MUST NOT BE GATED ON THE MODE.
	//
	// Asserting the call merely EXISTS was provably inert: wrapping the loop in
	// `if verify` kept it present, kept the WARN literal present, kept this test
	// green, and silenced the re-encrypt run -- the run where an operator forms
	// the belief that everything has been converted. docs/secrets-rotation.md
	// tells operators both runs print the counts, so that is the property.
	//
	// Checked as "the mode flag is not referenced from the report onward",
	// which is exactly what "unconditional" means here and does not depend on
	// how the branch is spelled.
	if i := strings.Index(body, "maintenance.ReportUncovered("); i >= 0 {
		// Strip string literals first. The log lines legitimately contain the
		// word "verify" ("a green verify does not certify these rows"), and
		// matching inside them made this fire on correct code -- a guard that
		// cries wolf gets deleted, which is how the property would be lost.
		tail := stripGoStrings(body[i:])
		if regexp.MustCompile(`\bverify\b`).MatchString(tail) {
			t.Errorf("the uncovered-column report is gated on the `verify` flag.\n"+
				"It must run in BOTH modes: docs/secrets-rotation.md promises the counts on the "+
				"re-encrypt run too, and that is the run that convinces an operator the sweep was "+
				"total. Offending code:\n%s", strings.TrimSpace(tail))
		}
	}
}

// stripGoStrings blanks the contents of interpreted and raw string literals,
// preserving offsets so an excerpt still reads sensibly.
func stripGoStrings(src string) string {
	out := []byte(src)
	for i := 0; i < len(out); i++ {
		var closer byte
		switch out[i] {
		case '"':
			closer = '"'
		case '`':
			closer = '`'
		default:
			continue
		}
		j := i + 1
		for j < len(out) {
			if closer == '"' && out[j] == '\\' {
				j += 2
				continue
			}
			if out[j] == closer {
				break
			}
			out[j] = ' '
			j++
		}
		i = j
	}
	return string(out)
}

// funcBody returns the body of the named top-level func, matched by brace depth.
//
// Brace counting rather than a regex to the closing brace: the body contains
// braces, and a lazy match would stop at the first one and let the assertions
// pass against a fragment.
func funcBody(src, name string) (string, bool) {
	i := strings.Index(src, "\nfunc "+name+"(")
	if i < 0 {
		return "", false
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return "", false
	}
	start := i + open
	depth := 0
	for j := start; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : j+1], true
			}
		}
	}
	return "", false
}
