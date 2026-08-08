package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Issue #737: TFR_JWT_SECRET_FILE hot-rotation was documented in
// docs/secrets-rotation.md as the recommended zero-downtime path, wired into the
// Helm chart, fully implemented in auth.StartJWTSecretFileWatch -- and started
// by nobody. Setting the variable did nothing at all.
//
// Two things are tested here, and the second is the one that matters. A unit
// test of the overlap parser would have passed just as happily while the watch
// was never started, because the defect was not in any function's logic; it was
// the absence of a call. So the wiring itself is asserted, structurally.

func TestJWTSecretOverlap(t *testing.T) {
	const def = 5 * time.Minute

	tests := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"unset falls back to the documented default", "", def},
		{"whitespace only is unset", "   ", def},
		{"a valid duration is honoured", "90s", 90 * time.Second},
		{"minutes", "10m", 10 * time.Minute},
		{"surrounding whitespace is trimmed", "  2m  ", 2 * time.Minute},
		// Not an error: the overlap only widens the window in which an OLD key
		// still validates, so a bad value cannot open access the current key
		// does not already grant. Refusing to boot over it would trade a
		// harmless typo for an outage.
		{"unparseable falls back rather than failing", "banana", def},
		{"zero falls back", "0s", def},
		{"negative falls back", "-5m", def},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jwtSecretOverlap(tt.raw); got != tt.want {
				t.Errorf("jwtSecretOverlap(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestJWTSecretFileWatchIsStarted is the guard for the actual defect.
//
// It reads main.go and asserts that serve() both reads TFR_JWT_SECRET_FILE and
// calls auth.StartJWTSecretFileWatch. A behavioural test cannot cover this:
// serve() opens listeners and databases, and the failure mode is not a wrong
// answer from a function but a function nobody invokes -- which is invisible to
// every test that does not look for the call site.
//
// This is the same shape as the defect: something documented, implemented and
// never reached. If the call is deleted or refactored out, this fails and says
// so, instead of the feature silently going back to doing nothing.
func TestJWTSecretFileWatchIsStarted(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)

	for _, want := range []string{
		`os.Getenv("TFR_JWT_SECRET_FILE")`,
		"auth.StartJWTSecretFileWatch(",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("main.go no longer contains %s -- TFR_JWT_SECRET_FILE is documented "+
				"in docs/secrets-rotation.md as the recommended zero-downtime rotation "+
				"path, and without this call setting it does nothing (issue #737)", want)
		}
	}

	// The call must be reachable from serve(), not merely present somewhere in
	// the file -- a call parked in a helper nothing invokes is the same defect.
	serveBody := funcBody(text, "func serve(cfg *config.Config) error {")
	if serveBody == "" {
		t.Fatal("could not locate serve() in main.go; this guard cannot verify anything")
	}
	if !strings.Contains(serveBody, "auth.StartJWTSecretFileWatch(") {
		t.Error("auth.StartJWTSecretFileWatch is not called from serve(); the watch " +
			"only runs if the server startup path starts it (issue #737)")
	}

	// Fail-closed: a read/watch failure must abort startup rather than fall back
	// to the env secret while the operator believes rotation is live.
	if !regexp.MustCompile(`TFR_JWT_SECRET_FILE is set but`).MatchString(serveBody) {
		t.Error("the watch failure path no longer aborts startup; booting with the env " +
			"secret after the operator asked for file-based secrets reintroduces #737 " +
			"by another route")
	}
}

// funcBody returns the source between header and the next top-level closing
// brace, or "" if the header is absent.
func funcBody(src, header string) string {
	i := strings.Index(src, header)
	if i < 0 {
		return ""
	}
	rest := src[i+len(header):]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j]
	}
	return rest
}
