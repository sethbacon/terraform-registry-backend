package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const skipSample = `package sample

import "context"

// Regular returns the input doubled.
func Regular(x int) int {
	return x * 2
}

// Integration is marked skip.
// coverage:skip:integration-only — fake reason
func Integration(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// DBDependent also skipped.
// coverage:skip:requires-database
func DBDependent() int {
	return 1
}
`

// Simulated coverage profile — line ranges for each function.
// Regular is at lines 6-8, Integration at 12-17, DBDependent at 21-23.
const profileSample = `mode: atomic
example.com/sample/sample.go:6.20,8.2 1 5
example.com/sample/sample.go:12.36,13.18 1 0
example.com/sample/sample.go:13.18,15.3 1 0
example.com/sample/sample.go:16.2,16.19 1 0
example.com/sample/sample.go:21.21,23.2 1 0
`

func TestCoverFilter_StripsMarkedFunctions(t *testing.T) {
	tmp := t.TempDir()
	// Place the sample file under a "sample" subdirectory so the profile's
	// module path (example.com/sample/sample.go) shares its last two path
	// segments with the absolute filesystem path. pathSuffixMatches requires
	// at least package+file agreement to avoid bare-filename false positives.
	pkgDir := filepath.Join(tmp, "sample")
	if err := os.MkdirAll(pkgDir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	srcPath := filepath.Join(pkgDir, "sample.go")
	if err := os.WriteFile(srcPath, []byte(skipSample), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	inPath := filepath.Join(tmp, "in.cov")
	outPath := filepath.Join(tmp, "out.cov")
	if err := os.WriteFile(inPath, []byte(profileSample), 0600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	// Reuse the exported helpers by calling them directly.
	skips, err := collectSkipRanges(tmp)
	if err != nil {
		t.Fatalf("collectSkipRanges: %v", err)
	}
	if len(skips) != 1 {
		t.Fatalf("want 1 file with skips, got %d: %v", len(skips), skips)
	}
	ranges := skips[srcPath]
	if len(ranges) != 2 {
		t.Fatalf("want 2 skip ranges (Integration + DBDependent), got %d: %v", len(ranges), ranges)
	}

	// Exercise shouldStrip on each profile line.
	lines := strings.Split(strings.TrimSpace(profileSample), "\n")[1:] // skip header
	stripped := 0
	for _, line := range lines {
		if shouldStrip(line, skips) {
			stripped++
		}
	}
	// Integration occupies 3 blocks (12-13, 13-15, 16-16); DBDependent is 1 block. 4 total.
	if stripped != 4 {
		t.Errorf("stripped = %d, want 4 (Integration's 3 blocks + DBDependent's 1)", stripped)
	}

	_ = outPath
}

func TestPathSuffixMatches(t *testing.T) {
	tests := []struct {
		abs, mod string
		want     bool
	}{
		{"/home/alice/proj/internal/api/router.go", "github.com/acme/proj/internal/api/router.go", true},
		{"C:/dev/repo/backend/internal/auth/provider.go", "github.com/foo/bar/internal/auth/provider.go", true},
		{"C:\\dev\\repo\\backend\\internal\\auth\\provider.go", "github.com/foo/bar/internal/auth/provider.go", true},
		{"/tmp/other/file.go", "github.com/foo/bar/internal/api/router.go", false},
		{"/home/alice/proj/other/router.go", "github.com/acme/proj/internal/api/router.go", false},
	}
	for _, tt := range tests {
		got := pathSuffixMatches(tt.abs, tt.mod)
		if got != tt.want {
			t.Errorf("pathSuffixMatches(%q, %q) = %v, want %v", tt.abs, tt.mod, got, tt.want)
		}
	}
}

func TestShouldStrip_MalformedLines(t *testing.T) {
	skips := map[string][]skipRange{}
	for _, line := range []string{
		"",
		"not a coverage line",
		"path/to/file.go:no-range-here 1 0",
		"path/to/file.go:invalid 1 0",
	} {
		if shouldStrip(line, skips) {
			t.Errorf("shouldStrip(%q) = true, want false for malformed line", line)
		}
	}
}
