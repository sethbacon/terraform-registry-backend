package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

// Issue #750 — the bundle parser had no entry cap and no cumulative budget.
//
// maxBundleBytes bounds the COMPRESSED archive only. gzip amplifies, so 50 MB
// of archive can encode far more than 50 MB of entries, and every .rego entry
// is retained in memory for the lifetime of the parse. Non-.rego entries were
// worse than unbounded — they were `continue`d, so their bodies were
// decompressed to reach the next header and accounted at nothing.
//
// Reachable from a hostile or compromised bundle host. The SHA-256 pin fails
// closed, but pinning is optional, so an unpinned deployment had no protection.

// tarGz builds a gzipped tar from (name, size) pairs. Bodies are zero bytes,
// which compress to almost nothing — that IS the amplification being tested.
func tarGz(t *testing.T, entries []struct {
	name string
	size int64
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Mode: 0o644, Size: e.size, Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("WriteHeader(%s): %v", e.name, err)
		}
		if _, err := tw.Write(make([]byte, e.size)); err != nil {
			t.Fatalf("Write(%s): %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func entriesOf(n int, name string, size int64) []struct {
	name string
	size int64
} {
	out := make([]struct {
		name string
		size int64
	}, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, struct {
			name string
			size int64
		}{fmt.Sprintf(name, i), size})
	}
	return out
}

func TestParseBundle_RejectsTooManyEntries(t *testing.T) {
	archive := tarGz(t, entriesOf(maxBundleEntries+1, "policy%d.rego", 0))

	// The compressed archive is tiny — that is the point. The old parser would
	// have walked every entry and retained every one.
	t.Logf("compressed archive: %d bytes for %d entries", len(archive), maxBundleEntries+1)

	if _, err := parseBundleTarGz(bytes.NewReader(archive)); err == nil {
		t.Fatal("an archive with more than maxBundleEntries entries was accepted")
	} else if !strings.Contains(err.Error(), "entries") {
		t.Errorf("error = %q, want it to name the entry cap", err)
	}
}

func TestParseBundle_RejectsCumulativeDecompressedSize(t *testing.T) {
	// Each entry is under the per-file cap; together they blow the budget.
	// The per-file limit alone never sees this.
	per := int64(maxRegoFileBytes)
	count := int(maxBundleDecompressedBytes/per) + 1
	if count > maxBundleEntries {
		t.Skipf("entry cap (%d) is reached before the byte budget with %d entries",
			maxBundleEntries, count)
	}
	archive := tarGz(t, entriesOf(count, "policy%d.rego", per))

	if _, err := parseBundleTarGz(bytes.NewReader(archive)); err == nil {
		t.Fatal("an archive exceeding the cumulative decompressed budget was accepted")
	} else if !strings.Contains(err.Error(), "decompresses") {
		t.Errorf("error = %q, want it to name the decompression budget", err)
	}
}

// TestParseBundle_ChargesSkippedEntries is the half the issue called out as
// worse than unbounded: entries the parser skips are still decompressed to
// reach the next header, and used to cost nothing.
//
// Every entry here is a NON-.rego file, so under the old accounting the parse
// was free no matter how large the archive claimed to be.
func TestParseBundle_ChargesSkippedEntries(t *testing.T) {
	per := int64(maxRegoFileBytes)
	count := int(maxBundleDecompressedBytes/per) + 1
	if count > maxBundleEntries {
		t.Skipf("entry cap reached first with %d entries", count)
	}
	archive := tarGz(t, entriesOf(count, "data%d.json", per))

	if _, err := parseBundleTarGz(bytes.NewReader(archive)); err == nil {
		t.Fatal("an archive of skipped (non-.rego) entries was accepted — skipped " +
			"entries must be charged against the budget, since reaching the next " +
			"header decompresses them anyway")
	}
}

// TestParseBundle_RejectsOversizedPolicyRatherThanTruncating.
//
// The previous per-file io.LimitReader(tr, 1<<20) silently cut a larger file
// off mid-source, so the bundle loaded as a POLICY THAT WAS NEVER WRITTEN. A
// truncation landing after an allow rule but before the deny that qualifies it
// inverts the outcome, with nothing in the logs to say so.
func TestParseBundle_RejectsOversizedPolicyRatherThanTruncating(t *testing.T) {
	archive := tarGz(t, []struct {
		name string
		size int64
	}{{"big.rego", maxRegoFileBytes + 1}})

	files, err := parseBundleTarGz(bytes.NewReader(archive))
	if err == nil {
		t.Fatalf("oversized policy file was accepted, returning %d file(s) — a "+
			"truncated policy is not the policy the operator wrote", len(files))
	}
	if !strings.Contains(err.Error(), "big.rego") {
		t.Errorf("error = %q, want it to name the offending file", err)
	}
}

// TestParseBundle_AcceptsARealisticBundle is the other direction: the limits
// must not reject ordinary bundles, or they get raised until meaningless.
func TestParseBundle_AcceptsARealisticBundle(t *testing.T) {
	archive := tarGz(t, []struct {
		name string
		size int64
	}{
		{"policies/upload.rego", 4096},
		{"policies/naming.rego", 2048},
		{"data.json", 1024}, // skipped, but charged
		{"README.md", 512},  // skipped
		{"policies/limits.rego", 8192},
	})

	files, err := parseBundleTarGz(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("a realistic bundle was rejected: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("got %d .rego files, want 3: %+v", len(files), files)
	}
	for _, f := range files {
		if !strings.HasSuffix(f.name, ".rego") {
			t.Errorf("non-.rego file retained: %s", f.name)
		}
	}
}

// TestParseBundle_ExactLimitsAreAccepted pins the boundary: a file of exactly
// maxRegoFileBytes is legal, one byte more is not.
func TestParseBundle_ExactLimitsAreAccepted(t *testing.T) {
	archive := tarGz(t, []struct {
		name string
		size int64
	}{{"exact.rego", maxRegoFileBytes}})

	files, err := parseBundleTarGz(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("a policy file of exactly the limit was rejected: %v", err)
	}
	if len(files) != 1 || int64(len(files[0].source)) != maxRegoFileBytes {
		t.Errorf("got %d file(s); source length = %d, want %d",
			len(files), len(files[0].source), maxRegoFileBytes)
	}
}
