package archiver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTarGz creates an in-memory tar.gz archive from a map of path→content.
func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func buildTarGzWithDir(t *testing.T, dirEntry string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Write the directory entry
	hdr := &tar.Header{
		Name:     dirEntry,
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar WriteHeader dir: %v", err)
	}

	for name, content := range files {
		fhdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(fhdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// ExtractTarGz
// ---------------------------------------------------------------------------

func TestExtractTarGz_Simple(t *testing.T) {
	data := buildTarGz(t, map[string]string{
		"main.tf":    `resource "null_resource" "x" {}`,
		"outputs.tf": `output "x" { value = "y" }`,
	})

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	for _, name := range []string{"main.tf", "outputs.tf"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestExtractTarGz_WithSubDirectory(t *testing.T) {
	data := buildTarGzWithDir(t, "module-v1.2.3/", map[string]string{
		"module-v1.2.3/main.tf":    `variable "x" {}`,
		"module-v1.2.3/outputs.tf": `output "x" { value = var.x }`,
	})

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "module-v1.2.3", "main.tf")); err != nil {
		t.Errorf("expected nested file to exist: %v", err)
	}
}

func TestExtractTarGz_Empty(t *testing.T) {
	data := buildTarGz(t, map[string]string{})
	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("empty archive should not error: %v", err)
	}
}

func TestExtractTarGz_InvalidGzip(t *testing.T) {
	if err := ExtractTarGz(bytes.NewReader([]byte("not gzip")), t.TempDir()); err == nil {
		t.Error("expected error for invalid gzip, got nil")
	}
}

func TestExtractTarGz_PathTraversal(t *testing.T) {
	// Build archive with a path traversal entry
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := "evil"
	_ = tw.WriteHeader(&tar.Header{
		Name: "../../../evil.txt",
		Mode: 0644,
		Size: int64(len(content)),
	})
	_, _ = tw.Write([]byte(content))
	_ = tw.Close()
	_ = gw.Close()

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest); err == nil {
		t.Error("expected path traversal error, got nil")
	}
}

// Issue #566 finding [46]: the 100MB cumulative decompression cap was never
// exercised by any test — assert a single entry exceeding it is rejected.
func TestExtractTarGz_ExceedsExtractionCap(t *testing.T) {
	oversized := bytes.Repeat([]byte("A"), maxExtractBytes+1)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "huge.bin", Mode: 0644, Size: int64(len(oversized))}); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if _, err := tw.Write(oversized); err != nil {
		t.Fatalf("tar Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	dest := t.TempDir()
	err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest)
	if err == nil {
		t.Fatal("expected extraction-size-limit error, got nil")
	}
	if !strings.Contains(err.Error(), "extraction size limit") {
		t.Errorf("error = %q, want it to mention the extraction size limit", err.Error())
	}
}

// Issue #566 finding [46]: TestExtractTarGz_ExceedsExtractionCap (above) only proves
// a single oversized entry is rejected — that alone would also pass a naive per-entry
// size check (e.g. "if header.Size > maxExtractBytes"). This test proves the cap is
// tracked cumulatively across MANY entries that are each individually tiny relative to
// the cap, closing the cumulative-sum-bypass gap.
func TestExtractTarGz_ExceedsExtractionCap_CumulativeSmallEntries(t *testing.T) {
	const entrySize = 1 << 20 // 1 MB per entry — 1% of the 100 MB cap, individually
	const entryCount = 150    // 150 MB total, comfortably over the cap

	chunk := bytes.Repeat([]byte("B"), entrySize)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for i := 0; i < entryCount; i++ {
		name := fmt.Sprintf("file-%03d.bin", i)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(chunk))}); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write(chunk); err != nil {
			t.Fatalf("tar Write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	dest := t.TempDir()
	err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest)
	if err == nil {
		t.Fatal("expected extraction-size-limit error from cumulative small entries, got nil")
	}
	if !strings.Contains(err.Error(), "extraction size limit") {
		t.Errorf("error = %q, want it to mention the extraction size limit", err.Error())
	}

	// Confirm extraction actually stopped partway through instead of writing all
	// 150 MB to disk — a naive per-entry check would let every entry through since
	// each is individually far under the cap.
	var totalOnDisk int64
	var fileCount int
	walkErr := filepath.WalkDir(dest, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		fileCount++
		totalOnDisk += info.Size()
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk dest: %v", walkErr)
	}
	if fileCount >= entryCount {
		t.Errorf("expected extraction to stop before all %d entries were written, found %d files", entryCount, fileCount)
	}
	if totalOnDisk >= int64(entryCount)*int64(entrySize) {
		t.Errorf("expected extraction to stop before writing all %d bytes to disk, found %d bytes", int64(entryCount)*int64(entrySize), totalOnDisk)
	}
	if totalOnDisk > maxExtractBytes+entrySize {
		t.Errorf("extraction wrote %d bytes, more than one entry past the %d-byte cap", totalOnDisk, int64(maxExtractBytes))
	}
}

// Issue #566 finding [46]: tar.TypeSymlink entries have no case in ExtractTarGz's
// switch (no default), so they are silently no-op'd — assert that's actually true
// and no symlink is ever created on disk, even one whose target would escape destDir.
func TestExtractTarGz_SymlinkEntryIgnored(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "evil-link",
		Typeflag: tar.TypeSymlink,
		Linkname: "../../../etc/passwd",
		Mode:     0777,
	}); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest); err != nil {
		t.Fatalf("ExtractTarGz should not error on a symlink entry: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "evil-link")); err == nil {
		t.Error("symlink entry should not have been created on disk")
	}
}

// Issue #566 finding [46]: same gap as TestExtractTarGz_SymlinkEntryIgnored but for
// tar.TypeLink (hardlink) entries — also has no case in ExtractTarGz's switch, so it
// must be silently no-op'd rather than ever creating a link on disk.
func TestExtractTarGz_HardlinkEntryIgnored(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "evil-hardlink",
		Typeflag: tar.TypeLink,
		Linkname: "../../../etc/passwd",
		Mode:     0644,
	}); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest); err != nil {
		t.Fatalf("ExtractTarGz should not error on a hardlink entry: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "evil-hardlink")); err == nil {
		t.Error("hardlink entry should not have been created on disk")
	}
}

func TestExtractTarGz_FileContents(t *testing.T) {
	const tfContent = `variable "region" { default = "us-east-1" }`
	data := buildTarGz(t, map[string]string{"variables.tf": tfContent})

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "variables.tf"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != tfContent {
		t.Errorf("file content = %q, want %q", got, tfContent)
	}
}

// seedTarGzBytes builds a minimal valid tar.gz archive from name->content pairs, for
// use as fuzz seed corpus. Fuzz seeds are registered outside of any *testing.T (via
// *testing.F, in the body of the Fuzz function itself, before f.Fuzz is called), so
// this mirrors buildTarGz above without requiring one; write errors are ignored since
// they can't realistically occur against an in-memory bytes.Buffer.
func seedTarGzBytes(files map[string]string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content))})
		_, _ = tw.Write([]byte(content))
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// Issue #566 finding [46]: FuzzExtractTarGz feeds arbitrary bytes through
// ExtractTarGz and asserts it never panics and never writes anything outside
// destDir, regardless of how malformed the input is. ExtractTarGz's own path
// containment check (see the filepath.Rel logic in tarball.go) means a
// well-behaved run either errors out before writing an escaping entry, or
// succeeds having only ever written inside destDir — so containment is
// verified here by walking destDir's *parent* after each run and failing if
// anything landed outside destDir.
func FuzzExtractTarGz(f *testing.F) {
	f.Add(seedTarGzBytes(map[string]string{"main.tf": `resource "null_resource" "x" {}`}))
	f.Add(seedTarGzBytes(map[string]string{"../../../evil.txt": "evil"}))
	f.Add([]byte{})
	f.Add([]byte("not a gzip stream at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		dest := filepath.Join(parent, "extract")

		// The return value is intentionally not asserted on: malformed input is
		// expected to produce an error and that's fine. What matters is that
		// ExtractTarGz never panics (a panic fails the fuzz run on its own) and
		// never escapes destDir, whether it errors or not.
		_ = ExtractTarGz(bytes.NewReader(data), dest)

		// Walking a fixed ancestor (e.g. parent) only catches escapes that land
		// exactly at that level -- a "../../../evil.txt" entry can climb past
		// any fixed ancestor entirely and go undetected by a directory walk.
		// Instead, independently re-parse the same input the way ExtractTarGz
		// does and, for every entry, compute the exact naive (unsanitized)
		// destination path; if that path resolves outside dest, assert nothing
		// was actually written there -- this targets precisely where a
		// malicious entry claims it wants to escape to, at any depth, without
		// needing to bound how far up the filesystem to search.
		for _, name := range tarEntryNames(data) {
			wouldBePath := filepath.Clean(filepath.Join(dest, name))
			rel, relErr := filepath.Rel(dest, wouldBePath)
			escapes := relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
			if !escapes {
				continue
			}
			if _, statErr := os.Lstat(wouldBePath); !os.IsNotExist(statErr) {
				t.Fatalf("ExtractTarGz wrote outside destDir for entry %q: found at %s", name, wouldBePath)
			}
		}
	})
}

// tarEntryNames re-parses a tar.gz byte stream the same way ExtractTarGz does
// and returns every entry's raw (unsanitized) name, or nil if the stream
// isn't a valid tar.gz -- used by FuzzExtractTarGz to independently determine
// which paths a malicious archive targets, without trusting ExtractTarGz's
// own accounting of what it wrote.
func tarEntryNames(data []byte) []string {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			return names
		}
		names = append(names, hdr.Name)
	}
}

// ---------------------------------------------------------------------------
// FindModuleRoot
// ---------------------------------------------------------------------------

func TestFindModuleRoot_NoSubdir(t *testing.T) {
	dir := t.TempDir()
	// Write a .tf file directly in the directory
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`variable "x" {}`), 0644); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != dir {
		t.Errorf("FindModuleRoot = %q, want %q", got, dir)
	}
}

func TestFindModuleRoot_SingleSubdirWithTf(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "terraform-module-abc123")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "main.tf"), []byte(`variable "x" {}`), 0644); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != sub {
		t.Errorf("FindModuleRoot = %q, want %q", got, sub)
	}
}

func TestFindModuleRoot_SingleSubdirWithoutTf(t *testing.T) {
	// Single subdirectory but no .tf files — should return the root
	dir := t.TempDir()
	sub := filepath.Join(dir, "not-a-module")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "README.md"), []byte("# readme"), 0644); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != dir {
		t.Errorf("FindModuleRoot = %q, want %q (should not unwrap when no .tf files)", got, dir)
	}
}

func TestFindModuleRoot_MultipleEntries(t *testing.T) {
	// Multiple entries — should return the root unchanged
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "b"), 0755); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != dir {
		t.Errorf("FindModuleRoot = %q, want %q", got, dir)
	}
}

func TestFindModuleRoot_NonExistentDir(t *testing.T) {
	got := FindModuleRoot("/nonexistent/path/xyz")
	if got != "/nonexistent/path/xyz" {
		t.Errorf("FindModuleRoot for non-existent path = %q, want original path", got)
	}
}
