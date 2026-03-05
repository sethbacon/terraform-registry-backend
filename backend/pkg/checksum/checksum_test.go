package checksum

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
)

func TestCalculateSHA256(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// echo -n "hello" | sha256sum
			name:  "hello",
			input: "hello",
			want:  "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			// sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
			name:  "empty string",
			input: "",
			want:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			got, err := CalculateSHA256(reader)
			if err != nil {
				t.Fatalf("CalculateSHA256() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("CalculateSHA256(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}

	t.Run("same input produces same hash", func(t *testing.T) {
		h1, _ := CalculateSHA256(strings.NewReader("consistent-input"))
		h2, _ := CalculateSHA256(strings.NewReader("consistent-input"))
		if h1 != h2 {
			t.Error("CalculateSHA256() returned different hashes for the same input")
		}
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		h1, _ := CalculateSHA256(strings.NewReader("input-a"))
		h2, _ := CalculateSHA256(strings.NewReader("input-b"))
		if h1 == h2 {
			t.Error("CalculateSHA256() returned same hash for different inputs")
		}
	})

	t.Run("binary data", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
		got, err := CalculateSHA256(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("CalculateSHA256() error: %v", err)
		}
		if len(got) != 64 {
			t.Errorf("CalculateSHA256() returned %d-char hex string, want 64", len(got))
		}
	})

	t.Run("returns lowercase hex", func(t *testing.T) {
		got, _ := CalculateSHA256(strings.NewReader("test"))
		for _, c := range got {
			if c >= 'A' && c <= 'F' {
				t.Errorf("CalculateSHA256() returned uppercase hex: %q", got)
				return
			}
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, err := CalculateSHA256(errReader{})
		if err == nil {
			t.Error("CalculateSHA256() expected error from failing reader, got nil")
		}
	})
}

func TestVerifySHA256(t *testing.T) {
	t.Run("matching checksum returns true", func(t *testing.T) {
		data := "hello"
		// Pre-computed SHA256 of "hello"
		expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
		ok, err := VerifySHA256(strings.NewReader(data), expected)
		if err != nil {
			t.Fatalf("VerifySHA256() error: %v", err)
		}
		if !ok {
			t.Error("VerifySHA256() = false, want true for matching checksum")
		}
	})

	t.Run("wrong checksum returns false", func(t *testing.T) {
		ok, err := VerifySHA256(strings.NewReader("hello"), "0000000000000000000000000000000000000000000000000000000000000000")
		if err != nil {
			t.Fatalf("VerifySHA256() error: %v", err)
		}
		if ok {
			t.Error("VerifySHA256() = true, want false for mismatched checksum")
		}
	})

	t.Run("empty data matches known checksum", func(t *testing.T) {
		emptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		ok, err := VerifySHA256(strings.NewReader(""), emptyHash)
		if err != nil {
			t.Fatalf("VerifySHA256() error: %v", err)
		}
		if !ok {
			t.Error("VerifySHA256() = false for empty string with correct hash")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, err := VerifySHA256(errReader{}, "anyvalue")
		if err == nil {
			t.Error("VerifySHA256() expected error from failing reader, got nil")
		}
	})
}

// errReader is an io.Reader that always returns an error.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestHashZip(t *testing.T) {
	t.Run("invalid bytes return error", func(t *testing.T) {
		_, err := HashZip([]byte("not a zip file"))
		if err == nil {
			t.Error("HashZip() expected error for invalid zip bytes, got nil")
		}
	})

	t.Run("empty zip returns h1: prefix", func(t *testing.T) {
		zf := buildOrderedTestZip(t, nil)
		got, err := HashZip(zf)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		if !strings.HasPrefix(got, "h1:") {
			t.Errorf("HashZip() = %q, want h1: prefix", got)
		}
	})

	t.Run("result has valid base64 payload", func(t *testing.T) {
		zf := buildOrderedTestZip(t, [][2]string{{"hello.txt", "world"}})
		got, err := HashZip(zf)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		if !strings.HasPrefix(got, "h1:") {
			t.Fatalf("HashZip() = %q, want h1: prefix", got)
		}
		if _, err := base64.StdEncoding.DecodeString(got[len("h1:"):]); err != nil {
			t.Errorf("HashZip() base64 payload is invalid: %v", err)
		}
	})

	t.Run("deterministic — same zip yields same hash", func(t *testing.T) {
		zf := buildOrderedTestZip(t, [][2]string{{"a.txt", "alpha"}, {"b.txt", "beta"}})
		h1, err := HashZip(zf)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		h2, err := HashZip(zf)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		if h1 != h2 {
			t.Error("HashZip() returned different hashes for identical input")
		}
	})

	t.Run("zip entry order does not affect hash", func(t *testing.T) {
		// Two zips with same files but stored in opposite order inside the archive.
		zfAB := buildOrderedTestZip(t, [][2]string{{"a.txt", "alpha"}, {"b.txt", "beta"}})
		zfBA := buildOrderedTestZip(t, [][2]string{{"b.txt", "beta"}, {"a.txt", "alpha"}})
		hAB, err := HashZip(zfAB)
		if err != nil {
			t.Fatalf("HashZip() AB error: %v", err)
		}
		hBA, err := HashZip(zfBA)
		if err != nil {
			t.Fatalf("HashZip() BA error: %v", err)
		}
		if hAB != hBA {
			t.Errorf("HashZip() gave different hashes for same content in different zip order: %q vs %q", hAB, hBA)
		}
	})

	t.Run("different file content produces different hash", func(t *testing.T) {
		zA := buildOrderedTestZip(t, [][2]string{{"file.txt", "content-a"}})
		zB := buildOrderedTestZip(t, [][2]string{{"file.txt", "content-b"}})
		hA, err := HashZip(zA)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		hB, err := HashZip(zB)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		if hA == hB {
			t.Error("HashZip() returned same hash for different file content")
		}
	})

	t.Run("different file names produce different hash", func(t *testing.T) {
		zA := buildOrderedTestZip(t, [][2]string{{"a.txt", "same"}})
		zB := buildOrderedTestZip(t, [][2]string{{"b.txt", "same"}})
		hA, err := HashZip(zA)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		hB, err := HashZip(zB)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		if hA == hB {
			t.Error("HashZip() returned same hash for different file names")
		}
	})

	t.Run("matches dirhash reference implementation", func(t *testing.T) {
		// Cross-validate HashZip against an inline reference of the same algorithm.
		// This catches regressions without hard-coding a magic opaque base64 string.
		files := [][2]string{{"terraform-provider-example_v1.0.0", "binary content here"}, {"LICENSE", "MIT"}}
		zf := buildOrderedTestZip(t, files)
		got, err := HashZip(zf)
		if err != nil {
			t.Fatalf("HashZip() error: %v", err)
		}
		want := referenceDirhash(t, files)
		if got != want {
			t.Errorf("HashZip() = %q, want %q", got, want)
		}
	})
}

// buildOrderedTestZip creates a zip archive containing the given files in the
// exact order provided. Pass nil for an empty archive.
func buildOrderedTestZip(t *testing.T, files [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, kv := range files {
		f, err := w.Create(kv[0])
		if err != nil {
			t.Fatalf("buildOrderedTestZip: create %q: %v", kv[0], err)
		}
		if _, err := f.Write([]byte(kv[1])); err != nil {
			t.Fatalf("buildOrderedTestZip: write %q: %v", kv[0], err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("buildOrderedTestZip: close: %v", err)
	}
	return buf.Bytes()
}

// referenceDirhash is an inline implementation of the h1: dirhash algorithm
// used to cross-validate HashZip. It operates directly on string content
// rather than zip entries, so it is independent of HashZip's zip-reading path.
func referenceDirhash(t *testing.T, files [][2]string) string {
	t.Helper()
	names := make([]string, len(files))
	content := make(map[string]string, len(files))
	for i, kv := range files {
		names[i] = kv[0]
		content[kv[0]] = kv[1]
	}
	sort.Strings(names)
	outer := sha256.New()
	for _, name := range names {
		inner := sha256.New()
		inner.Write([]byte(content[name]))
		fmt.Fprintf(outer, "%x  %s\n", inner.Sum(nil), name)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(outer.Sum(nil))
}
