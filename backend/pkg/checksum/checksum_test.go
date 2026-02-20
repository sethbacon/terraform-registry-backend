package checksum

import (
	"bytes"
	"io"
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
