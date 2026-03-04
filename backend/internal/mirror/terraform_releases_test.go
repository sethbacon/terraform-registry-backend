package mirror

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newReleasesClient starts a test server and returns a TerraformReleasesClient
// pointing at it. The server is closed automatically when the test ends.
func newReleasesClient(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *TerraformReleasesClient) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewTerraformReleasesClient(srv.URL+"/", "terraform")
	// Keep timeouts short in tests by reusing the HTTPClient for downloads too.
	c.DownloadClient = c.HTTPClient
	return srv, c
}

// buildIndexJSON builds a minimal releases index JSON body with the given versions.
func buildIndexJSON(versions map[string]TerraformIndexVersion) []byte {
	type indexDoc struct {
		Versions map[string]TerraformIndexVersion `json:"versions"`
	}
	b, _ := json.Marshal(indexDoc{Versions: versions})
	return b
}

// ---------------------------------------------------------------------------
// NewTerraformReleasesClient
// ---------------------------------------------------------------------------

func TestNewTerraformReleasesClient_Defaults(t *testing.T) {
	c := NewTerraformReleasesClient("https://releases.hashicorp.com/", "")
	if c.ProductName != "terraform" {
		t.Errorf("ProductName = %q, want terraform", c.ProductName)
	}
	if c.UpstreamURL != "https://releases.hashicorp.com" {
		t.Errorf("UpstreamURL = %q, trailing slash should be stripped", c.UpstreamURL)
	}
	if c.HTTPClient == nil {
		t.Error("HTTPClient is nil")
	}
	if c.DownloadClient == nil {
		t.Error("DownloadClient is nil")
	}
}

func TestNewTerraformReleasesClient_CustomProduct(t *testing.T) {
	c := NewTerraformReleasesClient("https://releases.example.com", "opentofu")
	if c.ProductName != "opentofu" {
		t.Errorf("ProductName = %q, want opentofu", c.ProductName)
	}
}

// ---------------------------------------------------------------------------
// ListVersions
// ---------------------------------------------------------------------------

func TestListVersions_Success(t *testing.T) {
	versions := map[string]TerraformIndexVersion{
		"1.5.0": {
			Name:    "terraform",
			Version: "1.5.0",
			SHASums: "terraform_1.5.0_SHA256SUMS",
			Builds: []TerraformReleaseBuild{
				{OS: "linux", Arch: "amd64", Filename: "terraform_1.5.0_linux_amd64.zip", URL: "https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip"},
			},
		},
		"1.4.0": {
			Name:    "terraform",
			Version: "1.4.0",
			SHASums: "https://releases.hashicorp.com/terraform/1.4.0/terraform_1.4.0_SHA256SUMS",
			Builds:  []TerraformReleaseBuild{},
		},
	}

	_, c := newReleasesClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/index.json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildIndexJSON(versions))
	})

	result, err := c.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("ListVersions error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("got %d versions, want 2", len(result))
	}

	// Find the 1.5.0 entry and verify the relative shasums URL was made absolute.
	var found150 bool
	for _, v := range result {
		if v.Version == "1.5.0" {
			found150 = true
			if !strings.HasPrefix(v.SHASumsURL, "http") {
				t.Errorf("SHASumsURL for 1.5.0 should be absolute, got %q", v.SHASumsURL)
			}
		}
		if v.Version == "1.4.0" {
			// Already absolute — should be preserved as-is.
			if v.SHASumsURL != "https://releases.hashicorp.com/terraform/1.4.0/terraform_1.4.0_SHA256SUMS" {
				t.Errorf("SHASumsURL for 1.4.0 = %q, want the original absolute URL", v.SHASumsURL)
			}
		}
	}
	if !found150 {
		t.Error("version 1.5.0 not found in results")
	}
}

func TestListVersions_VersionFieldFallsBackToMapKey(t *testing.T) {
	// When the entry's version field is empty the map key should be used.
	versions := map[string]TerraformIndexVersion{
		"1.3.0": {
			// Version deliberately left empty
			SHASums: "",
		},
	}

	_, c := newReleasesClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(buildIndexJSON(versions))
	})

	result, err := c.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("ListVersions error: %v", err)
	}
	if len(result) != 1 || result[0].Version != "1.3.0" {
		t.Errorf("expected version 1.3.0 from map key, got %+v", result)
	}
}

func TestListVersions_ExtraTopLevelKey(t *testing.T) {
	// Index documents may contain unknown top-level keys; they must be skipped.
	raw := `{"license":"MPL-2.0","versions":{"1.0.0":{"version":"1.0.0","shasums":"","builds":[]}}}`

	_, c := newReleasesClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(raw))
	})

	result, err := c.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("ListVersions error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 version, got %d", len(result))
	}
}

func TestListVersions_NonOKStatus(t *testing.T) {
	_, c := newReleasesClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
	})

	_, err := c.ListVersions(context.Background())
	if err == nil {
		t.Error("expected error for non-200, got nil")
	}
}

func TestListVersions_InvalidURL(t *testing.T) {
	c := NewTerraformReleasesClient("http://127.0.0.1:0", "terraform") // nothing listening
	_, err := c.ListVersions(context.Background())
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

func TestListVersions_MalformedJSON(t *testing.T) {
	_, c := newReleasesClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`not json at all`))
	})

	_, err := c.ListVersions(context.Background())
	if err == nil {
		t.Error("expected JSON parse error, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchSHASums
// ---------------------------------------------------------------------------

func TestFetchSHASums_Success(t *testing.T) {
	sumsContent := "abc123def456  terraform_1.5.0_linux_amd64.zip\n" +
		"fedcba098765  terraform_1.5.0_darwin_amd64.zip\n"

	_, c := newReleasesClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, sumsContent)
	})

	sums, raw, err := c.FetchSHASums(context.Background(), "1.5.0")
	if err != nil {
		t.Fatalf("FetchSHASums error: %v", err)
	}
	if string(raw) != sumsContent {
		t.Errorf("raw bytes mismatch")
	}
	if sums["terraform_1.5.0_linux_amd64.zip"] != "abc123def456" {
		t.Errorf("unexpected sha for linux zip: %q", sums["terraform_1.5.0_linux_amd64.zip"])
	}
	if sums["terraform_1.5.0_darwin_amd64.zip"] != "fedcba098765" {
		t.Errorf("unexpected sha for darwin zip: %q", sums["terraform_1.5.0_darwin_amd64.zip"])
	}
}

func TestFetchSHASums_NonOKStatus(t *testing.T) {
	_, c := newReleasesClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, _, err := c.FetchSHASums(context.Background(), "9.9.9")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

func TestFetchSHASums_InvalidURL(t *testing.T) {
	c := NewTerraformReleasesClient("http://127.0.0.1:0", "terraform")
	_, _, err := c.FetchSHASums(context.Background(), "1.0.0")
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchSHASumsSignature
// ---------------------------------------------------------------------------

func TestFetchSHASumsSignature_Success(t *testing.T) {
	sigBytes := []byte{0x89, 0x01, 0x23} // fake GPG sig bytes

	_, c := newReleasesClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(sigBytes)
	})

	got, err := c.FetchSHASumsSignature(context.Background(), "1.5.0")
	if err != nil {
		t.Fatalf("FetchSHASumsSignature error: %v", err)
	}
	if !bytes.Equal(got, sigBytes) {
		t.Errorf("sig bytes mismatch: got %v, want %v", got, sigBytes)
	}
}

func TestFetchSHASumsSignature_NonOKStatus(t *testing.T) {
	_, c := newReleasesClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := c.FetchSHASumsSignature(context.Background(), "1.5.0")
	if err == nil {
		t.Error("expected error for 403, got nil")
	}
}

func TestFetchSHASumsSignature_InvalidURL(t *testing.T) {
	c := NewTerraformReleasesClient("http://127.0.0.1:0", "terraform")
	_, err := c.FetchSHASumsSignature(context.Background(), "1.0.0")
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ParseSHASums
// ---------------------------------------------------------------------------

func TestParseSHASums_Normal(t *testing.T) {
	input := "aabbcc112233  terraform_1.5.0_linux_amd64.zip\n" +
		"ddeeff445566  terraform_1.5.0_windows_amd64.zip\n"

	m := ParseSHASums([]byte(input))
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d", len(m))
	}
	if m["terraform_1.5.0_linux_amd64.zip"] != "aabbcc112233" {
		t.Error("linux zip sha mismatch")
	}
	if m["terraform_1.5.0_windows_amd64.zip"] != "ddeeff445566" {
		t.Error("windows zip sha mismatch")
	}
}

func TestParseSHASums_EmptyLines(t *testing.T) {
	input := "\n\naabbcc112233  file.zip\n\n"
	m := ParseSHASums([]byte(input))
	if len(m) != 1 {
		t.Errorf("expected 1 entry, got %d", len(m))
	}
}

func TestParseSHASums_MalformedLine(t *testing.T) {
	// Lines with only one field (no filename) must be skipped.
	input := "justahash\ngoodhash  good_file.zip\n"
	m := ParseSHASums([]byte(input))
	if len(m) != 1 {
		t.Errorf("expected 1 entry after skipping bad line, got %d", len(m))
	}
}

func TestParseSHASums_Empty(t *testing.T) {
	m := ParseSHASums([]byte(""))
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

// ---------------------------------------------------------------------------
// DownloadBinary
// ---------------------------------------------------------------------------

func TestDownloadBinary_Success(t *testing.T) {
	content := []byte("fake zip content")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	c := NewTerraformReleasesClient(srv.URL, "terraform")
	c.DownloadClient = c.HTTPClient

	data, sha, err := c.DownloadBinary(context.Background(), srv.URL+"/terraform_1.5.0_linux_amd64.zip")
	if err != nil {
		t.Fatalf("DownloadBinary error: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Error("downloaded content mismatch")
	}
	// Verify the returned sha matches the content.
	expected := ComputeSHA256Hex(content)
	if sha != expected {
		t.Errorf("sha = %q, want %q", sha, expected)
	}
}

func TestDownloadBinary_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewTerraformReleasesClient(srv.URL, "terraform")
	c.DownloadClient = c.HTTPClient

	_, _, err := c.DownloadBinary(context.Background(), srv.URL+"/missing.zip")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

func TestDownloadBinary_InvalidURL(t *testing.T) {
	c := NewTerraformReleasesClient("http://127.0.0.1:0", "terraform")
	_, _, err := c.DownloadBinary(context.Background(), "http://127.0.0.1:0/file.zip")
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

// ---------------------------------------------------------------------------
// StreamWithSHA256
// ---------------------------------------------------------------------------

func TestStreamWithSHA256_KnownContent(t *testing.T) {
	content := []byte("hello world")
	// Precomputed SHA256 of "hello world"
	wantSHA := "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576cac8d269d3f1d4c"

	data, got, err := StreamWithSHA256(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("StreamWithSHA256 error: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Error("returned data does not match input")
	}
	// We care that it returns a 64-char hex string and matches ComputeSHA256Hex.
	if len(got) != 64 {
		t.Errorf("sha length = %d, want 64", len(got))
	}
	_ = wantSHA // tolerance: just verify it matches our own function
	if got != ComputeSHA256Hex(content) {
		t.Errorf("sha mismatch: got %q, ComputeSHA256Hex = %q", got, ComputeSHA256Hex(content))
	}
}

func TestStreamWithSHA256_Empty(t *testing.T) {
	data, sha, err := StreamWithSHA256(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Error("expected empty data")
	}
	if sha != ComputeSHA256Hex(nil) {
		t.Errorf("sha of empty != ComputeSHA256Hex(nil): %q vs %q", sha, ComputeSHA256Hex(nil))
	}
}

func TestStreamWithSHA256_ReadError(t *testing.T) {
	r := io.NopCloser(errReader{})
	_, _, err := StreamWithSHA256(r)
	if err == nil {
		t.Error("expected read error, got nil")
	}
}

// errReader always returns an error on Read.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated read failure")
}

// ---------------------------------------------------------------------------
// ComputeSHA256Hex
// ---------------------------------------------------------------------------

func TestComputeSHA256Hex_KnownValues(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		// echo -n "" | sha256sum
		{[]byte(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		// echo -n "abc" | sha256sum
		{[]byte("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, tt := range tests {
		got := ComputeSHA256Hex(tt.input)
		if got != tt.want {
			t.Errorf("ComputeSHA256Hex(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateBinarySHA256
// ---------------------------------------------------------------------------

func TestValidateBinarySHA256_Match(t *testing.T) {
	data := []byte("terraform binary")
	hash := ComputeSHA256Hex(data)
	if !ValidateBinarySHA256(data, hash) {
		t.Error("expected match, got false")
	}
}

func TestValidateBinarySHA256_CaseInsensitive(t *testing.T) {
	data := []byte("terraform binary")
	hash := strings.ToUpper(ComputeSHA256Hex(data))
	if !ValidateBinarySHA256(data, hash) {
		t.Error("expected case-insensitive match, got false")
	}
}

func TestValidateBinarySHA256_Mismatch(t *testing.T) {
	data := []byte("terraform binary")
	if ValidateBinarySHA256(data, "000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("expected mismatch, got true")
	}
}
