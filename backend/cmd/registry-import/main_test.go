package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── isZip ────────────────────────────────────────────────────────────────────

func TestIsZip_Valid(t *testing.T) {
	// Minimal valid zip header
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00}
	if !isZip(data) {
		t.Error("expected true for zip magic header")
	}
}

func TestIsZip_Invalid(t *testing.T) {
	if isZip([]byte{0x1F, 0x8B, 0x00}) {
		t.Error("expected false for gzip header")
	}
}

func TestIsZip_Short(t *testing.T) {
	if isZip([]byte{0x50, 0x4B}) {
		t.Error("expected false for short slice")
	}
}

// ─── zipToTarGz ───────────────────────────────────────────────────────────────

func buildZip(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestZipToTarGz_RoundTrip(t *testing.T) {
	zipData, err := buildZip(map[string]string{
		"main.tf": `resource "null_resource" "example" {}`,
	})
	if err != nil {
		t.Fatalf("building zip: %v", err)
	}

	tgz, err := zipToTarGz(zipData)
	if err != nil {
		t.Fatalf("zipToTarGz: %v", err)
	}

	// Read back and verify the file is present.
	gr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	tr := tar.NewReader(gr)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if hdr.Name == "main.tf" {
			found = true
			content, _ := io.ReadAll(tr)
			if !strings.Contains(string(content), "null_resource") {
				t.Errorf("unexpected content: %s", content)
			}
		}
	}
	if !found {
		t.Error("main.tf not found in converted tar.gz")
	}
}

func TestZipToTarGz_InvalidZip(t *testing.T) {
	_, err := zipToTarGz([]byte("not a zip"))
	if err == nil {
		t.Error("expected error for invalid zip data")
	}
}

// ─── listVersions via HTTP mock ───────────────────────────────────────────────

func TestListVersions_OK(t *testing.T) {
	payload := versionsResponse{
		Modules: []struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		}{
			{Versions: []struct {
				Version string `json:"version"`
			}{{Version: "1.0.0"}, {Version: "1.1.0"}}},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	client := srv.Client()
	versions, err := listVersions(client, srv.URL, "hashicorp", "consul", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
}

func TestListVersions_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"modules":[]}`))
	}))
	defer srv.Close()

	versions, err := listVersions(srv.Client(), srv.URL, "ns", "name", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected 0 versions, got %d", len(versions))
	}
}

func TestListVersions_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := listVersions(srv.Client(), srv.URL, "ns", "name", "aws")
	if err == nil {
		t.Error("expected error for 404")
	}
}

// ─── downloadURL via HTTP mock ────────────────────────────────────────────────

func TestDownloadURL_XTerraformGet(t *testing.T) {
	const want = "https://example.com/archive.tar.gz"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Terraform-Get", want)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	got, err := downloadURL(srv.Client(), srv.URL, "ns", "name", "aws", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestDownloadURL_NoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	_, err := downloadURL(srv.Client(), srv.URL, "ns", "name", "aws", "1.0.0")
	if err == nil {
		t.Error("expected error when no location header")
	}
}

// ─── importVersion — skip on 409 ─────────────────────────────────────────────

func TestImportVersion_SkipOn409(t *testing.T) {
	// Source: serve download redirect + archive
	archiveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/download"):
			w.Header().Set("X-Terraform-Get", "http://"+r.Host+"/archive.tar.gz")
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, ".tar.gz"):
			// Minimal valid tar.gz (empty)
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			_ = gw.Close()
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(buf.Bytes())
		}
	}))
	defer archiveSrv.Close()

	// Target: always return 409
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer targetSrv.Close()

	result, err := importVersion(archiveSrv.Client(), archiveSrv.URL, targetSrv.URL, "key", "org",
		importJob{namespace: "ns", name: "name", system: "aws", version: "1.0.0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "skipped" {
		t.Errorf("expected skipped, got %q", result)
	}
}
