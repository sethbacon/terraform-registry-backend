package analyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// writeTFFiles writes a map of filename→content into dir.
func writeTFFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// buildTarGz creates an in-memory tar.gz from a map of path→content.
func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// buildTarGzWrapped wraps files inside a single top-level directory (like GitHub archives).
func buildTarGzWrapped(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	wrapped := make(map[string]string, len(files))
	for name, content := range files {
		wrapped[prefix+"/"+name] = content
	}
	// add the directory entry
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: prefix + "/", Typeflag: tar.TypeDir, Mode: 0755})
	for name, content := range wrapped {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// AnalyzeDir
// ---------------------------------------------------------------------------

func TestAnalyzeDir_NoTFFiles(t *testing.T) {
	// tfconfig tolerates dirs with no .tf files — returns an empty (non-nil) module.
	dir := t.TempDir()
	writeTFFiles(t, dir, map[string]string{"README.md": "# readme"})

	doc, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc != nil {
		if len(doc.Inputs) != 0 || len(doc.Outputs) != 0 || len(doc.Providers) != 0 {
			t.Errorf("expected empty doc, got %+v", doc)
		}
	}
}

func TestAnalyzeDir_EmptyModule(t *testing.T) {
	dir := t.TempDir()
	writeTFFiles(t, dir, map[string]string{"main.tf": ""})

	doc, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil doc for dir with main.tf")
	}
	if len(doc.Inputs) != 0 {
		t.Errorf("expected 0 inputs, got %d", len(doc.Inputs))
	}
	if len(doc.Outputs) != 0 {
		t.Errorf("expected 0 outputs, got %d", len(doc.Outputs))
	}
}

func TestAnalyzeDir_Variables(t *testing.T) {
	dir := t.TempDir()
	writeTFFiles(t, dir, map[string]string{
		"variables.tf": `
variable "region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "instance_count" {
  type = number
}
`,
	})

	doc, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
	if len(doc.Inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d: %v", len(doc.Inputs), doc.Inputs)
	}

	// Find by name (sorted alphabetically by AnalyzeDir)
	var region, count *InputVar
	for i := range doc.Inputs {
		switch doc.Inputs[i].Name {
		case "region":
			region = &doc.Inputs[i]
		case "instance_count":
			count = &doc.Inputs[i]
		}
	}
	if region == nil {
		t.Fatal("missing 'region' variable")
	}
	if region.Description != "AWS region" {
		t.Errorf("region description = %q, want 'AWS region'", region.Description)
	}
	if region.Required {
		t.Error("region should not be required (has default)")
	}
	if count == nil {
		t.Fatal("missing 'instance_count' variable")
	}
	if !count.Required {
		t.Error("instance_count should be required (no default)")
	}
}

func TestAnalyzeDir_Outputs(t *testing.T) {
	dir := t.TempDir()
	writeTFFiles(t, dir, map[string]string{
		"main.tf": `resource "null_resource" "x" {}`,
		"outputs.tf": `
output "instance_ip" {
  value       = "10.0.0.1"
  description = "The instance IP address"
}

output "secret_value" {
  value     = "secret"
  sensitive = true
}
`,
	})

	doc, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(doc.Outputs))
	}

	var ip, secret *OutputVal
	for i := range doc.Outputs {
		switch doc.Outputs[i].Name {
		case "instance_ip":
			ip = &doc.Outputs[i]
		case "secret_value":
			secret = &doc.Outputs[i]
		}
	}
	if ip == nil {
		t.Fatal("missing 'instance_ip' output")
	}
	if ip.Description != "The instance IP address" {
		t.Errorf("instance_ip description = %q", ip.Description)
	}
	if secret == nil {
		t.Fatal("missing 'secret_value' output")
	}
	if !secret.Sensitive {
		t.Error("secret_value should be sensitive")
	}
}

func TestAnalyzeDir_Providers(t *testing.T) {
	dir := t.TempDir()
	writeTFFiles(t, dir, map[string]string{
		"versions.tf": `
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}
`,
	})

	doc, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d: %v", len(doc.Providers), doc.Providers)
	}
	if doc.Providers[0].Name != "aws" {
		t.Errorf("provider name = %q, want aws", doc.Providers[0].Name)
	}
	if doc.Providers[0].Source != "hashicorp/aws" {
		t.Errorf("provider source = %q, want hashicorp/aws", doc.Providers[0].Source)
	}
	if doc.Requirements == nil {
		t.Fatal("expected non-nil requirements")
	}
	if doc.Requirements.RequiredVersion == "" {
		t.Error("expected required_version to be non-empty")
	}
}

func TestAnalyzeDir_SortedAlphabetically(t *testing.T) {
	dir := t.TempDir()
	writeTFFiles(t, dir, map[string]string{
		"variables.tf": `
variable "z_var" {}
variable "a_var" {}
variable "m_var" {}
`,
		"outputs.tf": `
output "z_out" { value = "z" }
output "a_out" { value = "a" }
`,
	})

	doc, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Inputs) != 3 {
		t.Fatalf("expected 3 inputs, got %d", len(doc.Inputs))
	}
	if doc.Inputs[0].Name != "a_var" || doc.Inputs[1].Name != "m_var" || doc.Inputs[2].Name != "z_var" {
		t.Errorf("inputs not sorted: %v", doc.Inputs)
	}
	if doc.Outputs[0].Name != "a_out" || doc.Outputs[1].Name != "z_out" {
		t.Errorf("outputs not sorted: %v", doc.Outputs)
	}
}

func TestAnalyzeDir_NonExistent(t *testing.T) {
	// tfconfig.LoadModule tolerates non-existent dirs and returns an empty (non-nil) module.
	// AnalyzeDir just returns an empty doc with no error.
	doc, _ := AnalyzeDir("/nonexistent/path/xyz")
	if doc != nil {
		if len(doc.Inputs) != 0 || len(doc.Outputs) != 0 || len(doc.Providers) != 0 {
			t.Errorf("expected empty doc for non-existent path, got %+v", doc)
		}
	}
}

// ---------------------------------------------------------------------------
// AnalyzeArchive
// ---------------------------------------------------------------------------

func TestAnalyzeArchive_FlatArchive(t *testing.T) {
	data := buildTarGz(t, map[string]string{
		"variables.tf": `variable "env" { description = "Environment" }`,
		"outputs.tf":   `output "name" { value = var.env }`,
	})

	doc, err := AnalyzeArchive(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("AnalyzeArchive: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
	if len(doc.Inputs) != 1 || doc.Inputs[0].Name != "env" {
		t.Errorf("unexpected inputs: %v", doc.Inputs)
	}
	if len(doc.Outputs) != 1 || doc.Outputs[0].Name != "name" {
		t.Errorf("unexpected outputs: %v", doc.Outputs)
	}
}

func TestAnalyzeArchive_WrappedArchive(t *testing.T) {
	// GitHub/GitLab wrap archives in a single top-level directory
	data := buildTarGzWrapped(t, "terraform-aws-vpc-abc1234", map[string]string{
		"variables.tf": `variable "vpc_cidr" { default = "10.0.0.0/16" }`,
	})

	doc, err := AnalyzeArchive(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("AnalyzeArchive: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil doc from wrapped archive")
	}
	if len(doc.Inputs) != 1 || doc.Inputs[0].Name != "vpc_cidr" {
		t.Errorf("unexpected inputs: %v", doc.Inputs)
	}
}

func TestAnalyzeArchive_EmptyArchive(t *testing.T) {
	// An empty archive extracts to an empty dir; tfconfig returns an empty module (not nil).
	data := buildTarGz(t, map[string]string{})
	doc, err := AnalyzeArchive(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("empty archive should not error: %v", err)
	}
	if doc != nil {
		if len(doc.Inputs) != 0 || len(doc.Outputs) != 0 || len(doc.Providers) != 0 {
			t.Errorf("expected empty doc for empty archive, got %+v", doc)
		}
	}
}

func TestAnalyzeArchive_InvalidReader(t *testing.T) {
	_, err := AnalyzeArchive(bytes.NewReader([]byte("not a tar.gz")))
	if err == nil {
		t.Error("expected error for invalid archive, got nil")
	}
}

// ---------------------------------------------------------------------------
// Marshal helpers
// ---------------------------------------------------------------------------

func TestMarshalInputs(t *testing.T) {
	inputs := []InputVar{{Name: "x", Type: "string", Required: true}}
	b, err := MarshalInputs(inputs)
	if err != nil {
		t.Fatalf("MarshalInputs: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestMarshalOutputs(t *testing.T) {
	outputs := []OutputVal{{Name: "y", Description: "desc"}}
	b, err := MarshalOutputs(outputs)
	if err != nil {
		t.Fatalf("MarshalOutputs: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestMarshalProviders(t *testing.T) {
	providers := []ProviderReq{{Name: "aws", Source: "hashicorp/aws"}}
	b, err := MarshalProviders(providers)
	if err != nil {
		t.Fatalf("MarshalProviders: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty JSON")
	}
}

// ---------------------------------------------------------------------------
// AnalyzeArchive — seek error path
// ---------------------------------------------------------------------------

type errSeekReader struct{}

func (e errSeekReader) Read(p []byte) (int, error)     { return 0, io.EOF }
func (e errSeekReader) Seek(int64, int) (int64, error) { return 0, errors.New("seek failed") }

func TestAnalyzeArchive_SeekError(t *testing.T) {
	_, err := AnalyzeArchive(errSeekReader{})
	if err == nil {
		t.Error("expected error for Seek failure, got nil")
	}
}
