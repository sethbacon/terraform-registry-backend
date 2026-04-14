// Package analyzer extracts structured Terraform documentation from module archives
// using the official HashiCorp terraform-config-inspect library.
// No binary dependency is required — parsing is done in-process.
package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
	"github.com/terraform-registry/terraform-registry/internal/archiver"
)

// ModuleDoc holds structured documentation extracted from a Terraform module.
type ModuleDoc struct {
	Inputs       []InputVar    `json:"inputs"`
	Outputs      []OutputVal   `json:"outputs"`
	Providers    []ProviderReq `json:"providers"`
	Requirements *Requirements `json:"requirements,omitempty"`
}

// InputVar represents a Terraform input variable.
type InputVar struct {
	Name        string      `json:"name"`
	Type        string      `json:"type,omitempty"`
	Description string      `json:"description,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Required    bool        `json:"required"`
}

// OutputVal represents a Terraform output value.
type OutputVal struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

// ProviderReq represents a required provider declaration.
type ProviderReq struct {
	Name               string `json:"name"`
	Source             string `json:"source,omitempty"`
	VersionConstraints string `json:"version_constraints,omitempty"`
}

// Requirements holds the terraform version constraint for the module.
type Requirements struct {
	RequiredVersion string `json:"required_version,omitempty"`
}

// AnalyzeDir parses Terraform files in moduleDir and returns structured metadata.
// Uses tfconfig.LoadModule which tolerates partial/incomplete modules.
// Returns (nil, nil) if the directory has no .tf files.
func AnalyzeDir(moduleDir string) (*ModuleDoc, error) {
	module, diags := tfconfig.LoadModule(moduleDir)
	if module == nil {
		return nil, nil
	}
	if diags.HasErrors() {
		// Partial parse is common with missing providers; log and continue.
		slog.Debug("terraform-config-inspect: parse diagnostics",
			"dir", moduleDir, "diags", diags.Error())
	}

	doc := &ModuleDoc{
		Inputs:    []InputVar{},
		Outputs:   []OutputVal{},
		Providers: []ProviderReq{},
	}

	for name, v := range module.Variables {
		doc.Inputs = append(doc.Inputs, InputVar{
			Name:        name,
			Type:        v.Type,
			Description: v.Description,
			Default:     v.Default,
			Required:    v.Required,
		})
	}
	sort.Slice(doc.Inputs, func(i, j int) bool { return doc.Inputs[i].Name < doc.Inputs[j].Name })

	for name, o := range module.Outputs {
		doc.Outputs = append(doc.Outputs, OutputVal{
			Name:        name,
			Description: o.Description,
			Sensitive:   o.Sensitive,
		})
	}
	sort.Slice(doc.Outputs, func(i, j int) bool { return doc.Outputs[i].Name < doc.Outputs[j].Name })

	for name, p := range module.RequiredProviders {
		req := ProviderReq{Name: name, Source: p.Source}
		if len(p.VersionConstraints) > 0 {
			req.VersionConstraints = strings.Join(p.VersionConstraints, ", ")
		}
		doc.Providers = append(doc.Providers, req)
	}
	sort.Slice(doc.Providers, func(i, j int) bool { return doc.Providers[i].Name < doc.Providers[j].Name })

	if len(module.RequiredCore) > 0 {
		doc.Requirements = &Requirements{
			RequiredVersion: strings.Join(module.RequiredCore, ", "),
		}
	}

	return doc, nil
}

// AnalyzeArchive extracts a tar.gz archive from reader and calls AnalyzeDir
// on the module root.  The reader must be seekable (os.File satisfies this).
// The temporary directory is removed on return.
func AnalyzeArchive(reader io.ReadSeeker) (*ModuleDoc, error) {
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek archive: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "tfdocs-*")
	if err != nil {
		return nil, fmt.Errorf("mkdirtemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := archiver.ExtractTarGz(reader, tmpDir); err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}

	return AnalyzeDir(archiver.FindModuleRoot(tmpDir))
}

// MarshalInputs serialises the inputs slice as JSON bytes.
func MarshalInputs(inputs []InputVar) ([]byte, error) {
	return json.Marshal(inputs)
}

// MarshalOutputs serialises the outputs slice as JSON bytes.
func MarshalOutputs(outputs []OutputVal) ([]byte, error) {
	return json.Marshal(outputs)
}

// MarshalProviders serialises the providers slice as JSON bytes.
func MarshalProviders(providers []ProviderReq) ([]byte, error) {
	return json.Marshal(providers)
}
