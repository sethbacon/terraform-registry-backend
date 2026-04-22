// Package installer downloads, verifies, and installs supported security scanner
// binaries from their official GitHub releases. It is consumed by the setup wizard
// and admin install endpoints.
package installer

import (
	"regexp"
	"runtime"
	"sort"
)

// AssetSpec describes how to locate and extract a scanner binary from a GitHub release.
type AssetSpec struct {
	// LatestReleaseAPI is the GitHub "latest release" JSON endpoint.
	LatestReleaseAPI string
	// VersionedAPI is the GitHub "release by tag" endpoint; use with fmt.Sprintf(..., version).
	VersionedAPI string
	// AssetPattern matches the release asset .Name for this OS/arch.
	AssetPattern *regexp.Regexp
	// ChecksumsPattern matches the checksums asset .Name for this version.
	ChecksumsPattern *regexp.Regexp
	// BinaryInArchive is the path inside the archive to extract (e.g. "trivy").
	BinaryInArchive string
	// ArchiveFormat is the archive type: "tar.gz" or "zip".
	ArchiveFormat string
}

// Catalog maps tool name → "GOOS/GOARCH" → AssetSpec.
var Catalog = map[string]map[string]AssetSpec{
	"trivy": {
		"linux/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_Linux-64bit\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
		"linux/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_Linux-ARM64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_macOS-64bit\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_macOS-ARM64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
	},
	"terrascan": {
		"linux/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Linux_x86_64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^terrascan_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
		"linux/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Linux_arm64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^terrascan_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Darwin_x86_64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^terrascan_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Darwin_arm64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^terrascan_[\d.]+_checksums\.txt$`),
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
	},
	"checkov": {
		"linux/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_linux_X86_64\.zip$`),
			ChecksumsPattern: regexp.MustCompile(`^checkov_linux_X86_64\.zip\.sha256$`),
			BinaryInArchive:  "checkov",
			ArchiveFormat:    "zip",
		},
		"linux/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_linux_arm64\.zip$`),
			ChecksumsPattern: regexp.MustCompile(`^checkov_linux_arm64\.zip\.sha256$`),
			BinaryInArchive:  "checkov",
			ArchiveFormat:    "zip",
		},
		"darwin/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_darwin_X86_64\.zip$`),
			ChecksumsPattern: regexp.MustCompile(`^checkov_darwin_X86_64\.zip\.sha256$`),
			BinaryInArchive:  "checkov",
			ArchiveFormat:    "zip",
		},
		"darwin/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_darwin_arm64\.zip$`),
			ChecksumsPattern: regexp.MustCompile(`^checkov_darwin_arm64\.zip\.sha256$`),
			BinaryInArchive:  "checkov",
			ArchiveFormat:    "zip",
		},
	},
}

// Lookup returns the AssetSpec for the given tool on the specified OS/arch.
func Lookup(tool, goos, goarch string) (AssetSpec, bool) {
	platforms, ok := Catalog[tool]
	if !ok {
		return AssetSpec{}, false
	}
	spec, ok := platforms[goos+"/"+goarch]
	return spec, ok
}

// Supports returns true if the tool has catalog entries (any platform).
func Supports(tool string) bool {
	_, ok := Catalog[tool]
	return ok
}

// SupportedTools returns a sorted list of tool names that the installer supports.
func SupportedTools() []string {
	tools := make([]string, 0, len(Catalog))
	for t := range Catalog {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	return tools
}

// RuntimeLookup is a convenience for Lookup using runtime.GOOS and runtime.GOARCH.
func RuntimeLookup(tool string) (AssetSpec, bool) {
	return Lookup(tool, runtime.GOOS, runtime.GOARCH)
}
