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
	// ChecksumsPattern matches the checksums asset .Name for this version. Leave nil when
	// the release publishes no checksums file and UseAssetDigest is used instead (checkov).
	ChecksumsPattern *regexp.Regexp
	// SignaturePattern optionally matches an additional signature/attestation asset .Name
	// (e.g. a Sigstore bundle). Only set when Signature.Type is "gpg" or "sigstore".
	SignaturePattern *regexp.Regexp
	// Signature describes optional cryptographic signature verification for this tool.
	// SHA256 checksum verification is always mandatory; this is additive.
	Signature SignatureSpec
	// UseAssetDigest, when true, verifies the downloaded archive's SHA256 against the
	// archive asset's GitHub-reported `digest` field instead of a checksums file/asset.
	UseAssetDigest bool
	// BinaryInArchive is the path inside the archive to extract (e.g. "trivy").
	BinaryInArchive string
	// ArchiveFormat is the archive type: "tar.gz" or "zip".
	ArchiveFormat string
}

// SignatureSpec describes optional signature/provenance verification for a tool's release
// artifacts, on top of the mandatory SHA256 checksum check.
type SignatureSpec struct {
	// Type is "", "none", "gpg", or "sigstore".
	Type string
	// Identity is the expected Sigstore keyless-signing identity (e.g. a GitHub Actions
	// workflow URI template, which may contain a "%s" placeholder for the version).
	Identity string
	// Issuer is the expected Sigstore OIDC token issuer.
	Issuer string
	// KeyURL is the well-known URL to fetch the ASCII-armored GPG public key (gpg only).
	KeyURL string
	// Fingerprint pins the expected GPG primary key fingerprint (gpg only).
	Fingerprint string
}

// trivySignature documents trivy's Sigstore keyless-signing provenance. Verification
// of the Sigstore bundle itself is not implemented yet (tracked as a follow-up); the
// generic signature hook logs a notice and never blocks the download for this type.
var trivySignature = SignatureSpec{
	Type:     "sigstore",
	Identity: "https://github.com/aquasecurity/trivy/.github/workflows/release.yaml@refs/tags/v%s",
	Issuer:   "https://token.actions.githubusercontent.com",
}

// noSignature marks tools whose upstream releases ship no cryptographic signature;
// integrity relies on the mandatory SHA256 checksum check alone.
var noSignature = SignatureSpec{Type: "none"}

// Catalog maps tool name → "GOOS/GOARCH" → AssetSpec.
var Catalog = map[string]map[string]AssetSpec{
	"trivy": {
		"linux/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_Linux-64bit\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			SignaturePattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt\.sigstore\.json$`),
			Signature:        trivySignature,
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
		"linux/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_Linux-ARM64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			SignaturePattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt\.sigstore\.json$`),
			Signature:        trivySignature,
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_macOS-64bit\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			SignaturePattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt\.sigstore\.json$`),
			Signature:        trivySignature,
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^trivy_[\d.]+_macOS-ARM64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt$`),
			SignaturePattern: regexp.MustCompile(`^trivy_[\d.]+_checksums\.txt\.sigstore\.json$`),
			Signature:        trivySignature,
			BinaryInArchive:  "trivy",
			ArchiveFormat:    "tar.gz",
		},
	},
	"terrascan": {
		"linux/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Linux_x86_64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^(terrascan_[\d.]+_)?checksums\.txt$`),
			Signature:        noSignature,
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
		"linux/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Linux_arm64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^(terrascan_[\d.]+_)?checksums\.txt$`),
			Signature:        noSignature,
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Darwin_x86_64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^(terrascan_[\d.]+_)?checksums\.txt$`),
			Signature:        noSignature,
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
		"darwin/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/tenable/terrascan/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/tenable/terrascan/releases/tags/v%s",
			AssetPattern:     regexp.MustCompile(`^terrascan_[\d.]+_Darwin_arm64\.tar\.gz$`),
			ChecksumsPattern: regexp.MustCompile(`^(terrascan_[\d.]+_)?checksums\.txt$`),
			Signature:        noSignature,
			BinaryInArchive:  "terrascan",
			ArchiveFormat:    "tar.gz",
		},
	},
	"checkov": {
		"linux/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_linux_X86_64\.zip$`),
			ChecksumsPattern: nil,
			UseAssetDigest:   true,
			Signature:        noSignature,
			BinaryInArchive:  "checkov",
			ArchiveFormat:    "zip",
		},
		"linux/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_linux_arm64\.zip$`),
			ChecksumsPattern: nil,
			UseAssetDigest:   true,
			Signature:        noSignature,
			BinaryInArchive:  "checkov",
			ArchiveFormat:    "zip",
		},
		"darwin/amd64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_darwin_X86_64\.zip$`),
			ChecksumsPattern: nil,
			UseAssetDigest:   true,
			Signature:        noSignature,
			BinaryInArchive:  "checkov",
			ArchiveFormat:    "zip",
		},
		"darwin/arm64": {
			LatestReleaseAPI: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
			VersionedAPI:     "https://api.github.com/repos/bridgecrewio/checkov/releases/tags/%s",
			AssetPattern:     regexp.MustCompile(`^checkov_darwin_arm64\.zip$`),
			ChecksumsPattern: nil,
			UseAssetDigest:   true,
			Signature:        noSignature,
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
