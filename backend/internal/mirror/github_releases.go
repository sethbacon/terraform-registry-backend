// Package mirror - github_releases.go implements a client that fetches Terraform
// (or OpenTofu) release metadata from the GitHub Releases API and translates it
// into the same TerraformVersionInfo / TerraformReleaseBuild types used by the
// standard HashiCorp releases client.
//
// GitHub Releases API endpoint: GET /repos/{owner}/{repo}/releases
//
// Supported upstream URL formats (all resolve to the same owner/repo):
//
//	https://github.com/opentofu/opentofu/releases
//	https://github.com/opentofu/opentofu
//	https://api.github.com/repos/opentofu/opentofu/releases
//	https://api.github.com/repos/opentofu/opentofu
//
// The client paginates automatically (100 releases per page) and filters
// release assets to find:
//   - Binary zips matching the pattern  {product}_{version}_{os}_{arch}.zip
//   - SHA256SUMS file matching          {product}_{version}_SHA256SUMS
//   - GPG signature matching            {product}_{version}_SHA256SUMS.sig   (or .72D7468F.sig)
//   - Hyphenated archives matching      {product}-v{version}-{os}-{arch}.tar.gz|.zip  (terraform-docs)
//   - Combined checksum file matching   {product}-v{version}.sha256sum                (terraform-docs)
package mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// IsGitHubReleasesURL returns true when the upstream URL refers to a GitHub
// repository releases page or the GitHub API releases endpoint.
func IsGitHubReleasesURL(upstreamURL string) bool {
	u := strings.ToLower(strings.TrimRight(upstreamURL, "/"))
	return strings.Contains(u, "github.com")
}

// ParseGitHubOwnerRepo extracts the owner and repository name from a GitHub
// URL in any of the supported formats.
func ParseGitHubOwnerRepo(upstreamURL string) (owner, repo string, err error) {
	u := strings.TrimRight(upstreamURL, "/")
	// Strip scheme + host variants
	for _, prefix := range []string{
		"https://api.github.com/repos/",
		"http://api.github.com/repos/",
		"https://github.com/",
		"http://github.com/",
	} {
		if strings.HasPrefix(strings.ToLower(u), strings.ToLower(prefix)) {
			u = u[len(prefix):]
			break
		}
	}
	// Drop trailing path segments like /releases, /releases/tag/…, etc.
	parts := strings.SplitN(u, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("cannot parse GitHub owner/repo from URL %q", upstreamURL)
	}
	// Strip .git suffix if present
	repoName := strings.TrimSuffix(parts[1], ".git")
	return parts[0], repoName, nil
}

// ----- GitHub API types -----------------------------------------------------

// gitHubRelease is the minimal subset of a GitHub releases API response entry.
type gitHubRelease struct {
	TagName    string        `json:"tag_name"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []gitHubAsset `json:"assets"`
}

// gitHubAsset is one downloadable file attached to a GitHub release.
type gitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// ----- GitHubReleasesClient -------------------------------------------------

// GitHubReleasesClient fetches Terraform / OpenTofu release metadata from the
// GitHub Releases API and returns it in the same shape as TerraformReleasesClient.
type GitHubReleasesClient struct {
	Owner          string
	Repo           string
	ProductName    string // binary name prefix, e.g. "opentofu" or "terraform"
	HTTPClient     *http.Client
	DownloadClient *http.Client
	// APIToken is an optional GitHub personal-access or fine-grained token.
	// It is read from the GITHUB_TOKEN env-var by the constructor when present.
	// Without a token the API is limited to 60 unauthenticated requests per hour.
	APIToken string // #nosec G117 -- configuration field for GitHub API authentication, not a hardcoded credential
}

// NewGitHubReleasesClient creates a GitHubReleasesClient from a GitHub URL and
// product name. productName should match the binary filename prefix ("opentofu",
// "terraform", or a custom value for third-party repos). The strict egress
// policy applies (see NewGitHubReleasesClientWithGuard).
func NewGitHubReleasesClient(upstreamURL, productName string) (*GitHubReleasesClient, error) {
	return NewGitHubReleasesClientWithGuard(upstreamURL, productName, nil)
}

// NewGitHubReleasesClientWithGuard is NewGitHubReleasesClient with an egress
// guard widening the SSRF deny-list (nil = strict). API calls and asset
// downloads (upstream-controlled browser_download_url values) are dialed
// through internal/httpsafe.
func NewGitHubReleasesClientWithGuard(upstreamURL, productName string, egress *httpsafe.Guard) (*GitHubReleasesClient, error) {
	owner, repo, err := ParseGitHubOwnerRepo(upstreamURL)
	if err != nil {
		return nil, err
	}
	if productName == "" {
		productName = repo // fall back to repo name
	}
	return &GitHubReleasesClient{
		Owner:          owner,
		Repo:           repo,
		ProductName:    productName,
		HTTPClient:     httpsafe.NewClient(30*time.Second, egress),
		DownloadClient: httpsafe.NewClient(10*time.Minute, egress),
	}, nil
}

// ----- regex for asset filename parsing -------------------------------------

// binaryZipRE matches:  {product}_{version}_{os}_{arch}.zip
// e.g. opentofu_1.9.0_linux_amd64.zip
var binaryZipRE = regexp.MustCompile(`^(.+?)_([^_]+)_([^_]+)_([^_]+)\.zip$`)

// bareBinaryRE matches bare binaries without version in filename:
//
//	{product}_{os}_{arch}       e.g. opa_linux_amd64
//	{product}_{os}_{arch}.exe   e.g. opa_windows_amd64.exe
//
// Used by projects like OPA that publish unversioned binaries per release.
var bareBinaryRE = regexp.MustCompile(`^(.+?)_([a-z]+)_([a-z0-9]+?)(?:_static)?(?:\.exe)?$`)

// perFileSHA256RE matches per-file SHA256 sidecar files: {filename}.sha256
var perFileSHA256RE = regexp.MustCompile(`^(.+)\.sha256$`)

// sha256sumsRE matches: {product}_{version}_SHA256SUMS (no extension)
var sha256sumsRE = regexp.MustCompile(`^(.+?)_([^_]+)_SHA256SUMS$`)

// sha256sumsSigRE matches: {product}_{version}_SHA256SUMS.sig  (or .*.sig)
var sha256sumsSigRE = regexp.MustCompile(`^(.+?)_([^_]+)_SHA256SUMS\..*sig$`)

// tfDocsArchiveRE matches hyphen-delimited, version-prefixed release archives:
//
//	{product}-v{version}-{os}-{arch}.tar.gz   e.g. terraform-docs-v0.24.0-linux-amd64.tar.gz
//	{product}-v{version}-{os}-{arch}.zip      e.g. terraform-docs-v0.24.0-windows-amd64.zip
//
// Used by terraform-docs, whose assets are hyphen-delimited (not underscore) and
// shipped as .tar.gz / .zip archives rather than bare {product}_{os}_{arch} files.
// The product prefix is still validated against c.ProductName by the caller, so
// the greedy leading group cannot cross-match another tool's assets.
var tfDocsArchiveRE = regexp.MustCompile(`^(.+)-v([0-9][^-\s]*)-([a-z0-9]+)-([a-z0-9]+)\.(?:tar\.gz|zip)$`)

// tfDocsSumsRE matches a single combined checksum file that carries the version
// in its name with a ".sha256sum" suffix: {product}-v{version}.sha256sum
// e.g. terraform-docs-v0.24.0.sha256sum. Its body is the standard
// "<sha256>  <filename>" format parsed by ParseSHASums.
var tfDocsSumsRE = regexp.MustCompile(`^(.+)-v([0-9][^-\s]*)\.sha256sum$`)

// ----- ListVersions ---------------------------------------------------------

// ListVersions fetches all (non-draft) releases from GitHub and returns them
// as TerraformVersionInfo slices. Pre-release / rc / beta versions are
// included — callers can apply filterTerraformVersions if desired.
func (c *GitHubReleasesClient) ListVersions(ctx context.Context) ([]TerraformVersionInfo, error) {
	var allVersions []TerraformVersionInfo
	page := 1

	for {
		releases, err := c.fetchReleasesPage(ctx, page)
		if err != nil {
			return nil, err
		}
		if len(releases) == 0 {
			break
		}

		for _, rel := range releases {
			if rel.Draft {
				continue
			}

			vi, ok := c.parseRelease(rel)
			if !ok {
				continue
			}
			allVersions = append(allVersions, vi)
		}

		if len(releases) < 100 {
			break // last page
		}
		page++
	}

	return allVersions, nil
}

func (c *GitHubReleasesClient) fetchReleasesPage(ctx context.Context, page int) ([]gitHubRelease, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=100&page=%d",
		c.Owner, c.Repo, page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build GitHub API request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIToken)
	}

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	if err != nil {
		return nil, fmt.Errorf("failed to call GitHub releases API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var releases []gitHubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxUpstreamResponseBytes)).Decode(&releases); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub releases response: %w", err)
	}
	return releases, nil
}

// parseRelease converts one GitHub release into a TerraformVersionInfo.
// Returns (info, false) if the release has no recognisable binary assets.
func (c *GitHubReleasesClient) parseRelease(rel gitHubRelease) (TerraformVersionInfo, bool) {
	// Normalise tag → version: strip leading "v" that some projects use.
	version := strings.TrimPrefix(rel.TagName, "v")

	var builds []TerraformReleaseBuild
	var sha256sumsURL string
	var sha256sumsSigURL string
	// perFileSHAs maps binary filename → download URL for its .sha256 sidecar.
	perFileSHAs := make(map[string]string)

	for _, asset := range rel.Assets {
		name := asset.Name
		url := asset.BrowserDownloadURL

		// Binary zip?
		if m := binaryZipRE.FindStringSubmatch(name); m != nil {
			product, _, osName, arch := m[1], m[2], m[3], m[4]
			if !strings.EqualFold(product, c.ProductName) {
				continue
			}
			builds = append(builds, TerraformReleaseBuild{
				Name:     product,
				Version:  version,
				OS:       osName,
				Arch:     arch,
				Filename: name,
				URL:      url,
			})
			continue
		}

		// Hyphenated, version-prefixed archive? (e.g. terraform-docs-v0.24.0-linux-amd64.tar.gz)
		if m := tfDocsArchiveRE.FindStringSubmatch(name); m != nil {
			product, osName, arch := m[1], m[3], m[4]
			if !strings.EqualFold(product, c.ProductName) {
				continue
			}
			builds = append(builds, TerraformReleaseBuild{
				Name:     product,
				Version:  version,
				OS:       osName,
				Arch:     arch,
				Filename: name,
				URL:      url,
			})
			continue
		}

		// Per-file .sha256 sidecar? (e.g. opa_linux_amd64.sha256)
		if m := perFileSHA256RE.FindStringSubmatch(name); m != nil {
			perFileSHAs[m[1]] = url
			continue
		}

		// SHA256SUMS file?
		if m := sha256sumsRE.FindStringSubmatch(name); m != nil {
			if strings.EqualFold(m[1], c.ProductName) {
				sha256sumsURL = url
			}
			continue
		}

		// Combined ".sha256sum" checksum file? (e.g. terraform-docs-v0.24.0.sha256sum)
		if m := tfDocsSumsRE.FindStringSubmatch(name); m != nil {
			if strings.EqualFold(m[1], c.ProductName) {
				sha256sumsURL = url
			}
			continue
		}

		// SHA256SUMS signature?
		if m := sha256sumsSigRE.FindStringSubmatch(name); m != nil {
			if strings.EqualFold(m[1], c.ProductName) {
				sha256sumsSigURL = url
			}
			continue
		}

		// Bare binary? (e.g. opa_linux_amd64, opa_windows_amd64.exe)
		if m := bareBinaryRE.FindStringSubmatch(name); m != nil {
			product, osName, arch := m[1], m[2], m[3]
			if !strings.EqualFold(product, c.ProductName) {
				continue
			}
			builds = append(builds, TerraformReleaseBuild{
				Name:     product,
				Version:  version,
				OS:       osName,
				Arch:     arch,
				Filename: name,
				URL:      url,
			})
			continue
		}
	}

	if len(builds) == 0 {
		return TerraformVersionInfo{}, false
	}

	vi := TerraformVersionInfo{
		Version:          version,
		SHASumsURL:       sha256sumsURL,
		SHASumsSignature: sha256sumsSigURL,
		Builds:           builds,
	}
	// Attach per-file SHA URLs so FetchSHASums can fall back to them.
	if len(perFileSHAs) > 0 && sha256sumsURL == "" {
		vi.PerFileSHAURLs = perFileSHAs
	}

	return vi, true
}

// ----- FetchSHASums ---------------------------------------------------------

// FetchSHASums downloads the SHA256SUMS asset for a specific version from
// GitHub and returns parsed filename→sha256 map plus the raw bytes.
// If no combined SHA256SUMS file exists (e.g. OPA), it falls back to fetching
// individual .sha256 sidecar files for each binary asset.
func (c *GitHubReleasesClient) FetchSHASums(ctx context.Context, version string) (map[string]string, []byte, error) {
	sumsURL, err := c.findSHA256SumsURL(ctx, version)
	if err != nil {
		return nil, nil, err
	}

	// Combined SHA256SUMS file found — use it directly.
	if sumsURL != "" {
		raw, fetchErr := c.fetchURL(ctx, sumsURL, 1<<20) // 1 MB cap
		if fetchErr != nil {
			return nil, nil, fmt.Errorf("failed to fetch SHA256SUMS for %s: %w", version, fetchErr)
		}
		return ParseSHASums(raw), raw, nil
	}

	// No combined file — try per-file .sha256 sidecars (OPA pattern).
	return c.fetchPerFileSHASums(ctx, version)
}

// fetchPerFileSHASums fetches individual .sha256 sidecar files for a release
// and synthesizes a combined filename→sha256 map.
func (c *GitHubReleasesClient) fetchPerFileSHASums(ctx context.Context, version string) (map[string]string, []byte, error) {
	// Fetch the release to find .sha256 assets.
	var rel gitHubRelease
	var found bool
	for _, tag := range []string{"v" + version, version} {
		r, fetchErr := c.fetchReleaseByTag(ctx, tag)
		if fetchErr == nil {
			rel = r
			found = true
			break
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("no release found for version %s in %s/%s", version, c.Owner, c.Repo)
	}

	sums := make(map[string]string)
	var combined strings.Builder

	for _, asset := range rel.Assets {
		m := perFileSHA256RE.FindStringSubmatch(asset.Name)
		if m == nil {
			continue
		}
		binaryFilename := m[1]
		raw, fetchErr := c.fetchURL(ctx, asset.BrowserDownloadURL, 256)
		if fetchErr != nil {
			continue
		}
		hash := strings.TrimSpace(strings.Fields(string(raw))[0])
		sums[binaryFilename] = hash
		combined.WriteString(hash + "  " + binaryFilename + "\n")
	}

	if len(sums) == 0 {
		return nil, nil, fmt.Errorf("no SHA256SUMS or .sha256 sidecar files found for version %s in %s/%s", version, c.Owner, c.Repo)
	}

	return sums, []byte(combined.String()), nil
}

// FetchSHASumsSignature downloads the GPG signature for the SHA256SUMS file
// of a specific version from GitHub.
func (c *GitHubReleasesClient) FetchSHASumsSignature(ctx context.Context, version string) ([]byte, error) {
	sigURL, err := c.findSHA256SumsSigURL(ctx, version)
	if err != nil {
		return nil, err
	}
	if sigURL == "" {
		return nil, fmt.Errorf("no SHA256SUMS signature asset found for version %s in %s/%s", version, c.Owner, c.Repo)
	}
	return c.fetchURL(ctx, sigURL, 65536) // 64 KB cap
}

// DownloadBinary downloads a binary zip from the given URL (already a full URL
// from the GitHub asset list). Identical to TerraformReleasesClient.DownloadBinary.
func (c *GitHubReleasesClient) DownloadBinaryStream(ctx context.Context, downloadURL string) (io.ReadCloser, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil) // #nosec G107 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	if err != nil {
		return nil, -1, fmt.Errorf("failed to build download request: %w", err)
	}

	resp, err := c.DownloadClient.Do(req)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to download binary: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, -1, fmt.Errorf("upstream returned %d for binary download: %s", resp.StatusCode, string(body))
	}

	return resp.Body, resp.ContentLength, nil
}

// ----- helpers --------------------------------------------------------------

func (c *GitHubReleasesClient) findSHA256SumsURL(ctx context.Context, version string) (string, error) {
	return c.findAssetURL(ctx, version, sha256sumsRE, tfDocsSumsRE)
}

func (c *GitHubReleasesClient) findSHA256SumsSigURL(ctx context.Context, version string) (string, error) {
	return c.findAssetURL(ctx, version, sha256sumsSigRE)
}

// findAssetURL fetches the specific release by tag (tries with and without
// leading "v") and returns the browser_download_url of the first asset whose
// name matches any of the supplied regexes and whose product prefix (capture
// group 1) matches c.ProductName.
func (c *GitHubReleasesClient) findAssetURL(ctx context.Context, version string, res ...*regexp.Regexp) (string, error) {
	// GitHub tags may use "v1.9.0" or "1.9.0" — try both.
	for _, tag := range []string{"v" + version, version} {
		rel, err := c.fetchReleaseByTag(ctx, tag)
		if err != nil {
			continue
		}
		for _, asset := range rel.Assets {
			for _, re := range res {
				if m := re.FindStringSubmatch(asset.Name); m != nil {
					if strings.EqualFold(m[1], c.ProductName) {
						return asset.BrowserDownloadURL, nil
					}
				}
			}
		}
		// Found the release but not the asset — no point checking the other tag.
		return "", nil
	}
	return "", nil
}

func (c *GitHubReleasesClient) fetchReleaseByTag(ctx context.Context, tag string) (gitHubRelease, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s",
		c.Owner, c.Repo, tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return gitHubRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIToken)
	}

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	if err != nil {
		return gitHubRelease{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return gitHubRelease{}, fmt.Errorf("tag %q: GitHub API returned %d", tag, resp.StatusCode)
	}

	var rel gitHubRelease
	// maxUpstreamResponseBytes (defined in upstream.go, shared across this
	// package's outbound clients) bounds this decode the same way it already
	// bounds fetchReleasesPage above.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxUpstreamResponseBytes)).Decode(&rel); err != nil {
		return gitHubRelease{}, err
	}
	return rel, nil
}

func (c *GitHubReleasesClient) fetchURL(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIToken)
	}

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}
