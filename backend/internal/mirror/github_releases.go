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
// "terraform", or a custom value for third-party repos).
func NewGitHubReleasesClient(upstreamURL, productName string) (*GitHubReleasesClient, error) {
	owner, repo, err := ParseGitHubOwnerRepo(upstreamURL)
	if err != nil {
		return nil, err
	}
	if productName == "" {
		productName = repo // fall back to repo name
	}
	return &GitHubReleasesClient{
		Owner:       owner,
		Repo:        repo,
		ProductName: productName,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		DownloadClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}, nil
}

// ----- regex for asset filename parsing -------------------------------------

// binaryZipRE matches:  {product}_{version}_{os}_{arch}.zip
// e.g. opentofu_1.9.0_linux_amd64.zip
var binaryZipRE = regexp.MustCompile(`^(.+?)_([^_]+)_([^_]+)_([^_]+)\.zip$`)

// sha256sumsRE matches: {product}_{version}_SHA256SUMS (no extension)
var sha256sumsRE = regexp.MustCompile(`^(.+?)_([^_]+)_SHA256SUMS$`)

// sha256sumsSigRE matches: {product}_{version}_SHA256SUMS.sig  (or .*.sig)
var sha256sumsSigRE = regexp.MustCompile(`^(.+?)_([^_]+)_SHA256SUMS\..*sig$`)

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

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- URL derived from admin-configured upstream
	if err != nil {
		return nil, fmt.Errorf("failed to call GitHub releases API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var releases []gitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
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

	for _, asset := range rel.Assets {
		name := asset.Name
		url := asset.BrowserDownloadURL

		// Binary zip?
		if m := binaryZipRE.FindStringSubmatch(name); m != nil {
			product, _, osName, arch := m[1], m[2], m[3], m[4]
			// Only accept assets belonging to our product (e.g. "opentofu_…")
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

		// SHA256SUMS file?
		if m := sha256sumsRE.FindStringSubmatch(name); m != nil {
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
	}

	if len(builds) == 0 {
		return TerraformVersionInfo{}, false
	}

	return TerraformVersionInfo{
		Version:          version,
		SHASumsURL:       sha256sumsURL,
		SHASumsSignature: sha256sumsSigURL,
		Builds:           builds,
	}, true
}

// ----- FetchSHASums ---------------------------------------------------------

// FetchSHASums downloads the SHA256SUMS asset for a specific version from
// GitHub and returns parsed filename→sha256 map plus the raw bytes.
// It first calls ListVersions to locate the asset URL for the given version.
func (c *GitHubReleasesClient) FetchSHASums(ctx context.Context, version string) (map[string]string, []byte, error) {
	sumsURL, err := c.findSHA256SumsURL(ctx, version)
	if err != nil {
		return nil, nil, err
	}
	if sumsURL == "" {
		return nil, nil, fmt.Errorf("no SHA256SUMS asset found for version %s in %s/%s", version, c.Owner, c.Repo)
	}

	raw, err := c.fetchURL(ctx, sumsURL, 1<<20) // 1 MB cap
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch SHA256SUMS for %s: %w", version, err)
	}
	return ParseSHASums(raw), raw, nil
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
func (c *GitHubReleasesClient) DownloadBinary(ctx context.Context, downloadURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build download request: %w", err)
	}

	resp, err := c.DownloadClient.Do(req) // #nosec G704 -- URL from admin-configured upstream
	if err != nil {
		return nil, "", fmt.Errorf("failed to download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("upstream returned %d for binary download", resp.StatusCode)
	}

	return StreamWithSHA256(resp.Body)
}

// ----- helpers --------------------------------------------------------------

func (c *GitHubReleasesClient) findSHA256SumsURL(ctx context.Context, version string) (string, error) {
	return c.findAssetURL(ctx, version, sha256sumsRE)
}

func (c *GitHubReleasesClient) findSHA256SumsSigURL(ctx context.Context, version string) (string, error) {
	return c.findAssetURL(ctx, version, sha256sumsSigRE)
}

// findAssetURL fetches the specific release by tag (tries with and without
// leading "v") and returns the browser_download_url of the first asset whose
// name matches re and whose product prefix matches c.ProductName.
func (c *GitHubReleasesClient) findAssetURL(ctx context.Context, version string, re *regexp.Regexp) (string, error) {
	// GitHub tags may use "v1.9.0" or "1.9.0" — try both.
	for _, tag := range []string{"v" + version, version} {
		rel, err := c.fetchReleaseByTag(ctx, tag)
		if err != nil {
			continue
		}
		for _, asset := range rel.Assets {
			if m := re.FindStringSubmatch(asset.Name); m != nil {
				if strings.EqualFold(m[1], c.ProductName) {
					return asset.BrowserDownloadURL, nil
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

	resp, err := c.HTTPClient.Do(req) // #nosec G704
	if err != nil {
		return gitHubRelease{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return gitHubRelease{}, fmt.Errorf("tag %q: GitHub API returned %d", tag, resp.StatusCode)
	}

	var rel gitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
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

	resp, err := c.HTTPClient.Do(req) // #nosec G704
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
