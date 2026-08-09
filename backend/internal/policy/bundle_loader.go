package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// regoFile holds the name and source of a single .rego module.
type regoFile struct {
	name   string
	source string
}

// maxBundleBytes bounds the fully-buffered bundle archive so a misbehaving or
// adversarial bundle host cannot exhaust memory. The archive is buffered (not
// streamed) because pinned-SHA-256 verification must run before any of its
// contents are parsed and loaded as active upload policy.
const maxBundleBytes = 50 << 20 // 50 MB

// Decompression budget for the bundle archive (issue #750).
//
// maxBundleBytes bounds the COMPRESSED archive only. gzip amplifies, so 50 MB
// of archive can encode far more than 50 MB of entries, and every .rego entry
// is retained in memory for the lifetime of the parse. Without these, a hostile
// or compromised bundle host could turn one 50 MB download into an
// out-of-memory kill.
//
// Non-.rego entries are charged too. Skipping an entry is not free: the tar
// reader must decompress its body to reach the next header, so an archive made
// entirely of skipped entries costs the same CPU and I/O while previously being
// accounted at zero.
const (
	// maxBundleEntries caps how many archive members are examined. Real OPA
	// bundles hold tens of policies; thousands means something else is going on.
	maxBundleEntries = 4096
	// maxBundleDecompressedBytes caps the cumulative declared size of every
	// entry, .rego or not.
	maxBundleDecompressedBytes = 64 << 20 // 64 MB
	// maxRegoFileBytes caps a single policy file.
	maxRegoFileBytes = 1 << 20 // 1 MB
)

// fetchBundle downloads the bundle archive from bundleURL and returns all
// .rego files it contains. bundleURL must use HTTPS unless its host is
// covered by egress's allow-list (loopback/internal test mirrors). The
// request is routed through the SSRF-safe egress client
// (internal/httpsafe): resolve-and-pin dial-time IP checks and per-hop
// redirect re-validation. When expectedSHA256 is non-empty, the downloaded
// archive's digest is verified before parsing and the bundle is rejected
// (fail closed, previously loaded policies kept) on any mismatch.
func fetchBundle(ctx context.Context, bundleURL string, expectedSHA256 string, egress *httpsafe.Guard) ([]regoFile, error) {
	parsed, err := url.Parse(bundleURL)
	if err != nil {
		return nil, fmt.Errorf("invalid bundle URL: %w", err)
	}
	if parsed.Scheme != "https" && !egress.HostExempt(parsed.Hostname()) {
		return nil, fmt.Errorf("policy bundle_url must use https (got %q); add the host to security.egress.allowlist if plain HTTP to an internal mirror is intentional", parsed.Scheme)
	}

	client := httpsafe.NewClient(30*time.Second, egress)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating bundle request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching bundle: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching bundle: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading bundle: %w", err)
	}
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds maximum size of %d bytes", maxBundleBytes)
	}

	if expectedSHA256 != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, expectedSHA256) {
			return nil, fmt.Errorf("policy bundle sha256 mismatch: got %s, want %s — refusing to load (fail closed)", got, expectedSHA256)
		}
	}

	return parseBundleTarGz(bytes.NewReader(data))
}

// parseBundleTarGz reads a .tar.gz bundle and returns all .rego source files inside it.
func parseBundleTarGz(r io.Reader) ([]regoFile, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("bundle gzip: %w", err)
	}
	defer gr.Close() //nolint:errcheck

	tr := tar.NewReader(gr)
	var files []regoFile

	var (
		entries      int
		decompressed int64
	)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle tar: %w", err)
		}

		// Charged before any filtering, so entries this loop skips still cost
		// against the budget -- reaching the next header decompresses them
		// whether or not their contents are wanted.
		entries++
		if entries > maxBundleEntries {
			return nil, fmt.Errorf("bundle contains more than %d entries", maxBundleEntries)
		}
		if hdr.Size > 0 {
			decompressed += hdr.Size
			if decompressed > maxBundleDecompressedBytes {
				return nil, fmt.Errorf("bundle decompresses to more than %d bytes",
					maxBundleDecompressedBytes)
			}
		}

		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if !strings.HasSuffix(hdr.Name, ".rego") {
			continue
		}

		// Reject an oversized policy rather than truncating it. The previous
		// io.LimitReader(tr, 1<<20) silently cut a larger file off mid-source:
		// the bundle then loaded as a POLICY THAT WAS NEVER WRITTEN -- a
		// truncation landing after an allow rule but before the deny that
		// qualifies it inverts the outcome, with nothing in the logs to say so.
		if hdr.Size > maxRegoFileBytes {
			return nil, fmt.Errorf("policy file %s is %d bytes, over the %d-byte limit",
				hdr.Name, hdr.Size, maxRegoFileBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxRegoFileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", hdr.Name, err)
		}
		// hdr.Size is the archive's own claim; this is the byte count actually
		// produced, so a header understating its body is caught too.
		if int64(len(data)) > maxRegoFileBytes {
			return nil, fmt.Errorf("policy file %s exceeds the %d-byte limit",
				hdr.Name, maxRegoFileBytes)
		}
		files = append(files, regoFile{name: hdr.Name, source: string(data)})
	}

	return files, nil
}
