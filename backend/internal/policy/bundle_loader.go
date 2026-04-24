package policy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// regoFile holds the name and source of a single .rego module.
type regoFile struct {
	name   string
	source string
}

// fetchBundle downloads the bundle archive from bundleURL and returns all .rego files
// it contains.  Only HTTP/HTTPS URLs are supported; the archive must be a .tar.gz.
func fetchBundle(ctx context.Context, bundleURL string) ([]regoFile, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleURL, nil) // #nosec G107 -- URL comes from operator config
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

	return parseBundleTarGz(resp.Body)
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

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if !strings.HasSuffix(hdr.Name, ".rego") {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 1<<20)) // 1 MB per file
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", hdr.Name, err)
		}
		files = append(files, regoFile{name: hdr.Name, source: string(data)})
	}

	return files, nil
}
