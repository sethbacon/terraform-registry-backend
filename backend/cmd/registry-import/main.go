// registry-import imports module versions from a public Terraform registry into a private
// registry instance via its upload API.
//
// Usage:
//
//	registry-import \
//	  --namespace=hashicorp \
//	  --source-url=https://registry.terraform.io \
//	  --org=myorg \
//	  --registry-url=https://my-registry.example.com \
//	  --api-key=<key>
//
// Flags:
//   - --source-url     Base URL of the source registry (default: https://registry.terraform.io)
//   - --namespace      Namespace (author) to import from the source registry (required)
//   - --module         Specific module name within the namespace to import (optional; imports all when omitted)
//   - --system         Filter by provider system, e.g. aws, azurerm (optional; imports all systems when omitted)
//   - --org            Organisation slug in the target registry (required)
//   - --registry-url   Base URL of the target registry (required)
//   - --api-key        API key for the target registry (required)
//   - --dry-run        Print planned actions without uploading anything
//   - --concurrency    Maximum parallel uploads (default: 4)
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// ─── source registry types ────────────────────────────────────────────────────

type versionsResponse struct {
	Modules []struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	} `json:"modules"`
}

type searchResponse struct {
	Modules []sourceModule `json:"modules"`
	Meta    struct {
		NextOffset int `json:"next_offset"`
		Limit      int `json:"limit"`
		Total      int `json:"total"`
	} `json:"meta"`
}

type sourceModule struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
}

// ─── work item ────────────────────────────────────────────────────────────────

type importJob struct {
	namespace string
	name      string
	system    string
	version   string
}

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	sourceURL := flag.String("source-url", "https://registry.terraform.io", "Source registry base URL")
	namespace := flag.String("namespace", "", "Namespace to import from source registry (required)")
	module := flag.String("module", "", "Specific module name to import (default: all modules in namespace)")
	system := flag.String("system", "", "Filter by provider/system (default: all)")
	org := flag.String("org", "", "Organisation slug in the target registry (required)")
	registryURL := flag.String("registry-url", "", "Target registry base URL (required)")
	apiKey := flag.String("api-key", "", "API key for the target registry (required)")
	dryRun := flag.Bool("dry-run", false, "Print planned actions without uploading")
	concurrency := flag.Int("concurrency", 4, "Maximum parallel uploads")
	flag.Parse()

	if *namespace == "" {
		log.Fatal("--namespace is required")
	}
	if *org == "" {
		log.Fatal("--org is required")
	}
	if *registryURL == "" {
		log.Fatal("--registry-url is required")
	}
	if *apiKey == "" {
		log.Fatal("--api-key is required")
	}

	client := &http.Client{Timeout: 120 * time.Second}

	// Collect all (module, system) pairs to import.
	modules, err := listModules(client, *sourceURL, *namespace, *module, *system)
	if err != nil {
		log.Fatalf("listing modules: %v", err)
	}
	log.Printf("found %d module/system combinations in namespace %q", len(modules), *namespace)

	// Build the full job list.
	var jobs []importJob
	for _, m := range modules {
		versions, err := listVersions(client, *sourceURL, m.Namespace, m.Name, m.Provider)
		if err != nil {
			log.Printf("[warn] listing versions for %s/%s/%s: %v", m.Namespace, m.Name, m.Provider, err)
			continue
		}
		for _, v := range versions {
			jobs = append(jobs, importJob{
				namespace: m.Namespace,
				name:      m.Name,
				system:    m.Provider,
				version:   v,
			})
		}
	}

	log.Printf("planning to import %d module versions", len(jobs))

	if *dryRun {
		for _, j := range jobs {
			fmt.Printf("  [dry-run] %s/%s/%s@%s\n", j.namespace, j.name, j.system, j.version)
		}
		return
	}

	// Execute imports with bounded concurrency.
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var succeeded, skipped, failed int

	for _, j := range jobs {
		j := j
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			result, err := importVersion(client, *sourceURL, *registryURL, *apiKey, *org, j)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && result == "skipped":
				skipped++
				log.Printf("[skip]    %s/%s/%s@%s (already exists)", j.namespace, j.name, j.system, j.version)
			case err == nil:
				succeeded++
				log.Printf("[ok]      %s/%s/%s@%s", j.namespace, j.name, j.system, j.version)
			default:
				failed++
				log.Printf("[error]   %s/%s/%s@%s: %v", j.namespace, j.name, j.system, j.version, err)
			}
		}()
	}

	wg.Wait()
	log.Printf("done — imported: %d, skipped: %d, failed: %d", succeeded, skipped, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// ─── source registry helpers ──────────────────────────────────────────────────

// listModules returns all modules in the namespace. If moduleName or providerFilter is set
// the results are filtered accordingly. Paginates automatically.
func listModules(client *http.Client, sourceURL, namespace, moduleName, providerFilter string) ([]sourceModule, error) {
	// If a specific module is given we can build the list directly.
	if moduleName != "" {
		if providerFilter != "" {
			return []sourceModule{{Namespace: namespace, Name: moduleName, Provider: providerFilter}}, nil
		}
		// We still need to discover which systems exist for this module.
		return listModuleSystems(client, sourceURL, namespace, moduleName)
	}

	// Otherwise page through the registry search API.
	var all []sourceModule
	offset := 0
	for {
		u := fmt.Sprintf("%s/v1/modules?namespace=%s&limit=50&offset=%d", sourceURL, namespace, offset)
		var resp searchResponse
		if err := getJSON(client, u, &resp); err != nil {
			return nil, err
		}
		for _, m := range resp.Modules {
			if providerFilter == "" || m.Provider == providerFilter {
				all = append(all, m)
			}
		}
		if offset+resp.Meta.Limit >= resp.Meta.Total {
			break
		}
		offset += resp.Meta.Limit
	}
	return all, nil
}

// listModuleSystems returns all provider/system entries for a given namespace/module.
func listModuleSystems(client *http.Client, sourceURL, namespace, moduleName string) ([]sourceModule, error) {
	u := fmt.Sprintf("%s/v1/modules/%s/%s", sourceURL, namespace, moduleName)
	// The module search endpoint returns multiple rows (one per provider) when provider is omitted.
	var resp searchResponse
	if err := getJSON(client, u, &resp); err != nil {
		return nil, err
	}
	return resp.Modules, nil
}

// listVersions returns all published version strings for a module.
func listVersions(client *http.Client, sourceURL, namespace, name, provider string) ([]string, error) {
	u := fmt.Sprintf("%s/v1/modules/%s/%s/%s/versions", sourceURL, namespace, name, provider)
	var resp versionsResponse
	if err := getJSON(client, u, &resp); err != nil {
		return nil, err
	}
	if len(resp.Modules) == 0 {
		return nil, nil
	}
	var versions []string
	for _, v := range resp.Modules[0].Versions {
		versions = append(versions, v.Version)
	}
	return versions, nil
}

// downloadURL retrieves the download URL for a specific module version via the
// X-Terraform-Get redirect header.
func downloadURL(client *http.Client, sourceURL, namespace, name, provider, version string) (string, error) {
	u := fmt.Sprintf("%s/v1/modules/%s/%s/%s/%s/download", sourceURL, namespace, name, provider, version)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download redirect: unexpected status %d", resp.StatusCode)
	}
	location := resp.Header.Get("X-Terraform-Get")
	if location == "" {
		location = resp.Header.Get("Location")
	}
	if location == "" {
		return "", errors.New("download redirect: no X-Terraform-Get or Location header")
	}
	return location, nil
}

// fetchArchive downloads a module archive from archiveURL and returns it as a .tar.gz byte
// slice. If the upstream serves a .zip, it is converted on the fly.
func fetchArchive(client *http.Client, archiveURL string) ([]byte, error) {
	resp, err := client.Get(archiveURL) // #nosec G107 -- URL originates from public registry X-Terraform-Get header
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("archive download: status %d from %s", resp.StatusCode, archiveURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// If the upstream returned a .zip, re-pack it as .tar.gz.
	if strings.HasSuffix(archiveURL, ".zip") || isZip(body) {
		return zipToTarGz(body)
	}
	return body, nil
}

// ─── target registry upload ───────────────────────────────────────────────────

// importVersion downloads a module version from source and uploads it to the target registry.
// Returns "skipped" when the version already exists (HTTP 409), nil error on success.
func importVersion(client *http.Client, sourceURL, registryURL, apiKey, org string, j importJob) (string, error) {
	// 1. Resolve the download URL.
	archiveURL, err := downloadURL(client, sourceURL, j.namespace, j.name, j.system, j.version)
	if err != nil {
		return "", fmt.Errorf("resolving download URL: %w", err)
	}

	// Resolve relative URLs against sourceURL.
	if strings.HasPrefix(archiveURL, "/") {
		archiveURL = sourceURL + archiveURL
	}

	// 2. Download the archive.
	archive, err := fetchArchive(client, archiveURL)
	if err != nil {
		return "", fmt.Errorf("fetching archive: %w", err)
	}

	// 3. Build the multipart upload request.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	writeField := func(k, v string) {
		if fw, e := mw.CreateFormField(k); e == nil {
			_, _ = fw.Write([]byte(v))
		}
	}
	writeField("namespace", j.namespace)
	writeField("name", j.name)
	writeField("system", j.system)
	writeField("version", j.version)
	writeField("org", org)

	fw, err := mw.CreateFormFile("file", path.Base(j.name)+"-"+j.version+".tar.gz")
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(archive); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	// 4. POST to the target registry.
	uploadURL := strings.TrimRight(registryURL, "/") + "/api/v1/modules"
	req, err := http.NewRequest(http.MethodPost, uploadURL, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		return "ok", nil
	case http.StatusConflict:
		return "skipped", nil
	default:
		resBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload returned %d: %s", resp.StatusCode, strings.TrimSpace(string(resBody)))
	}
}

// ─── utilities ────────────────────────────────────────────────────────────────

func getJSON(client *http.Client, url string, dest interface{}) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}

// isZip checks the first 4 bytes for the PK\x03\x04 magic header.
func isZip(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04
}

// zipToTarGz converts a zip archive (in memory) to a .tar.gz stream.
// Terraform module archives from the public registry are often zip files.
func zipToTarGz(zipData []byte) ([]byte, error) {
	r := bytes.NewReader(zipData)
	zr, err := zip.NewReader(r, int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		info := f.FileInfo()
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			rc.Close() //nolint:errcheck
			return nil, err
		}
		header.Name = f.Name
		if err := tw.WriteHeader(header); err != nil {
			rc.Close() //nolint:errcheck
			return nil, err
		}
		if !info.IsDir() {
			if _, err := io.Copy(tw, rc); err != nil {
				rc.Close() //nolint:errcheck
				return nil, err
			}
		}
		rc.Close() //nolint:errcheck
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
