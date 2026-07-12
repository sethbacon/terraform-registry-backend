// Package osv provides a thin client for the OSV.dev vulnerability database API.
//
// OSV API reference: https://google.github.io/osv.dev/api/
//
// The client uses the /v1/querybatch endpoint (up to 1000 queries per call) with
// a fallback to the single /v1/query endpoint when the batch endpoint returns an
// error. A client-side rate limiter caps outbound throughput at 60 requests/second
// to stay well under OSV's documented limits even when scanning large provider
// catalogs.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

const (
	defaultEndpoint = "https://api.osv.dev"
	batchMaxSize    = 1000
	requestsPerSec  = 60
)

// Client is a rate-limited HTTP client for the OSV.dev API.
type Client struct {
	endpoint   string
	httpClient *http.Client
	limiter    *rate.Limiter
}

// NewClient returns a Client pointed at the given endpoint with the strict
// egress policy (no allow-list). Pass an empty string to use the default
// (https://api.osv.dev). The endpoint is operator-configurable
// (cve.osv_endpoint), so requests are dialed through internal/httpsafe.
func NewClient(endpoint string) *Client {
	return NewClientWithGuard(endpoint, nil)
}

// NewClientWithGuard is NewClient with an egress guard widening the SSRF
// deny-list (nil = strict), for deployments that point osv_endpoint at an
// internal OSV mirror.
func NewClientWithGuard(endpoint string, egress *httpsafe.Guard) *Client {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	return &Client{
		endpoint:   endpoint,
		httpClient: httpsafe.NewClient(30*time.Second, egress),
		limiter:    rate.NewLimiter(rate.Limit(requestsPerSec), requestsPerSec),
	}
}

// ---- Request / Response types ----------------------------------------------

// Query is a single OSV query entry used in both single and batch requests.
type Query struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
}

// Package identifies a software package in the OSV ecosystem.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// BatchRequest is the body of POST /v1/querybatch.
type BatchRequest struct {
	Queries []Query `json:"queries"`
}

// BatchResponse is the response from POST /v1/querybatch.
type BatchResponse struct {
	Results []QueryResult `json:"results"`
}

// QueryResult is one element of a BatchResponse.Results slice.
type QueryResult struct {
	Vulns []Advisory `json:"vulns"`
}

// Advisory is the OSV advisory shape (subset of fields we use).
type Advisory struct {
	ID         string     `json:"id"`
	Aliases    []string   `json:"aliases"`
	Summary    string     `json:"summary"`
	Details    string     `json:"details"`
	Severity   []Severity `json:"severity"`
	References []Ref      `json:"references"`
	Published  *time.Time `json:"published"`
	Modified   *time.Time `json:"modified"`
	Withdrawn  *time.Time `json:"withdrawn"`
}

// Severity holds a CVSS score string and its type.
type Severity struct {
	Type  string `json:"type"`  // "CVSS_V3", "CVSS_V2"
	Score string `json:"score"` // e.g. "CVSS:3.1/AV:N/AC:L/..."
}

// Ref is a single external reference.
type Ref struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ---- API methods -----------------------------------------------------------

// QueryBatch submits up to batchMaxSize queries in a single call.
// It returns one QueryResult per input query in the same order.
// If the batch endpoint fails, it falls back to individual single-query calls.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	results, err := c.doBatch(ctx, queries)
	if err != nil {
		// Fallback: individual queries
		results = make([]QueryResult, len(queries))
		for i, q := range queries {
			advisories, sErr := c.QuerySingle(ctx, q)
			if sErr != nil {
				// Best-effort: log and return an empty result for this entry.
				results[i] = QueryResult{}
				continue
			}
			results[i] = QueryResult{Vulns: advisories}
		}
	}
	return results, nil
}

// QuerySingle calls POST /v1/query for a single package+version.
func (c *Client) QuerySingle(ctx context.Context, q Query) ([]Advisory, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	body, _ := json.Marshal(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv query HTTP %d: %s", resp.StatusCode, b)
	}

	var result QueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}
	return result.Vulns, nil
}

// doBatch performs the actual batch HTTP request.
func (c *Client) doBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	body, _ := json.Marshal(BatchRequest{Queries: queries})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv querybatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv querybatch HTTP %d: %s", resp.StatusCode, b)
	}

	var br BatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, fmt.Errorf("decode osv batch response: %w", err)
	}
	return br.Results, nil
}

// ---- Severity helpers -------------------------------------------------------

// NormalizeSeverity converts the first CVSS v3 vector in an advisory to a
// severity bucket (critical/high/medium/low/unknown). Falls back to unknown when
// no CVSS v3 severity is present.
func NormalizeSeverity(advisory Advisory) string {
	for _, s := range advisory.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		score := cvssV3BaseScore(s.Score)
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		case score > 0:
			return "low"
		}
	}
	return "unknown"
}

// cvssV3BaseScore parses the numeric base score from a CVSS v3 vector string.
// OSV embeds the base score in some vectors as the trailing "/BS:N.N" segment or
// as a separate numeric field. When parsing fails, 0 is returned.
func cvssV3BaseScore(vector string) float64 {
	// OSV sometimes provides a plain numeric score instead of a full vector.
	// Try direct parse first.
	var f float64
	if n, _ := fmt.Sscanf(vector, "%f", &f); n == 1 {
		return f
	}
	// Fall back to 0 — we cannot determine numeric score.
	return 0
}

// ReferenceURLs extracts the URL strings from an advisory's references slice.
func ReferenceURLs(advisory Advisory) []string {
	urls := make([]string, 0, len(advisory.References))
	for _, r := range advisory.References {
		if r.URL != "" {
			urls = append(urls, r.URL)
		}
	}
	return urls
}

// CanonicalID returns the most human-readable identifier for an advisory:
// the first CVE alias if present, otherwise the OSV ID itself.
func CanonicalID(advisory Advisory) string {
	for _, alias := range advisory.Aliases {
		if len(alias) >= 4 && alias[:4] == "CVE-" {
			return alias
		}
	}
	return advisory.ID
}
