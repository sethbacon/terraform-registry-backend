// Package cve implements the OSV.dev matching pipeline for the CVE polling subsystem.
//
// The Matcher queries OSV.dev for advisories affecting three artifact kinds:
//   - Binary: Terraform and OpenTofu binary versions present in mirror catalogs.
//   - Provider: All provider versions registered in the registry.
//   - Scanner: The configured scanner binary (trivy, snyk, checkov, terrascan).
//
// Queries are batched (up to 1000 per call) and rate-limited to stay within OSV
// API limits. Newly discovered advisories generate an audit-log entry and an email;
// subsequent polls update existing rows in place.
package cve

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/cve/osv"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// scannerPackage maps a scanner tool name to its (ecosystem, package) tuple for OSV.
var scannerPackage = map[string][2]string{
	"trivy":     {"Go", "github.com/aquasecurity/trivy"},
	"terrascan": {"Go", "github.com/tenable/terrascan"},
	"snyk":      {"npm", "snyk"},
	"checkov":   {"PyPI", "checkov"},
}

// binaryRepoURL maps a tool name to the canonical GitHub repo URL used in OSV GIT queries.
var binaryRepoURL = map[string]string{
	"terraform": "https://github.com/hashicorp/terraform",
	"opentofu":  "https://github.com/opentofu/opentofu",
	"packer":    "https://github.com/hashicorp/packer",
	"opa":       "https://github.com/open-policy-agent/opa",
}

// batchSize is the maximum number of queries per OSV /v1/querybatch call.
const batchSize = 1000

// Matcher orchestrates CVE candidate enumeration and OSV querying.
type Matcher struct {
	osvClient *osv.Client
	cveRepo   *repositories.CVERepository
	scanCfg   *config.ScanningConfig
}

// NewMatcher creates a Matcher wired to the given OSV client and repositories.
// coverage:skip:integration-only — constructor for the live-DB matcher pipeline.
func NewMatcher(osvClient *osv.Client, cveRepo *repositories.CVERepository, scanCfg *config.ScanningConfig) *Matcher {
	return &Matcher{
		osvClient: osvClient,
		cveRepo:   cveRepo,
		scanCfg:   scanCfg,
	}
}

// RunResult summarises a single matcher run.
type RunResult struct {
	NewAdvisories []models.CVEAdvisory // advisories that were brand-new this run
	Total         int                  // total affected targets written
}

// Run executes a full CVE polling pass across all enabled target kinds.
// It returns a RunResult with any newly inserted advisories so the caller
// (job) can emit notifications for them.
// coverage:skip:integration-only — orchestrates live OSV.dev queries and PostgreSQL writes.
func (m *Matcher) Run(ctx context.Context, pollBinaries, pollProviders, pollScanner bool) (RunResult, error) {
	var result RunResult

	if pollBinaries {
		n, err := m.runBinaries(ctx, &result)
		if err != nil {
			log.Printf("[cve-matcher] binary pass error: %v", err)
		} else {
			log.Printf("[cve-matcher] binary pass: %d advisories written", n)
		}
	}

	if pollProviders {
		n, err := m.runProviders(ctx, &result)
		if err != nil {
			log.Printf("[cve-matcher] provider pass error: %v", err)
		} else {
			log.Printf("[cve-matcher] provider pass: %d advisories written", n)
		}
	}

	if pollScanner {
		n, err := m.runScanner(ctx, &result)
		if err != nil {
			log.Printf("[cve-matcher] scanner pass error: %v", err)
		} else {
			log.Printf("[cve-matcher] scanner pass: %d advisories written", n)
		}
	}

	return result, nil
}

// ---- Binaries ---------------------------------------------------------------

// coverage:skip:integration-only — requires live DB candidates + OSV.dev queries.
func (m *Matcher) runBinaries(ctx context.Context, result *RunResult) (int, error) {
	candidates, err := m.cveRepo.ListAllBinaryCandidates(ctx)
	if err != nil {
		return 0, fmt.Errorf("list binary candidates: %w", err)
	}
	if len(candidates) == 0 {
		return 0, nil
	}

	// Build OSV queries (one per candidate).
	type indexedCandidate struct {
		idx       int
		candidate repositories.BinaryCandidate
	}
	queries := make([]osv.Query, 0, len(candidates))
	indexed := make([]indexedCandidate, 0, len(candidates))

	for _, c := range candidates {
		repoURL, ok := binaryRepoURL[c.Tool]
		if !ok {
			continue
		}
		queries = append(queries, osv.Query{
			Package: osv.Package{Ecosystem: "GIT", Name: repoURL},
			Version: c.Version,
		})
		indexed = append(indexed, indexedCandidate{idx: len(queries) - 1, candidate: c})
	}

	results, err := m.queryBatched(ctx, queries)
	if err != nil {
		return 0, err
	}

	total := 0
	for _, ic := range indexed {
		qr := results[ic.idx]
		targets, n, err := m.persistAdvisories(ctx, qr.Vulns, models.CVETargetKindBinary, func(adv osv.Advisory) models.CVEAffectedTarget {
			tvID := mustParseUUID(ic.candidate.VersionID)
			cfgID := ic.candidate.MirrorConfigID
			return models.CVEAffectedTarget{
				TargetKind:         models.CVETargetKindBinary,
				TerraformVersionID: &tvID,
				TargetRef: models.CVETargetRef{
					MirrorConfigID:     cfgID,
					TerraformVersionID: ic.candidate.VersionID,
					Tool:               ic.candidate.Tool,
					Version:            ic.candidate.Version,
				},
			}
		}, result)
		_ = targets
		if err != nil {
			log.Printf("[cve-matcher] binary persist error for %s %s: %v", ic.candidate.Tool, ic.candidate.Version, err)
		}
		total += n
	}
	return total, nil
}

// ---- Providers ---------------------------------------------------------------

// coverage:skip:integration-only — requires live DB candidates + OSV.dev queries.
func (m *Matcher) runProviders(ctx context.Context, result *RunResult) (int, error) {
	candidates, err := m.cveRepo.ListAllProviderCandidates(ctx)
	if err != nil {
		return 0, fmt.Errorf("list provider candidates: %w", err)
	}
	if len(candidates) == 0 {
		return 0, nil
	}

	queries := make([]osv.Query, 0, len(candidates))
	for _, c := range candidates {
		goModule := providerGoModule(c)
		queries = append(queries, osv.Query{
			Package: osv.Package{Ecosystem: "Go", Name: goModule},
			Version: c.Version,
		})
	}

	results, err := m.queryBatched(ctx, queries)
	if err != nil {
		return 0, err
	}

	total := 0
	for i, c := range candidates {
		qr := results[i]

		// If the Go-ecosystem query returned nothing, retry with GIT ecosystem
		// using the provider's stored source URL (when available).
		if len(qr.Vulns) == 0 && c.Source != nil && *c.Source != "" {
			retry, retryErr := m.osvClient.QuerySingle(ctx, osv.Query{
				Package: osv.Package{Ecosystem: "GIT", Name: *c.Source},
				Version: c.Version,
			})
			if retryErr == nil {
				qr.Vulns = retry
			}
		}

		pvID := mustParseUUID(c.ProviderVersionID)
		pID := c.ProviderID
		ns := c.Namespace
		pt := c.ProviderType
		ver := c.Version

		_, n, err := m.persistAdvisories(ctx, qr.Vulns, models.CVETargetKindProvider, func(adv osv.Advisory) models.CVEAffectedTarget {
			return models.CVEAffectedTarget{
				TargetKind:        models.CVETargetKindProvider,
				ProviderVersionID: &pvID,
				TargetRef: models.CVETargetRef{
					ProviderID:        pID,
					ProviderVersionID: c.ProviderVersionID,
					Namespace:         ns,
					ProviderType:      pt,
					Version:           ver,
				},
			}
		}, result)
		if err != nil {
			log.Printf("[cve-matcher] provider persist error for %s/%s %s: %v", c.Namespace, c.ProviderType, c.Version, err)
		}
		total += n
	}
	return total, nil
}

// ---- Scanner ---------------------------------------------------------------

// coverage:skip:integration-only — requires live ScanningConfig + OSV.dev query.
func (m *Matcher) runScanner(ctx context.Context, result *RunResult) (int, error) {
	if m.scanCfg == nil || !m.scanCfg.Enabled {
		return 0, nil
	}

	pkg, ok := scannerPackage[m.scanCfg.Tool]
	if !ok {
		// custom tool — operator owns vulnerability tracking
		return 0, nil
	}

	version := m.scanCfg.ExpectedVersion
	if version == "" {
		// No expected version pinned; skip — we cannot determine the installed version
		// without shelling out at poll time. The detected version is only available via
		// the scanning admin endpoint which runs a live probe.
		return 0, nil
	}

	vulns, err := m.osvClient.QuerySingle(ctx, osv.Query{
		Package: osv.Package{Ecosystem: pkg[0], Name: pkg[1]},
		Version: version,
	})
	if err != nil {
		return 0, fmt.Errorf("osv scanner query: %w", err)
	}

	tool := m.scanCfg.Tool
	ver := version
	_, n, err := m.persistAdvisories(ctx, vulns, models.CVETargetKindScanner, func(adv osv.Advisory) models.CVEAffectedTarget {
		return models.CVEAffectedTarget{
			TargetKind: models.CVETargetKindScanner,
			TargetRef: models.CVETargetRef{
				Tool:    tool,
				Version: ver,
			},
		}
	}, result)
	return n, err
}

// ---- Shared helpers --------------------------------------------------------

// persistAdvisories writes OSV advisories to the database as CVEAdvisory rows
// and populates CVEAffectedTarget rows using the supplied target builder.
// It returns the list of targets written, the count, and any error.
// coverage:skip:integration-only — requires a live CVERepository (PostgreSQL).
func (m *Matcher) persistAdvisories(
	ctx context.Context,
	vulns []osv.Advisory,
	kind models.CVETargetKind,
	buildTarget func(osv.Advisory) models.CVEAffectedTarget,
	result *RunResult,
) ([]models.CVEAffectedTarget, int, error) {
	if len(vulns) == 0 {
		return nil, 0, nil
	}

	var targets []models.CVEAffectedTarget
	for _, v := range vulns {
		if v.Withdrawn != nil && v.Withdrawn.Before(time.Now()) {
			// Mark existing advisory as withdrawn and skip.
			_ = m.cveRepo.MarkWithdrawn(ctx, "osv", osv.CanonicalID(v))
			continue
		}

		advisory := models.CVEAdvisory{
			Source:      "osv",
			SourceID:    osv.CanonicalID(v),
			Severity:    models.CVESeverity(osv.NormalizeSeverity(v)),
			Summary:     v.Summary,
			Details:     v.Details,
			References:  osv.ReferenceURLs(v),
			PublishedAt: v.Published,
			ModifiedAt:  v.Modified,
			WithdrawnAt: v.Withdrawn,
		}

		advisoryID, isNew, err := m.cveRepo.UpsertAdvisory(ctx, &advisory)
		if err != nil {
			log.Printf("[cve-matcher] upsert advisory %s: %v", advisory.SourceID, err)
			continue
		}
		advisory.ID = advisoryID

		if isNew {
			result.NewAdvisories = append(result.NewAdvisories, advisory)
		}

		target := buildTarget(v)
		target.AdvisoryID = advisoryID
		target.Fingerprint = target.TargetRef.FingerprintFor(kind)

		targets = append(targets, target)
	}

	if len(targets) == 0 {
		return nil, 0, nil
	}

	// Group targets by advisory so we can call ReplaceAffectedTargets per advisory.
	byAdvisory := map[uuid.UUID][]models.CVEAffectedTarget{}
	for _, t := range targets {
		byAdvisory[t.AdvisoryID] = append(byAdvisory[t.AdvisoryID], t)
	}

	total := 0
	for advID, ts := range byAdvisory {
		if err := m.cveRepo.ReplaceAffectedTargets(ctx, advID, kind, ts); err != nil {
			log.Printf("[cve-matcher] replace targets for %s: %v", advID, err)
			continue
		}
		total += len(ts)
	}

	result.Total += total
	return targets, total, nil
}

// queryBatched splits queries into chunks of batchSize and sends each chunk.
// coverage:skip:integration-only — requires a live OSV.dev HTTP client.
func (m *Matcher) queryBatched(ctx context.Context, queries []osv.Query) ([]osv.QueryResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	results := make([]osv.QueryResult, len(queries))
	for start := 0; start < len(queries); start += batchSize {
		end := start + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		chunk := queries[start:end]
		batchResults, err := m.osvClient.QueryBatch(ctx, chunk)
		if err != nil {
			return results, fmt.Errorf("batch query [%d:%d]: %w", start, end, err)
		}
		for i, r := range batchResults {
			results[start+i] = r
		}
	}
	return results, nil
}

// providerGoModule derives the conventional Go module path for a provider.
// It reads the provider's stored source URL first; if not set, it falls back
// to the canonical github.com/<namespace>/terraform-provider-<type> pattern.
func providerGoModule(c repositories.ProviderCandidate) string {
	if c.Source != nil && *c.Source != "" {
		// Attempt to extract a github.com/<org>/<repo> path from the URL.
		s := strings.TrimPrefix(*c.Source, "https://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimSuffix(s, ".git")
		// Only use it if it looks like github.com/<org>/<repo>
		if strings.HasPrefix(s, "github.com/") {
			parts := strings.SplitN(s, "/", 3)
			if len(parts) == 3 {
				return strings.Join(parts, "/")
			}
		}
	}
	return fmt.Sprintf("github.com/%s/terraform-provider-%s", c.Namespace, c.ProviderType)
}

// mustParseUUID parses a UUID string, returning uuid.Nil on error.
func mustParseUUID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}
