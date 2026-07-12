// releases_key_refresh_job.go implements the background job that re-fetches
// each tool's release-signing GPG key from its .well-known/pgp-key.txt
// endpoint, with strict primary-fingerprint pinning, and caches the result so
// the terraform mirror sync can prefer it over the embedded snapshot.
//
// The job also doubles as the in-process resolver consulted by gpgKeyForTool:
// when terraform mirror sync asks for a tool's key, the job hands back the
// cached row if available, "" otherwise. The caller then falls back to the
// embedded constant. This avoids a second round trip to the DB on every
// mirror tick.
//
// Expiry warnings: on every cycle, the effective key (cache ∪ embedded) is
// parsed and its earliest signing-key expiry is exported as a gauge labeled
// by source. If that expiry falls within ExpiryWarningDays the job also logs
// a high-visibility warn so it shows up in deployment logs without scraping
// Prometheus.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// allowedReleasesKeyFingerprints pins the primary-key fingerprint we trust per
// tool. Rotating to a different fingerprint is a deliberate, reviewed change —
// the refresh job will refuse anything else and keep the existing cache or
// fall back to the embedded snapshot.
var allowedReleasesKeyFingerprints = map[string]string{
	"terraform": "C874011F0AB405110D02105534365D9472D7468F", // HashiCorp Security
	"opentofu":  "",                                         // populated from the embedded snapshot at job construction
}

// ReleasesKeyRefreshJob implements ReleasesKeyResolver and runs the periodic
// upstream-key refresh. Construct via NewReleasesKeyRefreshJob and Start the
// returned value in a goroutine.
type ReleasesKeyRefreshJob struct {
	cfg        *config.ReleasesGPGKeysConfig
	repo       *repositories.ReleasesGPGKeyRepository
	httpClient *http.Client

	// tools is the iteration order — keep deterministic for predictable logs
	// and tests.
	tools []toolEndpoint

	// cache holds the in-process resolver state. The job updates it after a
	// successful upsert; SetReleasesKeyResolver(job) installs the lookup hook
	// in package jobs so terraform mirror sync sees the refreshed key.
	cacheMu sync.RWMutex
	cache   map[string]string // tool -> armored key

	stopChan chan struct{}
}

type toolEndpoint struct {
	tool        string
	url         string
	fingerprint string
}

// NewReleasesKeyRefreshJob constructs the refresh job. The embedded OpenTofu
// key is parsed eagerly so the OpenTofu fingerprint pin matches whatever is
// shipped — that avoids hardcoding a second fingerprint that must be kept in
// sync with the snapshot. A parse failure here is fatal because the job has
// nothing safe to do without a pin.
func NewReleasesKeyRefreshJob(cfg *config.ReleasesGPGKeysConfig, repo *repositories.ReleasesGPGKeyRepository, httpClient *http.Client) (*ReleasesKeyRefreshJob, error) {
	if httpClient == nil {
		// hashicorp_url / opentofu_url are operator-configurable, so the
		// default client is the SSRF-safe strict client (internal/httpsafe);
		// pass an explicit client built with an egress guard for deployments
		// that override these to an internal mirror.
		httpClient = httpsafe.NewClient(30*time.Second, nil)
	}

	// Derive the OpenTofu fingerprint from the embedded snapshot so a future
	// snapshot refresh automatically updates the pin without a second edit.
	opentofuInfo, err := mirror.ParseReleasesKey(mirror.OpenTofuReleasesGPGKey)
	if err != nil {
		return nil, fmt.Errorf("releases key refresh: parse embedded OpenTofu key: %w", err)
	}

	pins := make(map[string]string, len(allowedReleasesKeyFingerprints))
	for k, v := range allowedReleasesKeyFingerprints {
		pins[k] = v
	}
	pins["opentofu"] = opentofuInfo.PrimaryFingerprint

	tools := []toolEndpoint{
		{tool: "terraform", url: cfg.HashiCorpURL, fingerprint: pins["terraform"]},
		{tool: "opentofu", url: cfg.OpenTofuURL, fingerprint: pins["opentofu"]},
	}

	return &ReleasesKeyRefreshJob{
		cfg:        cfg,
		repo:       repo,
		httpClient: httpClient,
		tools:      tools,
		cache:      make(map[string]string, len(tools)),
		stopChan:   make(chan struct{}),
	}, nil
}

// ResolveReleasesKey implements the ReleasesKeyResolver interface consumed by
// terraform mirror sync. Returns "" when no cached key is available so the
// caller can fall back to the embedded snapshot.
func (j *ReleasesKeyRefreshJob) ResolveReleasesKey(tool string) string {
	if j == nil {
		return ""
	}
	j.cacheMu.RLock()
	defer j.cacheMu.RUnlock()
	return j.cache[strings.ToLower(tool)]
}

// Name identifies the job in the jobs.Registry (issue #565 finding [40]).
func (j *ReleasesKeyRefreshJob) Name() string { return "releases-key-refresh" }

// Start runs an initial refresh cycle, primes the in-process cache from any
// previously persisted rows, then loops on a ticker. It is a no-op when
// cfg.Enabled is false. It blocks (the Registry runs it in its own
// goroutine); the error return satisfies jobs.Job, though this job has no
// fatal startup error.
func (j *ReleasesKeyRefreshJob) Start(ctx context.Context) error {
	if !j.cfg.Enabled {
		slog.Info("releases key refresh job: disabled (releases_gpg_keys.enabled=false)")
		return nil
	}

	interval := time.Duration(j.cfg.RefreshIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	slog.Info("releases key refresh job: started",
		"interval", interval,
		"expiry_warning_days", j.cfg.ExpiryWarningDays,
	)

	// Prime in-memory cache from persisted rows so a restart immediately
	// honors the last fetched keys even if the upstream is briefly
	// unreachable on this cycle.
	j.primeCacheFromDB(ctx)

	// Run once immediately so the first sync after startup sees fresh keys
	// (or at least the most recent attempt's outcome reflected in metrics).
	j.runCycle(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			j.runCycle(ctx)
		case <-j.stopChan:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Stop signals the job to exit gracefully.
func (j *ReleasesKeyRefreshJob) Stop() error {
	if j == nil {
		return nil
	}
	select {
	case <-j.stopChan:
		// already stopped
	default:
		close(j.stopChan)
	}
	return nil
}

// primeCacheFromDB loads any persisted rows into the in-process cache so the
// resolver returns fresh keys immediately on startup, even before the first
// refresh cycle completes.
func (j *ReleasesKeyRefreshJob) primeCacheFromDB(ctx context.Context) {
	for _, t := range j.tools {
		row, err := j.repo.Get(ctx, t.tool)
		if err != nil {
			slog.Warn("releases key refresh: prime cache: db read failed",
				"tool", t.tool, "error", err)
			continue
		}
		if row == nil {
			continue
		}
		// Defense in depth: the row should already match the pin (we wrote
		// it ourselves) but a manual DB edit could break that. Verify and
		// drop on mismatch so the resolver never hands a wrong-key string
		// to the mirror sync.
		if !strings.EqualFold(row.PrimaryFingerprint, t.fingerprint) {
			slog.Error("releases key refresh: prime cache: fingerprint mismatch on persisted row; ignoring",
				"tool", t.tool,
				"got", row.PrimaryFingerprint,
				"want", t.fingerprint,
			)
			continue
		}
		j.cacheMu.Lock()
		j.cache[t.tool] = row.ArmoredKey
		j.cacheMu.Unlock()
		slog.Info("releases key refresh: primed cache from db",
			"tool", t.tool, "fingerprint", row.PrimaryFingerprint, "fetched_at", row.FetchedAt)
	}
}

// runCycle attempts to refresh each tool's key and then runs the expiry
// warning pass on the resulting effective state.
func (j *ReleasesKeyRefreshJob) runCycle(ctx context.Context) {
	for _, t := range j.tools {
		j.refreshOne(ctx, t)
	}
	j.exportExpiryGauges()
}

// refreshOne fetches a single tool's key and persists it on success. Every
// outcome bumps the per-tool counter so failure modes are visible in
// Prometheus regardless of whether they hit the log.
func (j *ReleasesKeyRefreshJob) refreshOne(ctx context.Context, t toolEndpoint) {
	armored, info, err := mirror.FetchReleasesKey(ctx, j.httpClient, t.url, t.fingerprint)
	if err != nil {
		switch {
		case errors.Is(err, mirror.ErrFingerprintMismatch):
			// This is the high-severity case: someone tried to serve us a
			// different key. Log loud, count it, keep cache untouched.
			gotFpr := ""
			if info != nil {
				gotFpr = info.PrimaryFingerprint
			}
			slog.Error("releases key refresh: FINGERPRINT MISMATCH — refusing to cache",
				"tool", t.tool,
				"url", t.url,
				"got", gotFpr,
				"want", t.fingerprint,
			)
			telemetry.ReleasesKeyRefreshTotal.WithLabelValues(t.tool, "fingerprint_mismatch").Inc()
		case errors.Is(err, mirror.ErrNoUsableSigningKey),
			errors.Is(err, mirror.ErrEmptyKeyring),
			strings.Contains(err.Error(), "parse armored"):
			slog.Warn("releases key refresh: parse failed",
				"tool", t.tool, "url", t.url, "error", err)
			telemetry.ReleasesKeyRefreshTotal.WithLabelValues(t.tool, "parse_failed").Inc()
		default:
			slog.Warn("releases key refresh: fetch failed",
				"tool", t.tool, "url", t.url, "error", err)
			telemetry.ReleasesKeyRefreshTotal.WithLabelValues(t.tool, "fetch_failed").Inc()
		}
		return
	}

	// Optimization: skip the DB write when the armored bytes haven't changed
	// since last cycle. Reduces noise in the audit log without hiding the
	// fact that we did make the upstream request (the success counter is
	// distinct from skipped_unchanged so dashboards can show both).
	j.cacheMu.RLock()
	prev, hadPrev := j.cache[t.tool]
	j.cacheMu.RUnlock()
	if hadPrev && prev == armored {
		telemetry.ReleasesKeyRefreshTotal.WithLabelValues(t.tool, "skipped_unchanged").Inc()
		return
	}

	row := &models.ReleasesGPGKey{
		Tool:               t.tool,
		ArmoredKey:         armored,
		PrimaryFingerprint: info.PrimaryFingerprint,
		SourceURL:          t.url,
	}
	if !info.LatestSigningExpiry.IsZero() {
		expiry := info.LatestSigningExpiry
		row.KeyExpiresAt = &expiry
	}
	if err := j.repo.Upsert(ctx, row); err != nil {
		slog.Warn("releases key refresh: db upsert failed",
			"tool", t.tool, "error", err)
		telemetry.ReleasesKeyRefreshTotal.WithLabelValues(t.tool, "db_failed").Inc()
		return
	}

	j.cacheMu.Lock()
	j.cache[t.tool] = armored
	j.cacheMu.Unlock()

	telemetry.ReleasesKeyRefreshTotal.WithLabelValues(t.tool, "success").Inc()
	slog.Info("releases key refresh: cached upstream key",
		"tool", t.tool, "fingerprint", info.PrimaryFingerprint,
		"expires_at", info.LatestSigningExpiry.Format(time.RFC3339),
	)
}

// exportExpiryGauges computes seconds-until-expiry for the cache (if present)
// and the embedded snapshot, sets the gauges, and logs a warn if either
// effective source is within ExpiryWarningDays of expiring.
//
// We export both sources so dashboards show the gap between cache freshness
// and embedded staleness, and so the alert still fires if the cache is
// somehow gone but the embedded snapshot is also near-expiry.
func (j *ReleasesKeyRefreshJob) exportExpiryGauges() {
	warnThreshold := time.Duration(j.cfg.ExpiryWarningDays) * 24 * time.Hour
	if warnThreshold <= 0 {
		warnThreshold = 60 * 24 * time.Hour
	}
	now := time.Now()

	for _, t := range j.tools {
		// Cache source: only if present.
		j.cacheMu.RLock()
		cached, hasCached := j.cache[t.tool]
		j.cacheMu.RUnlock()
		if hasCached {
			j.exportOne(t.tool, "cache", cached, now, warnThreshold)
		}
		// Embedded source: always present (compiled in).
		j.exportOne(t.tool, "embedded", embeddedKeyForTool(t.tool), now, warnThreshold)
	}
}

func (j *ReleasesKeyRefreshJob) exportOne(tool, source, armored string, now time.Time, warnThreshold time.Duration) {
	if armored == "" {
		return
	}
	info, err := mirror.ParseReleasesKey(armored)
	if err != nil {
		slog.Warn("releases key refresh: expiry export: parse failed",
			"tool", tool, "source", source, "error", err)
		return
	}
	if info.LatestSigningExpiry.IsZero() {
		// Key has no expiry — set gauge to 0 to surface "unknown / unset".
		telemetry.ReleasesKeyExpiresSeconds.WithLabelValues(tool, source).Set(0)
		return
	}
	remaining := info.LatestSigningExpiry.Sub(now)
	telemetry.ReleasesKeyExpiresSeconds.WithLabelValues(tool, source).Set(remaining.Seconds())

	if remaining < warnThreshold {
		level := slog.LevelWarn
		if remaining < 0 {
			level = slog.LevelError
		}
		slog.Log(context.Background(), level,
			"releases key refresh: key approaching expiry",
			"tool", tool,
			"source", source,
			"expires_at", info.LatestSigningExpiry.Format(time.RFC3339),
			"days_remaining", int(remaining.Hours()/24),
			"fingerprint", info.PrimaryFingerprint,
		)
	}
}

// embeddedKeyForTool returns the compiled-in snapshot for a tool. Kept here
// (rather than reaching into terraform_mirror_sync.go) so the refresh job
// stays a single file and tests can drop it in without dragging the full
// terraform_mirror_sync test surface.
func embeddedKeyForTool(tool string) string {
	switch strings.ToLower(tool) {
	case "terraform":
		return mirror.HashiCorpReleasesGPGKey
	case "opentofu":
		return mirror.OpenTofuReleasesGPGKey
	default:
		return ""
	}
}
