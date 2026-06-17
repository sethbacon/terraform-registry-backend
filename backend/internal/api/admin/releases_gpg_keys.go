// releases_gpg_keys.go implements the admin read-only endpoint that surfaces
// the state of the upstream-key refresh feature. The mirror admin page and the
// admin dashboard tile consume it to show a glance-level view of whether the
// GPG keys mirror sync uses are fresh, where they came from (cache vs
// embedded), and how close they are to expiry.
//
// All computation here is pure: read the cached row, parse the embedded
// snapshot, derive expiry math and status from the configured warning
// threshold. No writes, no upstream fetches — those belong to
// ReleasesKeyRefreshJob.
package admin

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// releasesGPGKeyRepo is the subset of ReleasesGPGKeyRepository used by this
// handler. Defining it locally keeps the handler testable without dragging
// the full repository into the mock surface.
type releasesGPGKeyRepo interface {
	Get(ctx context.Context, tool string) (*models.ReleasesGPGKey, error)
}

// mirrorConfigLister is the subset of the Terraform mirror repository used to
// discover which binaries are actually configured, so the endpoint only
// surfaces signing-key rows for those binaries.
type mirrorConfigLister interface {
	ListAll(ctx context.Context) ([]models.TerraformMirrorConfig, error)
}

// ReleasesGPGKeysHandler exposes the GET /api/v1/admin/releases-gpg-keys
// endpoint. It mirrors the embedded snapshot + cache lookup logic from
// ReleasesKeyRefreshJob, but as a pure read so the UI can show the same
// effective state the mirror sync uses.
type ReleasesGPGKeysHandler struct {
	repo    releasesGPGKeyRepo
	mirrors mirrorConfigLister
	cfg     config.ReleasesGPGKeysConfig
}

// NewReleasesGPGKeysHandler constructs a ReleasesGPGKeysHandler.
func NewReleasesGPGKeysHandler(repo releasesGPGKeyRepo, mirrors mirrorConfigLister, cfg config.ReleasesGPGKeysConfig) *ReleasesGPGKeysHandler {
	return &ReleasesGPGKeysHandler{repo: repo, mirrors: mirrors, cfg: cfg}
}

// releasesKeyFamily maps a configured binary tool to the signing-key "family"
// it verifies against: the cache/embedded lookup key, and whether a managed key
// exists at all. terraform, packer and sentinel are all signed by the same
// HashiCorp releases key, so they share the "terraform" cache/embedded entry;
// opentofu has its own key. Everything else (e.g. opa, custom) has no managed
// signing key yet, so its row is surfaced with an explicit "none" source.
func releasesKeyFamily(tool string) (keyTool string, hasManagedKey bool) {
	switch strings.ToLower(tool) {
	case "terraform", "packer", "sentinel":
		return "terraform", true
	case "opentofu":
		return "opentofu", true
	default:
		return "", false
	}
}

// configuredTools returns the distinct configured binary tools in a
// deterministic (sorted) order. Two mirrors for the same tool collapse to one
// signing-key row, since the key is per-tool, not per-config.
func (h *ReleasesGPGKeysHandler) configuredTools(ctx context.Context) ([]string, error) {
	configs, err := h.mirrors.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(configs))
	tools := make([]string, 0, len(configs))
	for _, cfg := range configs {
		tool := strings.ToLower(strings.TrimSpace(cfg.Tool))
		if tool == "" || seen[tool] {
			continue
		}
		seen[tool] = true
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	return tools, nil
}

// ReleasesGPGKeyCacheView is the cache-side block in the response. Embedded
// in the per-tool object; nil when no row has been persisted yet.
type ReleasesGPGKeyCacheView struct {
	ArmoredPresent  bool       `json:"armored_present"`
	Fingerprint     string     `json:"fingerprint"`
	FetchedAt       time.Time  `json:"fetched_at"`
	SourceURL       string     `json:"source_url"`
	KeyExpiresAt    *time.Time `json:"key_expires_at,omitempty"`
	DaysUntilExpiry *int       `json:"days_until_expiry,omitempty"`
}

// ReleasesGPGKeyEmbeddedView is the embedded-snapshot block. Always present
// because the snapshot is compiled in.
type ReleasesGPGKeyEmbeddedView struct {
	Fingerprint     string     `json:"fingerprint"`
	KeyExpiresAt    *time.Time `json:"key_expires_at,omitempty"`
	DaysUntilExpiry *int       `json:"days_until_expiry,omitempty"`
}

// ReleasesGPGKeyStatusView is one tool's row in the response. Status is
// pre-computed against ExpiryWarningDays so the UI doesn't have to re-derive
// the threshold; effective_source mirrors gpgKeyForTool so the UI shows the
// same source the mirror sync actually uses.
type ReleasesGPGKeyStatusView struct {
	Tool              string                      `json:"tool"`
	Cache             *ReleasesGPGKeyCacheView    `json:"cache"`
	Embedded          *ReleasesGPGKeyEmbeddedView `json:"embedded"`
	EffectiveSource   string                      `json:"effective_source"` // "cache" | "embedded"
	ExpiryWarningDays int                         `json:"expiry_warning_days"`
	Status            string                      `json:"status"` // "ok" | "warn" | "expired" | "unknown" | "unsigned"
}

// ReleasesGPGKeysResponse is the top-level response envelope.
type ReleasesGPGKeysResponse struct {
	Keys []ReleasesGPGKeyStatusView `json:"keys"`
}

// @Summary      Get release signing key cache + expiry state
// @Description  Returns the current cached upstream release-signing GPG key and embedded snapshot state for each configured binary mirror. Binaries that share the HashiCorp releases key (terraform, packer, sentinel) each report that key's state; opentofu reports its own. Binaries whose upstream publishes no release signature (e.g. opa — checksum-only) are listed with an explicit "none" source and an "unsigned" status, so operators can see they are verified by checksum but not by signature (distinct from "unknown"). The response includes the fingerprint, expiry, and a pre-computed status against the configured warning threshold so UIs can render a glance-level view without re-deriving the rules.
// @Tags         Terraform Mirror
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  admin.ReleasesGPGKeysResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Missing required scope"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/releases-gpg-keys [get]
func (h *ReleasesGPGKeysHandler) GetReleasesGPGKeys(c *gin.Context) {
	now := time.Now()
	warningDays := h.cfg.ExpiryWarningDays
	if warningDays <= 0 {
		warningDays = 60
	}

	tools, err := h.configuredTools(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list configured mirrors: " + err.Error()})
		return
	}

	out := make([]ReleasesGPGKeyStatusView, 0, len(tools))
	for _, tool := range tools {
		view, err := h.buildToolView(c.Request.Context(), tool, now, warningDays)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load releases key state: " + err.Error()})
			return
		}
		out = append(out, view)
	}

	c.JSON(http.StatusOK, ReleasesGPGKeysResponse{Keys: out})
}

// buildToolView assembles one tool's row. Splits cache + embedded loading,
// derives expiry math, and chooses effective source + status.
func (h *ReleasesGPGKeysHandler) buildToolView(ctx context.Context, tool string, now time.Time, warningDays int) (ReleasesGPGKeyStatusView, error) {
	view := ReleasesGPGKeyStatusView{
		Tool:              tool,
		ExpiryWarningDays: warningDays,
		Status:            "unknown",
		EffectiveSource:   "none",
	}

	// Binaries without a managed signing key (e.g. opa, custom) are still listed
	// so operators can see they are configured, but with an explicit "none"
	// source and "unknown" status — there is no key to report on yet.
	keyTool, hasManagedKey := releasesKeyFamily(tool)
	if !hasManagedKey {
		// OPA-style tools publish no release signature at all (only per-file
		// SHA-256 checksums), so mirror sync verifies them by checksum and can't
		// check authenticity. Mark them "unsigned" so the UI shows an intentional
		// "unsigned upstream" state rather than "unknown" — which reads like
		// missing data or a misconfiguration. Genuinely unclassified tools (no
		// managed key and not known-unsigned) keep the default "unknown".
		if mirror.IsUnsignedUpstreamTool(tool) {
			view.Status = "unsigned"
		}
		return view, nil
	}

	cacheRow, err := h.repo.Get(ctx, keyTool)
	if err != nil {
		return view, err
	}
	if cacheRow != nil {
		view.Cache = &ReleasesGPGKeyCacheView{
			ArmoredPresent: cacheRow.ArmoredKey != "",
			Fingerprint:    cacheRow.PrimaryFingerprint,
			FetchedAt:      cacheRow.FetchedAt,
			SourceURL:      cacheRow.SourceURL,
			KeyExpiresAt:   cacheRow.KeyExpiresAt,
		}
		if cacheRow.KeyExpiresAt != nil {
			d := daysBetween(now, *cacheRow.KeyExpiresAt)
			view.Cache.DaysUntilExpiry = &d
		}
	}

	embedded := embeddedKeyArmoredForTool(keyTool)
	if embedded != "" {
		if info, parseErr := mirror.ParseReleasesKey(embedded); parseErr == nil {
			view.Embedded = &ReleasesGPGKeyEmbeddedView{
				Fingerprint: info.PrimaryFingerprint,
			}
			if !info.LatestSigningExpiry.IsZero() {
				expiry := info.LatestSigningExpiry
				view.Embedded.KeyExpiresAt = &expiry
				d := daysBetween(now, expiry)
				view.Embedded.DaysUntilExpiry = &d
			}
		}
	}

	// Effective source: prefer cache only when its fingerprint matches the
	// embedded one. A drifted cache row (manual DB edit, future allow-list
	// rotation) is reported as effective=embedded so the UI shows what the
	// mirror sync actually uses — the refresh job's cache-prime check
	// ignores drift-fingerprint rows for the same reason.
	view.EffectiveSource = "embedded"
	if view.Cache != nil && view.Embedded != nil && view.Cache.Fingerprint == view.Embedded.Fingerprint {
		view.EffectiveSource = "cache"
	}

	// Status is derived against the effective source's expiry so the UI
	// shows the same risk operators would actually face.
	view.Status = computeStatus(view, warningDays)
	return view, nil
}

// computeStatus returns "ok", "warn", "expired", or "unknown" against the
// effective source's days-until-expiry.
func computeStatus(view ReleasesGPGKeyStatusView, warningDays int) string {
	var days *int
	if view.EffectiveSource == "cache" && view.Cache != nil {
		days = view.Cache.DaysUntilExpiry
	} else if view.Embedded != nil {
		days = view.Embedded.DaysUntilExpiry
	}
	if days == nil {
		return "unknown"
	}
	switch {
	case *days < 0:
		return "expired"
	case *days < warningDays:
		return "warn"
	default:
		return "ok"
	}
}

// daysBetween returns ceil((to - from) in days). Negative when 'to' is past.
func daysBetween(from, to time.Time) int {
	diff := to.Sub(from).Hours() / 24
	if diff >= 0 {
		return int(math.Ceil(diff))
	}
	return int(math.Floor(diff))
}

// embeddedKeyArmoredForTool returns the compiled-in snapshot. Defined here
// (rather than reaching across packages into jobs.embeddedKeyForTool which
// is unexported) so this handler stays self-contained.
func embeddedKeyArmoredForTool(tool string) string {
	switch tool {
	case "terraform":
		return mirror.HashiCorpReleasesGPGKey
	case "opentofu":
		return mirror.OpenTofuReleasesGPGKey
	default:
		return ""
	}
}
