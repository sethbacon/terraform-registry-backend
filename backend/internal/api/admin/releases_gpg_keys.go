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

// ReleasesGPGKeysHandler exposes the GET /api/v1/admin/releases-gpg-keys
// endpoint. It mirrors the embedded snapshot + cache lookup logic from
// ReleasesKeyRefreshJob, but as a pure read so the UI can show the same
// effective state the mirror sync uses.
type ReleasesGPGKeysHandler struct {
	repo releasesGPGKeyRepo
	cfg  config.ReleasesGPGKeysConfig
}

// NewReleasesGPGKeysHandler constructs a ReleasesGPGKeysHandler.
func NewReleasesGPGKeysHandler(repo releasesGPGKeyRepo, cfg config.ReleasesGPGKeysConfig) *ReleasesGPGKeysHandler {
	return &ReleasesGPGKeysHandler{repo: repo, cfg: cfg}
}

// supportedReleasesGPGTools is the canonical iteration order — keep stable so
// API consumers can rely on the ordering of the response array.
var supportedReleasesGPGTools = []string{"terraform", "opentofu"}

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
	Status            string                      `json:"status"` // "ok" | "warn" | "expired" | "unknown"
}

// ReleasesGPGKeysResponse is the top-level response envelope.
type ReleasesGPGKeysResponse struct {
	Keys []ReleasesGPGKeyStatusView `json:"keys"`
}

// @Summary      Get release signing key cache + expiry state
// @Description  Returns the current cached upstream release-signing GPG key and embedded snapshot state for each supported tool (terraform, opentofu). The response includes the fingerprint, expiry, and a pre-computed status against the configured warning threshold so UIs can render a glance-level view without re-deriving the rules.
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

	out := make([]ReleasesGPGKeyStatusView, 0, len(supportedReleasesGPGTools))
	for _, tool := range supportedReleasesGPGTools {
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
	}

	cacheRow, err := h.repo.Get(ctx, tool)
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

	embedded := embeddedKeyArmoredForTool(tool)
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
