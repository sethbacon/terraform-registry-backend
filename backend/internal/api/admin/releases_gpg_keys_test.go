package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// stubReleasesRepo is a configurable test double for releasesGPGKeyRepo.
type stubReleasesRepo struct {
	rows map[string]*models.ReleasesGPGKey
	err  error
}

func (s *stubReleasesRepo) Get(_ context.Context, tool string) (*models.ReleasesGPGKey, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.rows[tool], nil
}

// stubMirrorLister is a configurable test double for mirrorConfigLister.
type stubMirrorLister struct {
	configs []models.TerraformMirrorConfig
	err     error
}

func (s *stubMirrorLister) ListAll(_ context.Context) ([]models.TerraformMirrorConfig, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.configs, nil
}

// mirrorListerForTools builds a stub lister with one config per named tool.
func mirrorListerForTools(tools ...string) *stubMirrorLister {
	configs := make([]models.TerraformMirrorConfig, 0, len(tools))
	for _, tool := range tools {
		configs = append(configs, models.TerraformMirrorConfig{Tool: tool})
	}
	return &stubMirrorLister{configs: configs}
}

// defaultMirrorLister lists terraform + opentofu, matching the historical
// always-on pair so existing tests exercise both signing-key rows.
func defaultMirrorLister() *stubMirrorLister {
	return mirrorListerForTools("terraform", "opentofu")
}

func newReleasesGPGRouter(t *testing.T, repo releasesGPGKeyRepo, cfg config.ReleasesGPGKeysConfig) *gin.Engine {
	return newReleasesGPGRouterWithMirrors(t, repo, defaultMirrorLister(), cfg)
}

func newReleasesGPGRouterWithMirrors(t *testing.T, repo releasesGPGKeyRepo, mirrors mirrorConfigLister, cfg config.ReleasesGPGKeysConfig) *gin.Engine {
	t.Helper()
	h := NewReleasesGPGKeysHandler(repo, mirrors, cfg)
	r := gin.New()
	r.GET("/admin/terraform-mirrors/releases-gpg-keys", h.GetReleasesGPGKeys)
	return r
}

// defaultCfg returns a config equivalent to the production defaults so
// status-threshold tests reflect real behaviour.
func defaultReleasesCfg() config.ReleasesGPGKeysConfig {
	return config.ReleasesGPGKeysConfig{
		Enabled:              true,
		RefreshIntervalHours: 24,
		ExpiryWarningDays:    60,
		HashiCorpURL:         "https://www.hashicorp.com/.well-known/pgp-key.txt",
		OpenTofuURL:          "https://opentofu.org/.well-known/pgp-key.txt",
	}
}

// invokeAndDecode runs a GET and returns the decoded response or fails the test.
func invokeAndDecode(t *testing.T, r *gin.Engine) (int, ReleasesGPGKeysResponse) {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/terraform-mirrors/releases-gpg-keys", nil))
	if w.Code != http.StatusOK {
		return w.Code, ReleasesGPGKeysResponse{}
	}
	var body ReleasesGPGKeysResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return w.Code, body
}

// findTool returns the per-tool view from a response, failing the test if absent.
func findTool(t *testing.T, body ReleasesGPGKeysResponse, tool string) ReleasesGPGKeyStatusView {
	t.Helper()
	for _, k := range body.Keys {
		if k.Tool == tool {
			return k
		}
	}
	t.Fatalf("tool %q not found in response", tool)
	return ReleasesGPGKeyStatusView{}
}

func TestReleasesGPGKeys_NoCacheRows_EmbeddedFallback(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouter(t, repo, defaultReleasesCfg())

	code, body := invokeAndDecode(t, r)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(body.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(body.Keys))
	}

	tf := findTool(t, body, "terraform")
	if tf.Cache != nil {
		t.Error("terraform: expected nil Cache when no row")
	}
	if tf.Embedded == nil {
		t.Fatal("terraform: expected Embedded block to be populated")
	}
	if tf.EffectiveSource != "embedded" {
		t.Errorf("terraform: EffectiveSource = %q, want embedded", tf.EffectiveSource)
	}
	if tf.Status == "unknown" {
		// The embedded snapshot has a known expiry; status should not be unknown.
		t.Error("terraform: expected status to be derived from embedded expiry, got unknown")
	}
}

func TestReleasesGPGKeys_CacheRowMatchesEmbedded_EffectiveSourceCache(t *testing.T) {
	// Parse the embedded snapshot so the test cache row has a matching fingerprint.
	info, err := mirror.ParseReleasesKey(mirror.HashiCorpReleasesGPGKey)
	if err != nil {
		t.Fatalf("parse embedded: %v", err)
	}
	expiry := time.Now().Add(365 * 24 * time.Hour)
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{
		"terraform": {
			Tool:               "terraform",
			ArmoredKey:         mirror.HashiCorpReleasesGPGKey,
			PrimaryFingerprint: info.PrimaryFingerprint,
			KeyExpiresAt:       &expiry,
			SourceURL:          "https://www.hashicorp.com/.well-known/pgp-key.txt",
			FetchedAt:          time.Now().Add(-2 * time.Hour),
		},
	}}
	r := newReleasesGPGRouter(t, repo, defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	tf := findTool(t, body, "terraform")

	if tf.Cache == nil {
		t.Fatal("expected Cache block to be populated")
	}
	if !tf.Cache.ArmoredPresent {
		t.Error("ArmoredPresent = false, want true (row has armored bytes)")
	}
	if tf.Cache.Fingerprint != info.PrimaryFingerprint {
		t.Errorf("cache fingerprint = %q, want %q", tf.Cache.Fingerprint, info.PrimaryFingerprint)
	}
	if tf.EffectiveSource != "cache" {
		t.Errorf("EffectiveSource = %q, want cache", tf.EffectiveSource)
	}
	if tf.Status != "ok" {
		t.Errorf("Status = %q, want ok for 365-day expiry", tf.Status)
	}
	if tf.Cache.DaysUntilExpiry == nil {
		t.Error("DaysUntilExpiry should be set when KeyExpiresAt is non-nil")
	} else if *tf.Cache.DaysUntilExpiry < 360 || *tf.Cache.DaysUntilExpiry > 366 {
		t.Errorf("DaysUntilExpiry = %d, want ~365", *tf.Cache.DaysUntilExpiry)
	}
}

func TestReleasesGPGKeys_CacheFingerprintDrift_EffectiveSourceEmbedded(t *testing.T) {
	// Cache row exists but has a different fingerprint (e.g. allow-list bumped
	// and a stale row left behind). Effective source must report embedded so
	// the UI shows what the mirror sync actually uses.
	expiry := time.Now().Add(365 * 24 * time.Hour)
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{
		"terraform": {
			Tool:               "terraform",
			ArmoredKey:         "ARMORED-WITH-WRONG-FPR",
			PrimaryFingerprint: "0000000000000000000000000000000000000000",
			KeyExpiresAt:       &expiry,
			SourceURL:          "https://example.com",
			FetchedAt:          time.Now(),
		},
	}}
	r := newReleasesGPGRouter(t, repo, defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	tf := findTool(t, body, "terraform")
	if tf.EffectiveSource != "embedded" {
		t.Errorf("EffectiveSource = %q, want embedded (cache fpr does not match embedded)", tf.EffectiveSource)
	}
}

func TestReleasesGPGKeys_Status_Expired(t *testing.T) {
	// Cache row matches embedded fingerprint but expired yesterday.
	info, _ := mirror.ParseReleasesKey(mirror.HashiCorpReleasesGPGKey)
	expired := time.Now().Add(-24 * time.Hour)
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{
		"terraform": {
			Tool:               "terraform",
			ArmoredKey:         mirror.HashiCorpReleasesGPGKey,
			PrimaryFingerprint: info.PrimaryFingerprint,
			KeyExpiresAt:       &expired,
			SourceURL:          "https://example.com",
			FetchedAt:          time.Now(),
		},
	}}
	r := newReleasesGPGRouter(t, repo, defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	tf := findTool(t, body, "terraform")
	if tf.Status != "expired" {
		t.Errorf("Status = %q, want expired", tf.Status)
	}
	if tf.Cache == nil || tf.Cache.DaysUntilExpiry == nil {
		t.Fatal("expected DaysUntilExpiry to be set on cache view")
	}
	if *tf.Cache.DaysUntilExpiry >= 0 {
		t.Errorf("expected negative days, got %d", *tf.Cache.DaysUntilExpiry)
	}
}

func TestReleasesGPGKeys_Status_Warn(t *testing.T) {
	info, _ := mirror.ParseReleasesKey(mirror.HashiCorpReleasesGPGKey)
	// Effective key expires in 30 days — inside the default 60-day warning window.
	soon := time.Now().Add(30 * 24 * time.Hour)
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{
		"terraform": {
			Tool:               "terraform",
			ArmoredKey:         mirror.HashiCorpReleasesGPGKey,
			PrimaryFingerprint: info.PrimaryFingerprint,
			KeyExpiresAt:       &soon,
			SourceURL:          "https://example.com",
			FetchedAt:          time.Now(),
		},
	}}
	r := newReleasesGPGRouter(t, repo, defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	tf := findTool(t, body, "terraform")
	if tf.Status != "warn" {
		t.Errorf("Status = %q, want warn for 30d expiry with 60d threshold", tf.Status)
	}
}

func TestReleasesGPGKeys_DefaultWarningDays_AppliedWhenConfigZero(t *testing.T) {
	// Cfg with ExpiryWarningDays = 0 must fall back to 60.
	cfg := defaultReleasesCfg()
	cfg.ExpiryWarningDays = 0
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouter(t, repo, cfg)

	_, body := invokeAndDecode(t, r)
	for _, k := range body.Keys {
		if k.ExpiryWarningDays != 60 {
			t.Errorf("%s: ExpiryWarningDays = %d, want 60 (default)", k.Tool, k.ExpiryWarningDays)
		}
	}
}

func TestReleasesGPGKeys_DBError_Returns500(t *testing.T) {
	repo := &stubReleasesRepo{err: errors.New("db down")}
	r := newReleasesGPGRouter(t, repo, defaultReleasesCfg())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/terraform-mirrors/releases-gpg-keys", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// When terraform and opentofu are both configured, both signing-key rows are
// returned. Rows now follow the configured binaries rather than a fixed list.
func TestReleasesGPGKeys_ConfiguredToolsReturned(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouter(t, repo, defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	seen := map[string]bool{}
	for _, k := range body.Keys {
		seen[k.Tool] = true
	}
	if !seen["terraform"] || !seen["opentofu"] {
		t.Errorf("expected both terraform and opentofu in response, got %+v", seen)
	}
}

// Only binaries that are actually configured produce a row.
func TestReleasesGPGKeys_OnlyConfiguredBinariesReturned(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouterWithMirrors(t, repo, mirrorListerForTools("opentofu"), defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	if len(body.Keys) != 1 {
		t.Fatalf("expected 1 key (opentofu only), got %d: %+v", len(body.Keys), body.Keys)
	}
	if body.Keys[0].Tool != "opentofu" {
		t.Errorf("tool = %q, want opentofu", body.Keys[0].Tool)
	}
}

// terraform, packer and sentinel all verify against the HashiCorp releases key,
// so each configured one gets its own row backed by that same embedded key.
func TestReleasesGPGKeys_SharedHashiCorpKeyPerBinary(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouterWithMirrors(t, repo, mirrorListerForTools("packer", "sentinel"), defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	if len(body.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(body.Keys))
	}
	hcInfo, err := mirror.ParseReleasesKey(mirror.HashiCorpReleasesGPGKey)
	if err != nil {
		t.Fatalf("parse embedded: %v", err)
	}
	for _, tool := range []string{"packer", "sentinel"} {
		row := findTool(t, body, tool)
		if row.Embedded == nil {
			t.Fatalf("%s: expected embedded HashiCorp key block", tool)
		}
		if row.Embedded.Fingerprint != hcInfo.PrimaryFingerprint {
			t.Errorf("%s: fingerprint = %q, want HashiCorp %q", tool, row.Embedded.Fingerprint, hcInfo.PrimaryFingerprint)
		}
		if row.EffectiveSource != "embedded" {
			t.Errorf("%s: effective source = %q, want embedded", tool, row.EffectiveSource)
		}
	}
}

// opa publishes no release signature (checksum-only). It is still listed (it is
// configured) with an explicit "none" source, no key blocks, and an "unsigned"
// status — so operators see it is verified by checksum but not by signature,
// distinct from a missing-data "unknown".
func TestReleasesGPGKeys_UnsignedUpstreamBinaryHasUnsignedStatus(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouterWithMirrors(t, repo, mirrorListerForTools("opa"), defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	if len(body.Keys) != 1 {
		t.Fatalf("expected 1 key (opa), got %d", len(body.Keys))
	}
	opa := findTool(t, body, "opa")
	if opa.EffectiveSource != "none" {
		t.Errorf("effective source = %q, want none", opa.EffectiveSource)
	}
	if opa.Status != "unsigned" {
		t.Errorf("status = %q, want unsigned", opa.Status)
	}
	if opa.Cache != nil || opa.Embedded != nil {
		t.Errorf("expected no cache/embedded for opa, got cache=%v embedded=%v", opa.Cache, opa.Embedded)
	}
}

// A configured tool that is neither key-managed nor known-unsigned keeps the
// default "unknown" status — the "unsigned" marker is reserved for tools we know
// publish no signature (opa), not for unclassified ones.
func TestReleasesGPGKeys_UnclassifiedToolIsUnknown(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouterWithMirrors(t, repo, mirrorListerForTools("futuretool"), defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	row := findTool(t, body, "futuretool")
	if row.EffectiveSource != "none" {
		t.Errorf("effective source = %q, want none", row.EffectiveSource)
	}
	if row.Status != "unknown" {
		t.Errorf("status = %q, want unknown", row.Status)
	}
}

// Nothing configured => empty response (the UI shows its no-data state).
func TestReleasesGPGKeys_NoConfiguredBinaries_EmptyResponse(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	r := newReleasesGPGRouterWithMirrors(t, repo, mirrorListerForTools(), defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	if len(body.Keys) != 0 {
		t.Fatalf("expected 0 keys when nothing configured, got %d", len(body.Keys))
	}
}

// Two mirrors for the same tool collapse to a single signing-key row.
func TestReleasesGPGKeys_DuplicateToolDeduped(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	lister := &stubMirrorLister{configs: []models.TerraformMirrorConfig{
		{Tool: "terraform"}, {Tool: "terraform"},
	}}
	r := newReleasesGPGRouterWithMirrors(t, repo, lister, defaultReleasesCfg())

	_, body := invokeAndDecode(t, r)
	if len(body.Keys) != 1 {
		t.Fatalf("expected 1 deduped terraform row, got %d", len(body.Keys))
	}
}

// A failure listing configured mirrors surfaces as a 500.
func TestReleasesGPGKeys_MirrorListError_Returns500(t *testing.T) {
	repo := &stubReleasesRepo{rows: map[string]*models.ReleasesGPGKey{}}
	lister := &stubMirrorLister{err: errors.New("db down")}
	r := newReleasesGPGRouterWithMirrors(t, repo, lister, defaultReleasesCfg())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/terraform-mirrors/releases-gpg-keys", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDaysBetween_Symmetry(t *testing.T) {
	// Future: positive days.
	if got := daysBetween(time.Unix(0, 0), time.Unix(86400*10, 0)); got != 10 {
		t.Errorf("daysBetween(+10d) = %d, want 10", got)
	}
	// Past: negative days.
	if got := daysBetween(time.Unix(86400*10, 0), time.Unix(0, 0)); got >= 0 {
		t.Errorf("daysBetween(-10d) = %d, want negative", got)
	}
}

func TestEmbeddedKeyArmoredForTool(t *testing.T) {
	if embeddedKeyArmoredForTool("terraform") == "" {
		t.Error("expected non-empty terraform key")
	}
	if embeddedKeyArmoredForTool("opentofu") == "" {
		t.Error("expected non-empty opentofu key")
	}
	if embeddedKeyArmoredForTool("nope") != "" {
		t.Error("expected empty for unknown tool")
	}
}
