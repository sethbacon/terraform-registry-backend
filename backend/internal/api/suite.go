package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sethbacon/terraform-suite-identity/identity/suite"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

const suiteIssuer = "terraform-registry"

// suiteServiceTokenHeader is the header the sibling expects for server-to-server
// cross-app reads (it gates the sibling's /consumers). Defined locally so this
// package needs no dependency on the sibling's middleware package.
const suiteServiceTokenHeader = "X-Suite-Service-Token" // #nosec G101 -- HTTP header name, not a credential

func buildSuiteManifest(cfg *config.Config) suite.Manifest {
	pub := cfg.Server.PublicURL
	if pub == "" {
		pub = cfg.Server.BaseURL
	}
	return suite.Manifest{
		SchemaVersion: suite.SchemaVersionV1,
		App:           "terraform-registry",
		Version:       AppVersion,
		BuildDate:     AppBuildDate,
		PublicURL:     pub,
		Identity:      suite.IdentityInfo{Issuer: suiteIssuer, SharedStore: cfg.Suite.IdentitySharedStore, Schema: "identity"},
		Capabilities: []suite.Capability{
			{ID: "modules.v1"}, {ID: "providers.v1"}, {ID: "mirror.v1"}, {ID: "oci.v1"},
		},
		Links: map[string]string{"moduleDetail": "/modules/{namespace}/{name}/{system}"},
	}
}

func suiteManifestHandler(cfg *config.Config) gin.HandlerFunc {
	m := buildSuiteManifest(cfg)
	return func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=30")
		c.JSON(http.StatusOK, m)
	}
}

func uiConfigHandler(cfg *config.Config, getClient func() *suite.DiscoveryClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		out := gin.H{"sibling": nil}
		if dc := getClient(); dc != nil {
			if state, m := dc.Snapshot(); state == suite.StateActive && m != nil {
				// Single sign-on is seamless only when BOTH apps assert the shared
				// identity store; otherwise the SPA keeps its "you may need to sign
				// in" hint. issuer is informational (which app minted the sibling's
				// tokens). Forwarded only on the active branch so a stale identity
				// block can't leak during degraded/unreachable windows.
				out["sibling"] = gin.H{
					"app": m.App, "state": string(state),
					"publicUrl": m.PublicURL, "links": m.Links,
					"issuer":      m.Identity.Issuer,
					"sharedStore": cfg.Suite.IdentitySharedStore && m.Identity.SharedStore,
				}
			} else {
				out["sibling"] = gin.H{"state": string(state)}
			}
		}
		c.JSON(http.StatusOK, out)
	}
}

func startSuiteDiscovery(cfg *config.Config) *suite.DiscoveryClient {
	if cfg.Suite.SiblingURL == "" {
		return nil
	}
	dc := suite.NewDiscoveryClient(cfg.Suite.SiblingURL, buildSuiteManifest(cfg), cfg.Suite.PollInterval)
	go dc.Start(context.Background())
	return dc
}

// moduleConsumersHandler server-proxies the "Consumed by" lookup to the sibling
// Suite app (TSM): which states consume this registry module. It returns an empty
// list whenever the sibling is absent/unreachable, the sibling token is
// unconfigured, or anything fails — so the panel simply hides and the registry
// stays fully standalone. 2s timeout; never blocks the page.
//
// @Summary      List module consumers (suite)
// @Description  Server-proxies a "Consumed by" lookup to the sibling Suite app (Terraform State Manager): which managed states reference this module. Returns an empty list when the sibling is unconfigured, unreachable, or the shared suite service token is unset, so the registry stays fully standalone. Always responds 200.
// @Tags         Suite
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Success      200  {object}  map[string]interface{}  "Consuming states (rows forwarded opaquely from the sibling) and total count"
// @Failure      401  {object}  map[string]interface{}  "Authentication required"
// @Router       /api/v1/suite/modules/{namespace}/{name}/{system}/consumers [get]
func moduleConsumersHandler(getClient func() *suite.DiscoveryClient, cfg *config.Config) gin.HandlerFunc {
	// registryHost is THIS registry's own public host — the key the sibling matches
	// "consumed by" on, so it never false-joins against public-registry modules.
	// Canonicalized so it compares like-for-like against the host TSM captured
	// from the module source address (case/port/trailing-dot folded).
	registryHost := ""
	if u, err := url.Parse(cfg.Server.GetPublicURL()); err == nil {
		registryHost = canonicalHost(u.Host)
	}
	httpClient := &http.Client{Timeout: 2 * time.Second}

	return func(c *gin.Context) {
		empty := gin.H{"consumers": []any{}, "total": 0}
		dc := getClient()
		if dc == nil || registryHost == "" || cfg.Suite.SiblingToken == "" {
			c.JSON(http.StatusOK, empty)
			return
		}
		state, m := dc.Snapshot()
		if state != suite.StateActive || m == nil || m.PublicURL == "" {
			c.JSON(http.StatusOK, empty)
			return
		}

		moduleAddr := c.Param("namespace") + "/" + c.Param("name") + "/" + c.Param("system")
		target := strings.TrimRight(m.PublicURL, "/") +
			"/api/v1/consumers?host=" + url.QueryEscape(registryHost) +
			"&module=" + url.QueryEscape(moduleAddr)

		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, target, nil)
		if err != nil {
			c.JSON(http.StatusOK, empty)
			return
		}
		req.Header.Set(suiteServiceTokenHeader, cfg.Suite.SiblingToken)

		resp, err := httpClient.Do(req)
		if err != nil {
			c.JSON(http.StatusOK, empty)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			c.JSON(http.StatusOK, empty)
			return
		}

		// Forward the sibling's rows opaquely (RawMessage) — the registry does not
		// reinterpret TSM's consumer shape.
		var body struct {
			Consumers []json.RawMessage `json:"consumers"`
			Total     int               `json:"total"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			c.JSON(http.StatusOK, empty)
			return
		}
		if body.Consumers == nil {
			body.Consumers = []json.RawMessage{}
		}
		c.JSON(http.StatusOK, gin.H{"consumers": body.Consumers, "total": body.Total})
	}
}
