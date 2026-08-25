package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	identityhttpsafe "github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	"github.com/sethbacon/terraform-suite-identity/identity/suite"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/safego"
	"github.com/terraform-registry/terraform-registry/internal/tenantscope"
)

// maxConsumersResponseBytes bounds the sibling's "/consumers" JSON response
// body. The 2s Timeout on the client below bounds wall-clock time, not bytes;
// without this cap a slow-trickle or oversized response would be fully
// buffered in memory by json.Decode.
const maxConsumersResponseBytes = 1 << 20 // 1 MB

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
		// This app's OWN public URL, asserted about itself. It is untrusted from
		// the READER's point of view, which is what the type records — the
		// sibling receiving this manifest must resolve it through its own egress
		// guard before fetching it, exactly as the registry does below with the
		// sibling's.
		PublicURL: suite.UntrustedURL(pub),
		Identity:  suite.IdentityInfo{Issuer: suiteIssuer, SharedStore: cfg.Suite.IdentitySharedStore, Schema: "identity"},
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
	// The discovery client carries the deployment's egress policy from v0.25.0
	// on: it is what validates and dials both the manifest poll and, via
	// SiblingPublicURL/GuardedClient, anything a consumer builds on the
	// sibling-asserted publicUrl. A separate instance built from the same
	// security.egress.allowlist as router.go's egressGuard/identityGuard,
	// following the convention already established there — the Guard is
	// immutable and policy-equivalent, so instance identity carries no meaning.
	guard, err := identityhttpsafe.NewGuard(cfg.Security.Egress.Allowlist)
	if err != nil {
		slog.Error("suite: invalid security.egress.allowlist; sibling discovery disabled", "error", err)
		return nil
	}
	// NewDiscoveryClient now fails closed on a plaintext "http://" sibling URL
	// (v0.17.0) rather than constructing a client for it; treat that the same
	// as "no sibling configured" — non-fatal, the registry stays standalone.
	dc, err := suite.NewDiscoveryClient(cfg.Suite.SiblingURL, buildSuiteManifest(cfg), cfg.Suite.PollInterval, guard)
	if err != nil {
		slog.Error("suite: failed to start sibling discovery client", "sibling_url", cfg.Suite.SiblingURL, "error", err)
		return nil
	}
	safego.Go(func() { dc.Start(context.Background()) })
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
func moduleConsumersHandler(getClient func() *suite.DiscoveryClient, cfg *config.Config, egressGuard *httpsafe.Guard, orgRepo *repositories.OrganizationRepository) gin.HandlerFunc {
	// hosts is THIS registry's set of canonical host identities the sibling
	// matches "consumed by" on: its public host, its base/discovery host, and any
	// operator-configured aliases (TFR_SERVER_HOST_ALIASES) for vanity-CNAME or
	// port-asymmetry deployments. Canonicalized + de-duped so the join compares
	// like-for-like against the host TSM captured from the module source address.
	hosts := canonicalHostSet(cfg.Server.GetPublicURL(), cfg.Server.BaseURL, cfg.Server.HostAliases)
	// Routed through the shared httpsafe egress guard like every other outbound
	// client in this codebase: m.PublicURL is the sibling's self-advertised
	// discovery field, not the operator-pinned SiblingURL, so it is untrusted
	// input that must be resolve-and-pinned (and re-validated on redirect) the
	// same as any other operator/upstream-influenced target (issue #653).
	httpClient := httpsafe.NewClient(2*time.Second, egressGuard)

	return func(c *gin.Context) {
		empty := gin.H{"consumers": []any{}, "total": 0}
		dc := getClient()
		if dc == nil || len(hosts) == 0 || cfg.Suite.SiblingToken == "" {
			c.JSON(http.StatusOK, empty)
			return
		}
		// SiblingPublicURL is the whole sequence in one call: sibling must be
		// Active, must advertise a publicUrl, and that URL — self-advertised by
		// the sibling, not operator-pinned — must pass the deployment's egress
		// policy before anything is built from it. It replaces the snapshot
		// check, the emptiness check and the standalone ValidateURL pre-flight
		// that used to sit here as three separate steps any of which could be
		// dropped. Every failure is still an empty 200, so the panel hides and
		// the registry stays standalone.
		siblingBase, err := dc.SiblingPublicURL(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusOK, empty)
			return
		}

		// siblingURL is the trusted origin advertised via discovery — the single
		// host the outbound request below is permitted to reach.
		siblingURL, err := url.Parse(siblingBase)
		if err != nil || siblingURL.Host == "" {
			c.JSON(http.StatusOK, empty)
			return
		}

		moduleAddr := c.Param("namespace") + "/" + c.Param("name") + "/" + c.Param("system")

		// Resolve which organizations this caller may read modules in. The
		// route sits in the authenticated group with no RequireScope, so this
		// is the only place the caller's tenancy is established.
		scope, err := tenantscope.Resolve(c, orgRepo, auth.ScopeModulesRead)
		if err != nil {
			slog.Warn("suite consumers: could not resolve caller organization scope",
				"error", err)
			c.JSON(http.StatusOK, empty)
			return
		}
		// A caller who holds no organizations and is not a platform admin can
		// legitimately see no consumers at all. Answer empty WITHOUT asking the
		// sibling: doing so closes this half of the disclosure now, rather than
		// waiting for the sibling to start enforcing the parameter below.
		if !scope.PlatformAdmin && len(scope.OrgIDs) == 0 {
			c.JSON(http.StatusOK, empty)
			return
		}

		// Build the outbound URL structurally from the trusted sibling origin
		// (siblingURL, parsed from the discovery-advertised PublicURL). The
		// user-provided module address and the registry's own host set are
		// attached only as escaped query parameters via net/url, so they cannot
		// influence the request scheme/host/path — the request authority is
		// fixed to the sibling by construction. (Resolves CodeQL
		// go/request-forgery: structured net/url construction confines the
		// untrusted input to the query component instead of concatenating it
		// into the URL string, which the taint analysis cannot localize.)
		target := *siblingURL
		target.Path = strings.TrimRight(siblingURL.Path, "/") + "/api/v1/consumers"
		// Emit every acceptable host as a repeated host= param; the sibling
		// matches a state if its captured host is any of them.
		q := url.Values{}
		q.Set("module", moduleAddr)
		for _, h := range hosts {
			q.Add("host", h)
		}
		// NAME THE CALLER'S ORGANIZATIONS (#439).
		//
		// The sibling's /consumers has no principal of its own -- it is
		// authenticated only by the shared suite service token -- so it cannot
		// work out who is asking. Today it ignores this parameter and answers
		// fleet-wide, which is why a registry user in one organization can see
		// another's source names and state keys through this proxy. Sending the
		// scope is what lets the sibling start enforcing it; until it does, this
		// is inert on the wire and changes nothing.
		//
		// A platform admin deliberately sends none: that scope crosses
		// organization boundaries here exactly as it does everywhere else, and
		// the absence of the parameter is what the sibling will read as
		// "fleet-wide", gated on its own operator opt-in.
		for _, orgID := range scope.OrgIDs {
			q.Add("organization", orgID)
		}
		target.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, target.String(), nil)
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
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxConsumersResponseBytes)).Decode(&body); err != nil {
			c.JSON(http.StatusOK, empty)
			return
		}
		if body.Consumers == nil {
			body.Consumers = []json.RawMessage{}
		}
		c.JSON(http.StatusOK, gin.H{"consumers": body.Consumers, "total": body.Total})
	}
}
