package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sethbacon/terraform-suite-identity/identity/suite"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

const suiteIssuer = "terraform-registry"

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
		Identity:      suite.IdentityInfo{Issuer: suiteIssuer, SharedStore: false, Schema: "identity"},
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

func uiConfigHandler(getClient func() *suite.DiscoveryClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		out := gin.H{"sibling": nil}
		if dc := getClient(); dc != nil {
			if state, m := dc.Snapshot(); state == suite.StateActive && m != nil {
				out["sibling"] = gin.H{
					"app": m.App, "state": string(state),
					"publicUrl": m.PublicURL, "links": m.Links,
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
