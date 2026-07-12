package github

import (
	"os"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// TestMain widens the shared connector client's (scm.HTTPClient) egress
// policy to an explicit loopback allow-list for this test binary only: every
// test in this package points a connector at an httptest.Server, which binds
// to 127.0.0.1. Production callers get the strict default (see
// internal/scm/httpclient.go); only this test binary's egress policy changes.
func TestMain(m *testing.M) {
	if err := scm.ConfigureEgress([]string{"127.0.0.1", "::1"}); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
