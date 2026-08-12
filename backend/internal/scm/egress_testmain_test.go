package scm

import (
	"os"
	"testing"
)

// TestMain widens the shared connector client's (HTTPClient) egress policy to an explicit
// loopback allow-list for this test binary only, so the DoJSON/ExchangeOAuthForm tests can
// talk to an httptest.Server (which binds to 127.0.0.1). Production callers get the strict
// default (see httpclient.go); only this test binary's egress policy changes. Mirrors the
// TestMain each connector subpackage already installs.
func TestMain(m *testing.M) {
	if err := ConfigureEgress([]string{"127.0.0.1", "::1"}); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
