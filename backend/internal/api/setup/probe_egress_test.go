package setup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// Issue #749 — the setup wizard's connectivity probes bypassed the egress policy.
//
// internal/httpsafe guards the HTTP clients this application constructs itself.
// These two probes go out through clients it does NOT construct: the cloud
// SDK's own transport for a caller-supplied S3/GCS/Azure endpoint, and a raw
// LDAP TCP dial to a caller-supplied host:port. Neither reached
// egressGuard.ValidateURL or Guard.DialContext, so both could hit loopback,
// RFC1918 and link-local targets — including 169.254.169.254.
//
// And because both handlers returned the underlying error verbatim, the
// response distinguished "connection refused" from "timeout" from a
// protocol-level error, which turns each into an internal port-scan oracle for
// anyone holding the first-run setup token.
//
// The guard was already stored on Handlers (WithEgressGuard) and simply never
// consulted — the field was assigned and read nowhere.

func probeEnv(t *testing.T, guard *httpsafe.Guard) *Handlers {
	t.Helper()
	gin.SetMode(gin.TestMode)
	env := newTestEnv(t)
	if guard != nil {
		env.h.WithEgressGuard(guard)
	}
	return env.h
}

func postJSON(t *testing.T, handler gin.HandlerFunc, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST("/test", handler)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", jsonBody(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// internalStorageTargets are the caller-supplied endpoint fields. AzureCDNURL
// is included even though the issue named only S3 and GCS: it is the same
// shape, a caller-supplied URL the SDK dials on its own transport.
var internalStorageTargets = []struct {
	field string
	body  map[string]interface{}
}{
	{"s3_endpoint", map[string]interface{}{
		"backend_type": "s3", "s3_bucket": "b", "s3_region": "us-east-1",
		// The cloud metadata endpoint specifically: the highest-value SSRF
		// target on every major cloud.
		"s3_endpoint": "http://169.254.169.254/latest/meta-data/",
	}},
	{"gcs_endpoint", map[string]interface{}{
		"backend_type": "gcs", "gcs_bucket": "b",
		"gcs_endpoint": "http://127.0.0.1:9000",
	}},
	{"azure_cdn_url", map[string]interface{}{
		"backend_type": "azure", "azure_container_name": "c",
		"azure_account_name": "a", "azure_account_key": "k",
		"azure_cdn_url": "http://10.0.0.5/",
	}},
}

func TestTestStorageConfig_InternalEndpointsAreRefused(t *testing.T) {
	for _, tc := range internalStorageTargets {
		t.Run(tc.field, func(t *testing.T) {
			h := probeEnv(t, httpsafe.MustGuard())
			w := postJSON(t, h.TestStorageConfig, tc.body)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the probe reports failure in the body)", w.Code)
			}
			body := getJSON(w)
			if body["success"] != false {
				t.Errorf("%s pointing at an internal address reported success=%v",
					tc.field, body["success"])
			}
			msg, _ := body["message"].(string)
			if !strings.Contains(msg, "egress policy") {
				t.Errorf("message = %q, want the egress-policy refusal (the probe should "+
					"not have been attempted at all)", msg)
			}
		})
	}
}

func TestTestLDAPConfig_InternalHostIsRefused(t *testing.T) {
	h := probeEnv(t, httpsafe.MustGuard())
	w := postJSON(t, h.TestLDAPConfig, map[string]interface{}{
		"host": "127.0.0.1", "port": 389,
		"bind_dn": "cn=admin", "bind_password": "pw",
		"base_dn": "ou=users", "user_filter": "(uid=%s)",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := getJSON(w)
	if body["success"] != false {
		t.Errorf("loopback LDAP host reported success=%v", body["success"])
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "egress policy") {
		t.Errorf("message = %q, want the egress-policy refusal", msg)
	}
}

// TestProbes_FailClosedWithoutAGuard is the deployment that never called
// WithEgressGuard. Silently keeping the old unguarded behaviour there is the
// failure mode worth preventing — the guard was stored and never consulted for
// exactly that reason.
func TestProbes_FailClosedWithoutAGuard(t *testing.T) {
	h := probeEnv(t, nil)
	if err := h.probeEgressAllowed(context.Background(), "http://example.com"); err == nil {
		t.Error("probeEgressAllowed with no guard returned nil — it must fail closed")
	}
}

func TestProbeEgressAllowed_AcceptsPublicTargets(t *testing.T) {
	// The other direction: the guard must not refuse legitimate configuration,
	// or every operator turns it off.
	h := probeEnv(t, httpsafe.MustGuard())
	for _, target := range []string{
		"https://s3.us-east-1.amazonaws.com",
		"93.184.216.34:636",
	} {
		if err := h.probeEgressAllowed(context.Background(), target); err != nil {
			t.Errorf("probeEgressAllowed(%q) = %v, want nil", target, err)
		}
	}
}

// TestProbeFailure_DoesNotReflectTheTransportError is the port-scan oracle half.
//
// "connection refused" vs "i/o timeout" vs a protocol error is exactly the
// signal an internal port scan needs; the operator can still read it in the
// server log.
func TestProbeFailure_DoesNotReflectTheTransportError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	probeFailure(c, "Storage", errors.New("dial tcp 10.0.0.5:9000: connect: connection refused"))

	body := w.Body.String()
	for _, leak := range []string{"connection refused", "10.0.0.5", "dial tcp", "9000"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaked %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "server logs") {
		t.Errorf("response should point the operator at the logs: %s", body)
	}
}
