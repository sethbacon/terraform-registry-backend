package httpsafe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeResolver returns a lookupIP func that always resolves to the given IPs.
func fakeResolver(ips ...string) func(context.Context, string) ([]net.IP, error) {
	parsed := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		parsed = append(parsed, net.ParseIP(s))
	}
	return func(context.Context, string) ([]net.IP, error) {
		return parsed, nil
	}
}

// ---------------------------------------------------------------------------
// NewGuard
// ---------------------------------------------------------------------------

func TestNewGuard_ValidEntries(t *testing.T) {
	g, err := NewGuard([]string{"registry.corp.internal", "10.1.2.3", "10.20.0.0/16", "fd00::/8", " ", ""})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if !g.HostExempt("REGISTRY.corp.INTERNAL") {
		t.Error("hostname allow-list entry should be case-insensitive")
	}
	if !g.HostExempt("10.1.2.3") {
		t.Error("IP allow-list entry not honored")
	}
	if !g.HostExempt("10.20.55.1") {
		t.Error("CIDR allow-list entry not honored")
	}
	if !g.HostExempt("fd00::1") {
		t.Error("IPv6 CIDR allow-list entry not honored")
	}
	if g.HostExempt("10.21.0.1") {
		t.Error("IP outside allow-listed CIDR should not be exempt")
	}
}

func TestNewGuard_InvalidEntry(t *testing.T) {
	if _, err := NewGuard([]string{"10.0.0.0/99"}); err == nil {
		t.Error("expected error for malformed CIDR")
	}
	if _, err := NewGuard([]string{"host with spaces"}); err == nil {
		t.Error("expected error for entry with spaces")
	}
}

// ---------------------------------------------------------------------------
// ValidateURL — denied ranges
// ---------------------------------------------------------------------------

func TestValidateURL_DeniedRanges(t *testing.T) {
	var g *Guard // nil guard = strict default policy
	denied := []string{
		"http://127.0.0.1/path",            // IPv4 loopback
		"http://127.8.9.10/",               // loopback /8
		"http://[::1]:8080/",               // IPv6 loopback
		"http://10.0.0.1/",                 // RFC 1918
		"http://172.16.0.1/",               // RFC 1918
		"http://172.31.255.254/",           // RFC 1918 upper edge
		"http://192.168.1.1/",              // RFC 1918
		"http://169.254.169.254/latest",    // link-local / cloud metadata
		"http://[fe80::1]/",                // IPv6 link-local
		"http://[fc00::1]/",                // IPv6 ULA
		"http://[fd12:3456::1]/",           // IPv6 ULA
		"http://0.0.0.0/",                  // unspecified
		"http://0.1.2.3/",                  // 0.0.0.0/8
		"http://224.0.0.1/",                // multicast
		"http://[ff02::1]/",                // IPv6 multicast
		"http://255.255.255.255/",          // broadcast
		"http://100.64.0.1/",               // carrier-grade NAT
		"http://[::ffff:127.0.0.1]/",       // IPv4-mapped loopback
		"http://[::ffff:169.254.169.254]/", // IPv4-mapped metadata
	}
	for _, u := range denied {
		if err := g.ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want blocked", u)
		}
	}
}

func TestValidateURL_PublicAllowed(t *testing.T) {
	var g *Guard
	for _, u := range []string{"https://8.8.8.8/", "http://1.1.1.1:8080/x", "https://[2606:4700::1111]/"} {
		if err := g.ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", u, err)
		}
	}
}

func TestValidateURL_SchemeAndHost(t *testing.T) {
	var g *Guard
	if err := g.ValidateURL("ftp://example.com/x"); err == nil {
		t.Error("expected error for ftp scheme")
	}
	if err := g.ValidateURL("file:///etc/passwd"); err == nil {
		t.Error("expected error for file scheme")
	}
	if err := g.ValidateURL("https:///nohost"); err == nil {
		t.Error("expected error for empty host")
	}
}

func TestValidateURL_ResolvedPrivateRejected(t *testing.T) {
	g := MustGuard()
	g.lookupIP = fakeResolver("192.168.7.7")
	if err := g.ValidateURL("https://internal.example.com/"); err == nil {
		t.Error("hostname resolving to RFC 1918 should be rejected")
	}
}

func TestValidateURL_MixedResolutionRejected(t *testing.T) {
	g := MustGuard()
	g.lookupIP = fakeResolver("93.184.216.34", "10.0.0.5")
	if err := g.ValidateURL("https://dual.example.com/"); err == nil {
		t.Error("hostname resolving to any private address should be rejected")
	}
}

func TestValidateURL_ResolvedPublicAllowed(t *testing.T) {
	g := MustGuard()
	g.lookupIP = fakeResolver("93.184.216.34")
	if err := g.ValidateURL("https://public.example.com/"); err != nil {
		t.Errorf("public resolution should pass, got %v", err)
	}
}

func TestValidateURL_LookupFailureFailsOpen(t *testing.T) {
	g := MustGuard()
	g.lookupIP = func(context.Context, string) ([]net.IP, error) {
		return nil, fmt.Errorf("no such host")
	}
	// Dial-time enforcement is authoritative; config-write validation must not
	// reject names that don't resolve from this vantage point.
	if err := g.ValidateURL("https://unresolvable.example.com/"); err != nil {
		t.Errorf("lookup failure should fail open at validation time, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateURL — allow-list overrides
// ---------------------------------------------------------------------------

func TestValidateURL_AllowlistOverrides(t *testing.T) {
	cases := []struct {
		allow []string
		url   string
	}{
		{[]string{"127.0.0.1"}, "http://127.0.0.1:8081/"},
		{[]string{"10.20.0.0/16"}, "https://10.20.4.2/"},
		{[]string{"registry.corp.internal"}, "https://registry.corp.internal/v1"},
		{[]string{"169.254.169.254"}, "http://169.254.169.254/"},
	}
	for _, tc := range cases {
		g := MustGuard(tc.allow...)
		g.lookupIP = fakeResolver("10.20.4.2") // for the hostname case
		if err := g.ValidateURL(tc.url); err != nil {
			t.Errorf("allowlist %v: ValidateURL(%q) = %v, want nil", tc.allow, tc.url, err)
		}
	}
}

// ---------------------------------------------------------------------------
// DialContext — resolve-and-pin
// ---------------------------------------------------------------------------

func TestDialContext_IPLiteralDenied(t *testing.T) {
	var g *Guard
	if _, err := g.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Error("dial to metadata IP should be blocked")
	}
	if _, err := g.DialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Error("dial to loopback should be blocked")
	}
}

func TestDialContext_ResolvedPrivateDenied(t *testing.T) {
	g := MustGuard()
	g.lookupIP = fakeResolver("127.0.0.1")
	if _, err := g.DialContext(context.Background(), "tcp", "rebind.example.com:80"); err == nil {
		t.Error("hostname resolving to loopback should be blocked at dial time")
	}
}

func TestDialContext_PinsValidatedIP(t *testing.T) {
	// The listener's real address is 127.0.0.1; the guard only permits it via
	// the CIDR allow-list. The fake resolver maps a fake hostname to the
	// listener IP, proving the dialed IP is the one that was resolved+checked.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr == nil {
			conn.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	g := MustGuard("127.0.0.0/8")
	g.lookupIP = fakeResolver(host)

	conn, err := g.DialContext(context.Background(), "tcp", net.JoinHostPort("pinned.example.com", port))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
}

// ---------------------------------------------------------------------------
// Client — redirects
// ---------------------------------------------------------------------------

// localhostGuard permits httptest servers via the "localhost" hostname while
// keeping the 127.0.0.1 IP itself denied, so redirect targets using the IP
// literal exercise the deny path.
func localhostURL(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return "http://localhost:" + port
}

func TestClient_RedirectToPrivateRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, MustGuard("localhost"))
	resp, err := client.Get(localhostURL(t, srv))
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect to metadata endpoint should be rejected")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("expected egress-blocked error, got: %v", err)
	}
}

func TestClient_RedirectToLoopbackIPRejected(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same machine, but via the raw IP that is NOT allow-listed.
		http.Redirect(w, r, srv.URL+"/internal", http.StatusFound)
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, MustGuard("localhost"))
	resp, err := client.Get(localhostURL(t, srv))
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect to non-allow-listed loopback IP should be rejected")
	}
}

func TestClient_CrossHostRedirectStripsCredentials(t *testing.T) {
	var gotAuth, gotCookie string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
	}))
	defer target.Close()

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/after", http.StatusFound) // 127.0.0.1 — different host than "localhost"
	}))
	defer src.Close()

	client := NewClient(5*time.Second, MustGuard("localhost", "127.0.0.1"))
	req, err := http.NewRequest(http.MethodGet, localhostURL(t, src), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "" {
		t.Errorf("Authorization header leaked across hosts: %q", gotAuth)
	}
	if gotCookie != "" {
		t.Errorf("Cookie header leaked across hosts: %q", gotCookie)
	}
}

func TestClient_SameHostRedirectKeepsCredentials(t *testing.T) {
	var gotAuth string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
			http.Redirect(w, r, "http://localhost:"+port+"/after", http.StatusFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, MustGuard("localhost"))
	req, err := http.NewRequest(http.MethodGet, localhostURL(t, srv)+"/start", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer keep-me")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer keep-me" {
		t.Errorf("same-host redirect should keep Authorization, got %q", gotAuth)
	}
}

// A cross-host redirect that resends a request body must be refused outright,
// not have its body silently stripped: header stripping alone misses
// credentials carried in the body itself (e.g. an OAuth client_secret in a
// token-exchange POST form), which a compromised/MITM'd/typo-squatted
// upstream can exfiltrate via a single 307/308 to an attacker host.
func TestClient_CrossHostRedirectWithBodyRefused(t *testing.T) {
	var attackerReceivedBody bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			attackerReceivedBody = true
		}
	}))
	defer attacker.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusTemporaryRedirect) // 307 preserves method+body
	}))
	defer origin.Close()

	client := NewClient(5*time.Second, MustGuard("localhost", "127.0.0.1"))
	req, err := http.NewRequest(http.MethodPost, localhostURL(t, origin),
		strings.NewReader("client_id=abc&client_secret=SUPERSECRET&code=xyz"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	if attackerReceivedBody {
		t.Fatal("cross-host redirect resent the request body to the redirect target")
	}
	if err == nil {
		t.Fatal("cross-host redirect carrying a body should be refused, not followed")
	}
}

// Same hostname but a different port (or scheme) is NOT the same origin: an
// open-redirect on a self-hosted instance, a misrouted reverse proxy, or a
// compromised upstream could otherwise retain credentials across the hop.
func TestClient_SameHostDifferentPortStripsCredentials(t *testing.T) {
	var gotAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer target.Close()
	targetHost, targetPort, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+targetHost+":"+targetPort+"/after", http.StatusFound)
	}))
	defer src.Close()

	client := NewClient(5*time.Second, MustGuard("localhost", "127.0.0.1"))
	req, err := http.NewRequest(http.MethodGet, localhostURL(t, src), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "" {
		t.Errorf("Authorization header leaked across a port change: %q", gotAuth)
	}
}

// NewClient must not honor HTTP_PROXY/HTTPS_PROXY: a proxied request is
// dialed to the proxy's address, which the guard validates and pins, while
// the real destination travels inside the forwarded request/CONNECT line and
// is never resolved or checked at all — silently defeating resolve-and-pin
// for every guarded egress path whenever a proxy env var is set.
func TestNewClient_DoesNotHonorEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	client := NewClient(5*time.Second, nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		req, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/", nil)
		proxyURL, err := transport.Proxy(req)
		if err == nil && proxyURL != nil {
			t.Fatalf("transport.Proxy resolved a proxy (%s) despite HTTP_PROXY being set; resolve-and-pin would be bypassed", proxyURL)
		}
	}
}

func TestClient_AllowlistedFetchSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, MustGuard("127.0.0.1"))
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestClient_StrictGuardBlocksLoopbackFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	client := NewClient(5*time.Second, nil)
	resp, err := client.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("strict client should refuse to dial loopback")
	}
}

func TestCheckRedirect_TooManyRedirects(t *testing.T) {
	var g *Guard
	via := make([]*http.Request, maxRedirects)
	req, _ := http.NewRequest(http.MethodGet, "https://8.8.8.8/", nil)
	for i := range via {
		via[i] = req
	}
	if err := g.CheckRedirect(req, via); err == nil {
		t.Error("expected redirect-limit error")
	}
}
