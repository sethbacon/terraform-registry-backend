// Package httpsafe provides a shared SSRF-safe HTTP client for every outbound
// request whose target URL is operator- or admin-configurable (mirror upstream
// registries, SCM provider base URLs, the policy bundle, the OSV endpoint,
// SAML IdP metadata, audit webhooks) — including second-order URLs returned by
// those upstreams (download_url, shasums_url, release asset URLs).
//
// Enforcement model:
//
//   - Scheme allow-list: only http and https requests are dialed.
//   - Resolve-and-pin: the hostname is resolved by the client itself, every
//     resolved IP is validated against a deny-list of non-public ranges
//     (loopback, RFC 1918, link-local including the 169.254.169.254 metadata
//     endpoint, CGNAT, IPv6 ULA/link-local/loopback, unspecified, multicast,
//     broadcast), and the connection is dialed to a validated IP. Because the
//     checked IP is the dialed IP, DNS rebinding between check and dial is
//     impossible.
//   - Redirect re-validation: every redirect hop passes through the same
//     dial-time checks, and CheckRedirect additionally re-validates the hop URL
//     and strips Authorization/Cookie headers on cross-host redirects.
//   - Explicit allow-list escape hatch: deployments that legitimately talk to
//     internal registries list those hosts/IPs/CIDRs in
//     security.egress.allowlist (default DENY).
//
// A nil *Guard is valid and enforces the strict policy with an empty
// allow-list, so callers can pass nil when no operator allow-list applies.
package httpsafe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// resolveTimeout bounds the DNS lookup performed by ValidateURL outside of a
// live request (config-write validation).
const resolveTimeout = 5 * time.Second

// maxRedirects mirrors net/http's default redirect cap.
const maxRedirects = 10

// Guard validates outbound URLs and dial targets against the egress policy.
// The zero value and nil are both valid strict guards (empty allow-list).
// Guard is immutable after construction and safe for concurrent use.
type Guard struct {
	allowHosts map[string]struct{}
	allowNets  []*net.IPNet

	// lookupIP overrides DNS resolution in tests of the guard itself.
	lookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

// NewGuard builds a Guard from allow-list entries. Each entry may be a
// hostname ("registry.corp.internal"), an IP ("10.1.2.3"), or a CIDR range
// ("10.20.0.0/16"). An empty or nil list yields the strict default policy.
func NewGuard(allowlist []string) (*Guard, error) {
	g := &Guard{allowHosts: make(map[string]struct{})}
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			g.allowNets = append(g.allowNets, ipNet)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 8 * net.IPv6len
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 8 * net.IPv4len
			}
			g.allowNets = append(g.allowNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if strings.ContainsAny(entry, "/ ") {
			return nil, fmt.Errorf("egress allowlist entry %q is not a valid hostname, IP, or CIDR", entry)
		}
		g.allowHosts[strings.ToLower(entry)] = struct{}{}
	}
	return g, nil
}

// MustGuard is NewGuard for static allow-lists (primarily tests); it panics on
// an invalid entry.
func MustGuard(allowlist ...string) *Guard {
	g, err := NewGuard(allowlist)
	if err != nil {
		panic(err)
	}
	return g
}

// HostExempt reports whether host (a hostname or IP literal) is covered by the
// allow-list, meaning deny-list checks (and the policy bundle's https-only
// requirement) do not apply to it.
func (g *Guard) HostExempt(host string) bool {
	if g == nil {
		return false
	}
	if _, ok := g.allowHosts[strings.ToLower(host)]; ok {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return g.ipAllowlisted(ip)
	}
	return false
}

func (g *Guard) ipAllowlisted(ip net.IP) bool {
	if g == nil {
		return false
	}
	for _, n := range g.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// checkIP rejects ip when it falls in a non-public range, unless the IP (or
// the hostname it was resolved from) is allow-listed.
func (g *Guard) checkIP(host string, ip net.IP) error {
	if g.ipAllowlisted(ip) {
		return nil
	}
	if reason := deniedRange(ip); reason != "" {
		return fmt.Errorf("egress to %q (%s) blocked: %s address — add the host to security.egress.allowlist if this internal target is intentional", host, ip, reason)
	}
	return nil
}

// deniedRange returns a non-empty range description when ip is not publicly
// routable. IPv4-mapped IPv6 addresses are classified as their IPv4 form.
func deniedRange(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLinkLocalUnicast():
		// Includes 169.254.0.0/16 (cloud metadata) and fe80::/10.
		return "link-local"
	case ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return "multicast"
	case ip.IsPrivate():
		// RFC 1918 (10/8, 172.16/12, 192.168/16) and IPv6 ULA fc00::/7.
		return "private"
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 0:
			return "reserved (0.0.0.0/8)"
		case ip4[0] == 100 && ip4[1]&0xc0 == 64:
			return "carrier-grade NAT (100.64.0.0/10)"
		case ip4.Equal(net.IPv4bcast):
			return "broadcast"
		}
	}
	return ""
}

// ValidateURL checks a configured URL against the egress policy: http/https
// scheme, non-empty host, and — when the host is not allow-listed — no
// resolution to a denied range. It is intended for config-write time so
// private/metadata targets are rejected with a clear error at save.
//
// A DNS lookup failure is NOT a validation error: the record may only resolve
// later (or only inside the deployment network), and the dial-time
// resolve-and-pin check remains the authoritative enforcement point.
func (g *Guard) ValidateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme %q not allowed (must be http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL must have a host")
	}
	if g.HostExempt(host) {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return g.checkIP(host, ip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	ips, err := g.resolve(ctx, host)
	if err != nil {
		// Fail open on lookup errors (see doc comment); dial-time enforcement
		// still applies to whatever the name resolves to when actually used.
		return nil
	}
	for _, ip := range ips {
		if err := g.checkIP(host, ip); err != nil {
			return err
		}
	}
	return nil
}

func (g *Guard) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if g != nil && g.lookupIP != nil {
		return g.lookupIP(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// DialContext resolves addr's host itself, validates EVERY resolved IP against
// the deny-list, and dials a validated IP directly — the checked IP is the
// connected IP, so a DNS answer cannot change between check and dial. A name
// that resolves to any denied address is rejected outright (mixed public +
// private answers are a rebinding pattern, not a legitimate configuration).
func (g *Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("egress dial %q: %w", addr, err)
	}

	// Match http.DefaultTransport's dialer behaviour.
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	if ip := net.ParseIP(host); ip != nil {
		if err := g.checkIP(host, ip); err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, addr)
	}

	if g.HostExempt(host) {
		return dialer.DialContext(ctx, network, addr)
	}

	ips, err := g.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("egress dial %q: resolve: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("egress dial %q: no addresses resolved", host)
	}
	for _, ip := range ips {
		if err := g.checkIP(host, ip); err != nil {
			return nil, err
		}
	}

	var dialErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = err
	}
	return nil, fmt.Errorf("egress dial %q: %w", host, dialErr)
}

// sameOrigin reports whether two URLs share scheme, host, and port. A
// same-hostname comparison alone is not enough: a redirect from
// https://git.internal/api to https://git.internal:9999/evil or to
// http://git.internal/evil is not "the same place" and must not be treated as
// safe to resend credentials/body to.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// CheckRedirect re-validates every redirect hop against the egress policy,
// strips credentials on a cross-origin hop, and refuses to follow a
// cross-origin hop that would resend a request body. The dial-time
// resolve-and-pin check still applies to the hop; this adds fast failure with
// a clear error plus credential hygiene.
//
// Body is refused rather than stripped: Go preserves method and body across
// 307/308 redirects, and a body can carry credentials a header-only strip
// would miss entirely (e.g. an OAuth client_secret in a token-exchange POST
// form). There is no general way to know which body fields are sensitive, so
// the safe behavior on cross-origin is to not resend it at all — the caller
// gets the redirect response back instead of an error, exactly as it would
// for same-origin non-redirect-following clients.
func (g *Guard) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if err := g.ValidateURL(req.URL.String()); err != nil {
		return fmt.Errorf("redirect blocked: %w", err)
	}
	if len(via) > 0 && !sameOrigin(req.URL, via[0].URL) {
		if req.GetBody != nil || req.ContentLength != 0 {
			return fmt.Errorf("refusing to follow cross-origin redirect to %s with a non-empty request body", req.URL.Host)
		}
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Cookie")
		req.Header.Del("Cookie2")
	}
	return nil
}

// NewClient returns an *http.Client with the given total-request timeout whose
// transport dials through g (resolve-and-pin) and whose CheckRedirect
// re-validates every hop. Pass a nil guard for the strict default policy.
// Other transport parameters mirror http.DefaultTransport.
//
// Proxy is deliberately nil (no HTTP_PROXY/HTTPS_PROXY support), not
// http.ProxyFromEnvironment: when a request is proxied, DialContext only ever
// dials the *proxy's* address — the guard would validate and pin the proxy,
// while the real destination is embedded in the forwarded request line (HTTP)
// or CONNECT target (HTTPS) and is never resolved or checked at all. A
// forward proxy is trusted infrastructure with its own (unverifiable from
// here) egress policy, which is a different trust model than this package
// provides; supporting it safely is out of scope.
func NewClient(timeout time.Duration, g *Guard) *http.Client {
	transport := &http.Transport{
		DialContext:           g.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: g.CheckRedirect,
	}
}
