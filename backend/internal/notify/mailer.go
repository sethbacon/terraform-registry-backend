// mailer.go implements Mailer, a shared SMTP email sender used by background jobs
// (CVE polling, API key expiry notifications, scanner update notifications). It
// centralizes the SMTP send logic that was previously duplicated across jobs.
package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Mailer sends plain-text notification emails using the configured SMTP server.
// cfg is held by pointer so that a runtime configuration update (e.g. via the
// admin notifications API) is observed by background jobs without recreating
// the Mailer.
type Mailer struct {
	cfg *config.SMTPConfig
}

// New constructs a Mailer for the given SMTP configuration. cfg is stored by
// reference; callers should pass a pointer to the live config struct (e.g.
// &cfg.Notifications.SMTP) so runtime updates are reflected in Send.
func New(cfg *config.SMTPConfig) *Mailer {
	return &Mailer{cfg: cfg}
}

// Send composes RFC822 headers plus a plain-text body and delivers the message to
// all recipients. When cfg.UseTLS is set, an implicit TLS connection is attempted
// first, falling back to STARTTLS (via smtp.SendMail) on dial failure; otherwise
// the connection is deliberately kept plaintext (see sendMailPlain).
// coverage:skip:integration-only — calls smtp.SendMail / TLS dial; requires live SMTP.
func (m *Mailer) Send(to []string, subject, body string) error {
	if m.cfg == nil {
		return fmt.Errorf("mailer: nil smtp config")
	}
	// Strip CR/LF from header-bound fields to prevent SMTP header (CRLF)
	// injection: recipients, subject and From must each occupy a single line.
	// The body is not header-bound, so it is delivered as-is after the blank line.
	recipients := make([]string, len(to))
	for i, addr := range to {
		recipients[i] = sanitizeHeader(addr)
	}
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		sanitizeHeader(m.cfg.From), strings.Join(recipients, ", "), sanitizeHeader(subject),
	)
	msg := []byte(headers + body + "\r\n")

	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	auth := authFor(m.cfg)

	if m.cfg.UseTLS {
		return sendMailTLS(addr, m.cfg.Host, auth, m.cfg.From, recipients, msg)
	}
	// UseTLS=false is a deliberate operator choice (typically a trusted,
	// network-isolated relay that has no valid certificate) and must reliably
	// result in a plaintext connection. smtp.SendMail cannot be used here: it
	// opportunistically upgrades to STARTTLS whenever the server merely
	// advertises the extension, with no way to opt out. Many relays advertise
	// STARTTLS even when unauthenticated/internal, so a self-signed or
	// otherwise untrusted certificate would fail the TLS handshake and abort
	// the send even though use_tls was explicitly set to false.
	return sendMailPlain(addr, m.cfg.Host, auth, m.cfg.From, recipients, msg)
}

// authFor returns the SMTP authentication mechanism for the configured
// credentials, or nil when both username and password are empty. A relay that
// does not require authentication (and therefore does not advertise the AUTH
// extension, e.g. an internal server on port 25) rejects a non-nil auth with
// "smtp: server doesn't support AUTH", so returning nil here skips
// authentication and allows sending through such relays.
func authFor(cfg *config.SMTPConfig) smtp.Auth {
	if cfg.Username == "" && cfg.Password == "" {
		return nil
	}
	return smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
}

// sanitizeHeader removes CR and LF characters so a value cannot inject
// additional SMTP headers (email header / CRLF injection). Per RFC 5322 a
// header value must occupy a single line.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// sendMailTLS connects via implicit TLS (port 465 / SMTPS) and sends a message.
// Use this when UseTLS=true and the port is 465; for port 587/25 STARTTLS,
// falls back to sendMailStartTLS, which upgrades explicitly rather than
// delegating to smtp.SendMail — so the config is unambiguous: UseTLS=true
// always means an encrypted connection, never a silent plaintext fallback.
// coverage:skip:integration-only — implicit-TLS dial plus a live SMTP protocol
// exchange; cannot be meaningfully unit-tested without a real SMTP-over-TLS server
// (the sibling Send is skipped for the same reason).
func sendMailTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return sendMailStartTLS(addr, host, auth, from, to, msg)
	}
	defer conn.Close()

	hostname, _, _ := net.SplitHostPort(addr)
	c, err := smtp.NewClient(conn, hostname)
	if err != nil {
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Quit() //nolint:errcheck

	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", addr, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	return w.Close()
}

// sendMailStartTLS connects in plaintext, then upgrades via STARTTLS (the
// standard submission-port pattern) before authenticating and sending. It
// calls c.StartTLS directly instead of delegating to smtp.SendMail: SendMail
// only upgrades when the server's EHLO response advertises the STARTTLS
// extension, and otherwise silently continues in plaintext -- so a relay that
// omits (or conditionally refuses) that advertisement would make a
// UseTLS=true send quietly succeed unencrypted. Calling StartTLS explicitly
// guarantees the upgrade is attempted and any failure (e.g. the relay
// rejecting it) is surfaced as a real error rather than swallowed.
// coverage:skip:integration-only — live SMTP protocol exchange (STARTTLS
// handshake); cannot be meaningfully unit-tested without a real SMTP server.
func sendMailStartTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Quit() //nolint:errcheck

	if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}

	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	return w.Close()
}

// sendMailPlain connects without TLS and sends a message, deliberately never
// attempting a STARTTLS upgrade even if the relay advertises the extension.
// This is the UseTLS=false path: unlike smtp.SendMail (which opportunistically
// upgrades to STARTTLS whenever the server offers it, with no way to opt out),
// this guarantees the connection stays plaintext throughout. Without this, a
// relay that merely advertises STARTTLS but presents a self-signed or otherwise
// untrusted certificate — common for internal/unauthenticated relays — would
// fail the TLS handshake and abort the send even though the operator explicitly
// configured use_tls: false for a plaintext connection.
func sendMailPlain(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Quit() //nolint:errcheck

	if auth != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return fmt.Errorf("smtp: server doesn't support AUTH")
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	return w.Close()
}
