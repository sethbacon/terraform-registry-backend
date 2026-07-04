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
// plain smtp.SendMail is used.
// coverage:skip:integration-only — calls smtp.SendMail / TLS dial; requires live SMTP.
func (m *Mailer) Send(to []string, subject, body string) error {
	if m.cfg == nil {
		return fmt.Errorf("mailer: nil smtp config")
	}
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		m.cfg.From, strings.Join(to, ", "), subject,
	)
	msg := []byte(headers + body + "\r\n")

	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)

	if m.cfg.UseTLS {
		return sendMailTLS(addr, m.cfg.Host, auth, m.cfg.From, to, msg)
	}
	return smtp.SendMail(addr, auth, m.cfg.From, to, msg)
}

// sendMailTLS connects via implicit TLS (port 465 / SMTPS) and sends a message.
// Use this when UseTLS=true and the port is 465; for port 587 STARTTLS,
// smtp.SendMail handles the upgrade automatically — but we call this path for
// both so the config is unambiguous: UseTLS=true always means an encrypted connection.
func sendMailTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		// Fall back to STARTTLS via the standard smtp.SendMail path (port 587 pattern)
		return smtp.SendMail(addr, auth, from, to, msg)
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
