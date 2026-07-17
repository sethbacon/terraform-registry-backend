package notify

import (
	"bufio"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// TestNew_HoldsLivePointer verifies that Mailer stores the *config.SMTPConfig
// by reference: mutating the referenced struct after construction is observed
// by the Mailer, without recreating it. This is the fix that lets a runtime
// admin config update reach background jobs that built their Mailer once at
// startup.
func TestNew_HoldsLivePointer(t *testing.T) {
	cfg := &config.SMTPConfig{Host: "old.example.com", From: "old@example.com"}
	m := New(cfg)

	cfg.Host = "new.example.com"
	cfg.From = "new@example.com"

	if m.cfg.Host != "new.example.com" {
		t.Errorf("m.cfg.Host = %q, want %q (live pointer not observed)", m.cfg.Host, "new.example.com")
	}
	if m.cfg.From != "new@example.com" {
		t.Errorf("m.cfg.From = %q, want %q (live pointer not observed)", m.cfg.From, "new@example.com")
	}
}

// TestSend_NilConfig_ReturnsError verifies the nil guard at the top of Send.
func TestSend_NilConfig_ReturnsError(t *testing.T) {
	m := &Mailer{cfg: nil}

	err := m.Send([]string{"to@example.com"}, "subject", "body")
	if err == nil {
		t.Fatal("expected error for nil smtp config, got nil")
	}
	if err.Error() != "mailer: nil smtp config" {
		t.Errorf("err = %q, want %q", err.Error(), "mailer: nil smtp config")
	}
}

// TestSanitizeHeader verifies CR/LF are stripped so a crafted subject or
// recipient cannot inject additional SMTP headers (email header injection).
func TestSanitizeHeader(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", "Weekly digest", "Weekly digest"},
		{"crlf header injection", "Subject\r\nBcc: victim@example.com", "SubjectBcc: victim@example.com"},
		{"lf only", "line1\nline2", "line1line2"},
		{"cr only", "a\rb", "ab"},
		{"address injection", "user@example.com\r\nRCPT TO:<evil@x>", "user@example.comRCPT TO:<evil@x>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeHeader(tt.in); got != tt.want {
				t.Errorf("sanitizeHeader(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestAuthFor verifies that authentication is only attached when credentials
// are provided. An open relay (no username/password) must receive a nil auth so
// smtp.SendMail does not fail with "smtp: server doesn't support AUTH".
func TestAuthFor(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		password    string
		wantNilAuth bool
	}{
		{"no credentials (unauthenticated relay)", "", "", true},
		{"username only", "user", "", false},
		{"password only", "", "secret", false},
		{"username and password", "user", "secret", false},
		{"whitespace-only username still attempts auth", " ", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.SMTPConfig{Host: "smtp.example.com", Username: tt.username, Password: tt.password}
			auth := authFor(cfg)
			if tt.wantNilAuth && auth != nil {
				t.Errorf("authFor(%q, %q) = non-nil, want nil", tt.username, tt.password)
			}
			if !tt.wantNilAuth && auth == nil {
				t.Errorf("authFor(%q, %q) = nil, want non-nil", tt.username, tt.password)
			}
		})
	}
}

// fakeSMTPResult records what a fakeSMTPServer observed during one session.
type fakeSMTPResult struct {
	gotSTARTTLS bool
	gotAuth     bool
	from        string
	rcpts       []string
}

// fakeSMTPServer accepts a single connection and speaks just enough SMTP to
// exercise sendMailPlain: it optionally advertises STARTTLS in the EHLO
// response (to prove the plaintext path never attempts to use it), always
// advertises AUTH, and completes MAIL/RCPT/DATA. The result is sent on the
// returned channel once the client disconnects.
func fakeSMTPServer(t *testing.T, advertiseSTARTTLS bool) (addr string, resultCh <-chan fakeSMTPResult) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan fakeSMTPResult, 1)
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		var res fakeSMTPResult

		writeLine := func(s string) {
			_, _ = w.WriteString(s + "\r\n")
			_ = w.Flush()
		}
		writeLine("220 fake.smtp.local ESMTP")

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				_, _ = w.WriteString("250-fake.smtp.local\r\n")
				if advertiseSTARTTLS {
					_, _ = w.WriteString("250-STARTTLS\r\n")
				}
				_, _ = w.WriteString("250 AUTH PLAIN\r\n")
				_ = w.Flush()
			case strings.HasPrefix(upper, "STARTTLS"):
				res.gotSTARTTLS = true
				writeLine("454 TLS not available")
			case strings.HasPrefix(upper, "AUTH"):
				res.gotAuth = true
				writeLine("235 OK")
			case strings.HasPrefix(upper, "MAIL FROM"):
				res.from = line
				writeLine("250 OK")
			case strings.HasPrefix(upper, "RCPT TO"):
				res.rcpts = append(res.rcpts, line)
				writeLine("250 OK")
			case upper == "DATA":
				writeLine("354 Start mail input")
				for {
					dline, derr := r.ReadString('\n')
					if derr != nil {
						break
					}
					if strings.TrimRight(dline, "\r\n") == "." {
						break
					}
				}
				writeLine("250 OK: queued")
			case upper == "QUIT":
				writeLine("221 Bye")
				ch <- res
				return
			default:
				writeLine("500 unrecognized command")
			}
		}
		ch <- res
	}()
	return ln.Addr().String(), ch
}

// TestSendMailPlain_NeverAttemptsSTARTTLSEvenWhenAdvertised is the regression
// test for the "unencrypted email sends fail against an unauthenticated,
// non-TLS relay" bug: when UseTLS=false, the relay may still advertise
// STARTTLS (common even for internal/unauthenticated relays), but
// sendMailPlain must never attempt the upgrade — unlike smtp.SendMail, which
// opportunistically upgrades whenever the extension is offered and would fail
// the handshake against a relay with a self-signed or otherwise untrusted
// certificate, aborting a send the operator explicitly configured as plaintext.
func TestSendMailPlain_NeverAttemptsSTARTTLSEvenWhenAdvertised(t *testing.T) {
	addr, resultCh := fakeSMTPServer(t, true /* advertise STARTTLS */)
	host, _, _ := net.SplitHostPort(addr)

	err := sendMailPlain(addr, host, nil, "from@example.com", []string{"to@example.com"},
		[]byte("Subject: hi\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("sendMailPlain returned error: %v", err)
	}

	select {
	case res := <-resultCh:
		if res.gotSTARTTLS {
			t.Error("sendMailPlain issued STARTTLS even though UseTLS=false; connection must stay plaintext")
		}
		if res.gotAuth {
			t.Error("sendMailPlain sent AUTH with a nil auth (unauthenticated relay)")
		}
		if res.from == "" || len(res.rcpts) != 1 {
			t.Errorf("unexpected session: from=%q rcpts=%v", res.from, res.rcpts)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fake SMTP server result")
	}
}

// TestSendMailPlain_SendsAuthWhenConfigured verifies the plaintext path still
// authenticates when credentials are configured (127.0.0.1 satisfies net/smtp's
// isLocalhost check, so PlainAuth permits sending credentials without TLS).
func TestSendMailPlain_SendsAuthWhenConfigured(t *testing.T) {
	addr, resultCh := fakeSMTPServer(t, false)
	host, _, _ := net.SplitHostPort(addr)
	auth := smtp.PlainAuth("", "user", "pass", host)

	err := sendMailPlain(addr, host, auth, "from@example.com", []string{"to@example.com"},
		[]byte("Subject: hi\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("sendMailPlain returned error: %v", err)
	}

	select {
	case res := <-resultCh:
		if !res.gotAuth {
			t.Error("expected sendMailPlain to send AUTH when credentials are configured")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fake SMTP server result")
	}
}

// TestSendMailStartTLS_Rejected_ReturnsError is the regression test for the
// bug this fix addresses: sendMailTLS's fallback previously delegated to
// smtp.SendMail, which only attempts STARTTLS when the server's EHLO
// advertises the extension and otherwise silently continues in plaintext --
// so a relay whose STARTTLS command fails (this fake server always responds
// "454 TLS not available", matching a live relay's
// `454 4.3.3 TLS not available after start`) would previously result in a
// silent plaintext "success" instead of a surfaced error. sendMailStartTLS
// calls c.StartTLS directly, so the rejection must now propagate.
func TestSendMailStartTLS_Rejected_ReturnsError(t *testing.T) {
	addr, _ := fakeSMTPServer(t, true /* advertise STARTTLS */)
	host, _, _ := net.SplitHostPort(addr)

	err := sendMailStartTLS(addr, host, nil, "from@example.com", []string{"to@example.com"},
		[]byte("Subject: hi\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("expected an error when the relay rejects STARTTLS, got nil (silent plaintext fallback)")
	}
	if !strings.Contains(err.Error(), "smtp starttls") {
		t.Errorf("error = %q, want it to mention the starttls failure", err.Error())
	}
}
