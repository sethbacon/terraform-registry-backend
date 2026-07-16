package notify

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

var notifyChannelCols = []string{
	"id", "name", "type", "encrypted_target", "events", "enabled",
	"last_status", "last_error", "last_sent_at", "created_at", "updated_at",
}

// newTestNotifier builds a Notifier over a sqlmock-backed channel repository, a
// real token cipher, and an egress guard that allow-lists loopback so an
// httptest server (127.0.0.1) is a reachable channel target.
func newTestNotifier(t *testing.T) (*Notifier, sqlmock.Sqlmock, *crypto.TokenCipher) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := repositories.NewNotificationChannelRepository(db)
	tc, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return NewNotifier(repo, nil, tc, httpsafe.MustGuard("127.0.0.1")), mock, tc
}

func webhookChannelRow(id uuid.UUID, enc string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(notifyChannelCols).AddRow(
		id, "ops", "webhook", enc, []byte(`["cve_detected"]`), true,
		nil, nil, nil, now, now)
}

func TestNotifier_NilIsNoOp(t *testing.T) {
	var n *Notifier
	n.Notify(context.Background(), Event{Type: EventCVEDetected}) // must not panic
	if err := n.SendTest(context.Background(), uuid.New()); err == nil {
		t.Error("SendTest on a nil Notifier should return an error")
	}
}

func TestParseRecipients(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{"single", "ops@example.com", 1, false},
		{"multiple with spaces", "a@example.com, b@example.com ", 2, false},
		{"skips blanks", "a@example.com,,", 1, false},
		{"empty", "", 0, true},
		{"only blanks", " , ", 0, true},
		{"invalid", "not-an-email", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRecipients(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseRecipients(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil && len(got) != tc.want {
				t.Errorf("ParseRecipients(%q) = %d recipients, want %d", tc.in, len(got), tc.want)
			}
		})
	}
}

func TestTeamsPayload(t *testing.T) {
	p := teamsPayload("Title", "Body")
	if p["type"] != "message" {
		t.Errorf("type = %v, want message", p["type"])
	}
	if _, ok := p["attachments"]; !ok {
		t.Error("teams payload missing attachments")
	}
}

func TestNotifier_send(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	for _, typ := range []string{"webhook", "slack", "teams"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		if err := n.send(context.Background(), typ, srv.URL, "Title", "Message"); err != nil {
			t.Errorf("send(%s): unexpected error %v", typ, err)
		}
		srv.Close()
	}
}

func TestNotifier_send_Non2xx(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := n.send(context.Background(), "webhook", srv.URL, "t", "m"); err == nil {
		t.Error("expected an error for a non-2xx destination response")
	}
}

func TestNotifier_send_TransportErrorRedacted(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	// Loopback is allow-listed by the test guard, so the request is attempted
	// and fails to connect (port 1). The error must not embed the target URL.
	target := "http://127.0.0.1:1/secret-webhook-token"
	err := n.send(context.Background(), "webhook", target, "t", "m")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if got := err.Error(); contains(got, "secret-webhook-token") {
		t.Errorf("send error leaked the target URL: %q", got)
	}
}

func TestNotifier_decryptTarget(t *testing.T) {
	n, _, tc := newTestNotifier(t)
	enc, err := tc.Seal("https://hooks.example.com/x")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := n.decryptTarget(&models.NotificationChannel{EncryptedTarget: enc})
	if err != nil || got != "https://hooks.example.com/x" {
		t.Fatalf("decryptTarget = (%q, %v)", got, err)
	}
	if _, err := n.decryptTarget(&models.NotificationChannel{EncryptedTarget: ""}); err == nil {
		t.Error("decryptTarget with no target should error")
	}
	if _, err := n.decryptTarget(&models.NotificationChannel{EncryptedTarget: "not-valid-ciphertext"}); err == nil {
		t.Error("decryptTarget with a bad ciphertext should error")
	}
}

func TestNotifier_sendEmail_InvalidRecipients(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	// ParseRecipients fails before the (nil) mailer is touched.
	if err := n.sendEmail("not-an-email", "t", "m"); err == nil {
		t.Error("sendEmail with an invalid recipient should error")
	}
}

func TestNotifier_Notify_DeliversToChannel(t *testing.T) {
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, mock, tc := newTestNotifier(t)
	enc, err := tc.Seal(srv.URL)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	mock.ExpectQuery("WHERE enabled").WillReturnRows(webhookChannelRow(uuid.New(), enc))
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))

	n.Notify(context.Background(), Event{Type: EventCVEDetected, Title: "t", Message: "m"})
	select {
	case <-hit:
	default:
		t.Error("expected the webhook endpoint to receive the notification")
	}
}

func TestNotifier_Notify_RepoError(t *testing.T) {
	n, mock, _ := newTestNotifier(t)
	mock.ExpectQuery("WHERE enabled").WillReturnError(sql.ErrConnDone)
	// A repository failure is logged, not panicked or propagated.
	n.Notify(context.Background(), Event{Type: EventCVEDetected})
}

func TestNotifier_Notify_DecryptError(t *testing.T) {
	n, mock, _ := newTestNotifier(t)
	// An undecryptable target makes delivery fail; the failure must be recorded
	// (exercises deliver's error path and record's "failed" branch).
	mock.ExpectQuery("WHERE enabled").WillReturnRows(webhookChannelRow(uuid.New(), "not-decryptable"))
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))
	n.Notify(context.Background(), Event{Type: EventCVEDetected, Title: "t", Message: "m"})
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestNotifier_SendTest_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, mock, tc := newTestNotifier(t)
	enc, err := tc.Seal(srv.URL)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	id := uuid.New()
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnRows(webhookChannelRow(id, enc))
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := n.SendTest(context.Background(), id); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
}

func TestNotifier_SendTest_NotFound(t *testing.T) {
	n, mock, _ := newTestNotifier(t)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(sql.ErrNoRows)
	if err := n.SendTest(context.Background(), uuid.New()); err == nil {
		t.Error("SendTest for a missing channel should return an error")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
