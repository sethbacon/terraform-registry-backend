package admin

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	identitycrypto "github.com/sethbacon/terraform-suite-identity/identity/crypto"
	identityhttpsafe "github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/notify"
)

var adminChannelCols = []string{
	"id", "name", "type", "encrypted_target", "events", "enabled",
	"last_status", "last_error", "last_sent_at", "created_at", "updated_at",
}

func adminChannelRow(id, enc string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(adminChannelCols).AddRow(
		id, "ops", "webhook", enc, []byte(`["cve_detected"]`), true,
		nil, nil, nil, now, now)
}

// newChannelHandlers builds the handlers over a sqlmock-backed repository and a
// real token cipher. guard is the egress guard used for create/update target
// validation (pass nil to skip the egress check in a test).
func newChannelHandlers(t *testing.T, guard *identityhttpsafe.Guard) (*NotificationChannelHandlers, sqlmock.Sqlmock, *identitycrypto.TokenCipher) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := repositories.NewNotificationChannelRepository(db)
	tc, err := identitycrypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	opts := identitynotify.Options{Source: "terraform-registry", TestMessage: "This is a test from the Terraform Registry."}
	notifier := notify.NewNotifier(repo, nil, tc, identityhttpsafe.MustGuard("127.0.0.1"), opts)
	return NewNotificationChannelHandlers(repo, notifier, tc, guard), mock, tc
}

func channelTestCtx(method, body string, params gin.Params) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, "/", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = params
	return c, w
}

func TestNotificationChannelRequest_Validate(t *testing.T) {
	strict := identityhttpsafe.MustGuard() // strict default policy

	cases := []struct {
		name    string
		req     notificationChannelRequest
		guard   *identityhttpsafe.Guard
		wantErr bool
	}{
		{"bad type", notificationChannelRequest{Type: "sms"}, nil, true},
		{"unknown event", notificationChannelRequest{Type: "webhook", Events: []string{"nope"}}, nil, true},
		{"email valid", notificationChannelRequest{Type: "email", Target: "ops@example.com"}, nil, false},
		{"email invalid", notificationChannelRequest{Type: "email", Target: "not-an-email"}, nil, true},
		{"url valid, nil guard", notificationChannelRequest{Type: "webhook", Target: "https://hooks.example.com/x"}, nil, false},
		{"url bad scheme", notificationChannelRequest{Type: "webhook", Target: "ftp://host/y"}, nil, true},
		{"url no host", notificationChannelRequest{Type: "webhook", Target: "https://"}, nil, true},
		{"guard blocks metadata", notificationChannelRequest{Type: "webhook", Target: "http://169.254.169.254/latest"}, strict, true},
		{"empty target ok", notificationChannelRequest{Type: "slack"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.validate(tc.guard)
			if (err != nil) != tc.wantErr {
				t.Errorf("validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNotificationChannelRequest_Events(t *testing.T) {
	if got := (&notificationChannelRequest{}).events(); got == nil || len(got) != 0 {
		t.Errorf("events() on nil = %v, want empty non-nil slice", got)
	}
	if got := (&notificationChannelRequest{Events: []string{"cve_detected"}}).events(); len(got) != 1 {
		t.Errorf("events() = %v, want 1 entry", got)
	}
}

func TestListChannels(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	mock.ExpectQuery("FROM notification_channels ORDER BY").WillReturnRows(adminChannelRow(uuid.New().String(), "ENC"))
	c, w := channelTestCtx(http.MethodGet, "", nil)
	h.ListChannels(c)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestListChannels_Error(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	mock.ExpectQuery("FROM notification_channels ORDER BY").WillReturnError(errors.New("boom"))
	c, w := channelTestCtx(http.MethodGet, "", nil)
	h.ListChannels(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestCreateChannel(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	mock.ExpectQuery("INSERT INTO notification_channels").WillReturnRows(adminChannelRow(uuid.New().String(), "ENC"))
	body := `{"name":"ops","type":"webhook","target":"https://hooks.example.com/x","events":["cve_detected"]}`
	c, w := channelTestCtx(http.MethodPost, body, nil)
	h.CreateChannel(c)
	if w.Code != http.StatusCreated {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestCreateChannel_BadJSON(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodPost, `{bad`, nil)
	h.CreateChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestCreateChannel_InvalidType(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodPost, `{"name":"x","type":"sms","target":"y"}`, nil)
	h.CreateChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestCreateChannel_MissingTarget(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodPost, `{"name":"x","type":"webhook"}`, nil)
	h.CreateChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestCreateChannel_RepoError(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	mock.ExpectQuery("INSERT INTO notification_channels").WillReturnError(errors.New("boom"))
	body := `{"name":"ops","type":"webhook","target":"https://hooks.example.com/x"}`
	c, w := channelTestCtx(http.MethodPost, body, nil)
	h.CreateChannel(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdateChannel(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()
	mock.ExpectQuery("UPDATE notification_channels").WillReturnRows(adminChannelRow(id, "ENC"))
	body := `{"name":"ops","type":"webhook","target":"https://hooks.example.com/x"}`
	c, w := channelTestCtx(http.MethodPut, body, gin.Params{{Key: "id", Value: id}})
	h.UpdateChannel(c)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestUpdateChannel_KeepTarget(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()
	mock.ExpectQuery("UPDATE notification_channels").WillReturnRows(adminChannelRow(id, "ENC"))
	// No target => the encrypt step is skipped and the existing target kept.
	body := `{"name":"ops","type":"webhook"}`
	c, w := channelTestCtx(http.MethodPut, body, gin.Params{{Key: "id", Value: id}})
	h.UpdateChannel(c)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestUpdateChannel_InvalidID(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodPut, `{"name":"x","type":"webhook"}`, gin.Params{{Key: "id", Value: "not-a-uuid"}})
	h.UpdateChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdateChannel_BadJSON(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodPut, `{bad`, gin.Params{{Key: "id", Value: uuid.New().String()}})
	h.UpdateChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdateChannel_ValidateFail(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodPut, `{"name":"x","type":"sms"}`, gin.Params{{Key: "id", Value: uuid.New().String()}})
	h.UpdateChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdateChannel_RepoError(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()
	mock.ExpectQuery("UPDATE notification_channels").WillReturnError(errors.New("boom"))
	body := `{"name":"ops","type":"webhook","target":"https://hooks.example.com/x"}`
	c, w := channelTestCtx(http.MethodPut, body, gin.Params{{Key: "id", Value: id}})
	h.UpdateChannel(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdateChannel_NotFound(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()
	mock.ExpectQuery("UPDATE notification_channels").WillReturnError(sql.ErrNoRows)
	body := `{"name":"ops","type":"webhook","target":"https://hooks.example.com/x"}`
	c, w := channelTestCtx(http.MethodPut, body, gin.Params{{Key: "id", Value: id}})
	h.UpdateChannel(c)
	if w.Code != http.StatusNotFound {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestDeleteChannel(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()
	mock.ExpectExec("DELETE FROM notification_channels").WillReturnResult(sqlmock.NewResult(0, 1))
	c, _ := channelTestCtx(http.MethodDelete, "", gin.Params{{Key: "id", Value: id}})
	h.DeleteChannel(c)
	// DeleteChannel replies 204 with no body; c.Status() buffers the code on the
	// gin writer without flushing it to the recorder, so assert on the writer.
	if c.Writer.Status() != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", c.Writer.Status(), http.StatusNoContent)
	}
}

func TestDeleteChannel_InvalidID(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodDelete, "", gin.Params{{Key: "id", Value: "bad"}})
	h.DeleteChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestDeleteChannel_RepoError(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()
	mock.ExpectExec("DELETE FROM notification_channels").WillReturnError(errors.New("boom"))
	c, w := channelTestCtx(http.MethodDelete, "", gin.Params{{Key: "id", Value: id}})
	h.DeleteChannel(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestTestChannel_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, mock, tc := newChannelHandlers(t, nil)
	enc, err := tc.Seal(srv.URL)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	id := uuid.New().String()
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnRows(adminChannelRow(id, enc))
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))

	c, w := channelTestCtx(http.MethodPost, "", gin.Params{{Key: "id", Value: id}})
	h.TestChannel(c)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestTestChannel_InvalidID(t *testing.T) {
	h, _, _ := newChannelHandlers(t, nil)
	c, w := channelTestCtx(http.MethodPost, "", gin.Params{{Key: "id", Value: "bad"}})
	h.TestChannel(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestTestChannel_NotFound(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(sql.ErrNoRows)
	c, w := channelTestCtx(http.MethodPost, "", gin.Params{{Key: "id", Value: id}})
	h.TestChannel(c)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("code = %d", w.Code)
	}
}
