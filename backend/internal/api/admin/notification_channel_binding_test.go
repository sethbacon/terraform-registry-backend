package admin

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	identitycrypto "github.com/sethbacon/terraform-suite-identity/identity/crypto"
	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"
)

// suite-identity #153 — the channel target is bound to its channel row, so a
// sealed target cannot be lifted out of one channel and written into another by
// anyone with database write access.
//
// These assert the value REACHING the database. The pre-existing create test
// passes without any of this: the follow-up UPDATE it does not expect simply
// errors, the handler logs and still returns 201, and the bind silently never
// happens. That is precisely the shape of test that certifies nothing.

type capturedArg struct{ got *string }

func (c capturedArg) Match(v driver.Value) bool {
	if s, ok := v.(string); ok {
		*c.got = s
	}
	return true
}

func assertBoundToChannel(t *testing.T, tc *identitycrypto.TokenCipher, stored, channelID, want string) {
	t.Helper()

	got, err := tc.OpenWithContext(stored, identitynotify.TargetContext(channelID))
	if err != nil {
		t.Fatalf("stored target does not open under its own row context: %v", err)
	}
	if got != want {
		t.Errorf("stored target = %q, want %q", got, want)
	}
	if _, err := tc.Open(stored); !errors.Is(err, identitycrypto.ErrDecryptionFailed) {
		t.Errorf("stored target still opens WITHOUT a context; it was not bound (err=%v)", err)
	}
	if _, err := tc.OpenWithContext(stored, identitynotify.TargetContext("some-other-channel")); err == nil {
		t.Error("stored target opened under another channel's context; the binding is vacuous")
	}
}

func TestCreateChannel_BindsTheTargetToTheNewRow(t *testing.T) {
	h, mock, tc := newChannelHandlers(t, nil)
	const target = "https://hooks.example.com/created"
	id := uuid.New().String()

	// Create cannot bind at INSERT time: the repository uses
	// `INSERT ... RETURNING` and takes no caller-supplied id.
	mock.ExpectQuery("INSERT INTO notification_channels").WillReturnRows(adminChannelRow(id, "ENC"))

	var stored string
	mock.ExpectQuery("UPDATE notification_channels").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), capturedArg{got: &stored}).
		WillReturnRows(adminChannelRow(id, "ENC"))

	body := `{"name":"ops","type":"webhook","target":"` + target + `","events":["cve_detected"]}`
	c, w := channelTestCtx(http.MethodPost, body, nil)
	h.CreateChannel(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201", w.Code)
	}
	if stored == "" {
		t.Fatal("no follow-up UPDATE captured; the created row was left unbound")
	}
	assertBoundToChannel(t, tc, stored, id, target)
}

func TestUpdateChannel_BindsTheTargetToTheRowBeingUpdated(t *testing.T) {
	h, mock, tc := newChannelHandlers(t, nil)
	const target = "https://hooks.example.com/updated"
	id := uuid.New().String()

	var stored string
	mock.ExpectQuery("UPDATE notification_channels").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), capturedArg{got: &stored}).
		WillReturnRows(adminChannelRow(id, "ENC"))

	body := `{"name":"ops","type":"webhook","target":"` + target + `","events":["cve_detected"]}`
	c, w := channelTestCtx(http.MethodPut, body, gin.Params{{Key: "id", Value: id}})
	h.UpdateChannel(c)

	if w.Code != http.StatusOK {
		t.Fatalf("update: status = %d, want 200", w.Code)
	}
	if stored == "" {
		t.Fatal("no encrypted target captured on update")
	}
	// Bound to the PATH id, not to whatever the fixture row returns.
	assertBoundToChannel(t, tc, stored, id, target)
}

// A create whose follow-up bind fails must still return 201: the channel exists
// and delivers (the notifier reads unbound targets too), and failing here would
// report an error for a row that WAS created, inviting a duplicate on retry.
func TestCreateChannel_StillSucceedsWhenTheBindWriteFails(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	id := uuid.New().String()

	mock.ExpectQuery("INSERT INTO notification_channels").WillReturnRows(adminChannelRow(id, "ENC"))
	mock.ExpectQuery("UPDATE notification_channels").WillReturnError(errors.New("bind write failed"))

	body := `{"name":"ops","type":"webhook","target":"https://hooks.example.com/x","events":["cve_detected"]}`
	c, w := channelTestCtx(http.MethodPost, body, nil)
	h.CreateChannel(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("create with a failed bind: status = %d, want 201 (the channel exists)", w.Code)
	}
}
