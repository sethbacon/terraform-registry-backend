package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func newNotificationChannelRepo(t *testing.T) (*NotificationChannelRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewNotificationChannelRepository(db), mock
}

var notificationChannelTestCols = []string{
	"id", "name", "type", "encrypted_target", "events", "enabled",
	"last_status", "last_error", "last_sent_at", "created_at", "updated_at",
}

// fullChannelRow populates every nullable column and a non-empty events array,
// exercising the JSON unmarshal and the Valid branches of scanNotificationChannel.
func fullChannelRow(id uuid.UUID, enc string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(notificationChannelTestCols).AddRow(
		id, "ops-webhook", "webhook", enc, []byte(`["cve_detected"]`), true,
		"sent", "prior failure", now, now, now)
}

// minimalChannelRow uses NULL status/error/sent_at and NULL events, exercising
// the empty-events and nil-NullX branches of scanNotificationChannel.
func minimalChannelRow(id uuid.UUID, enc string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(notificationChannelTestCols).AddRow(
		id, "ops-mail", "email", enc, nil, true,
		nil, nil, nil, now, now)
}

func TestNotificationChannelRepo_Create(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	id := uuid.New()
	mock.ExpectQuery("INSERT INTO notification_channels").
		WillReturnRows(fullChannelRow(id, "ENC"))

	ch := &models.NotificationChannel{Name: "ops-webhook", Type: "webhook", EncryptedTarget: "ENC", Events: []string{"cve_detected"}, Enabled: true}
	saved, err := repo.Create(context.Background(), ch)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if saved.ID != id {
		t.Errorf("ID = %v, want %v", saved.ID, id)
	}
	if saved.EncryptedTarget != "" {
		t.Error("Create must redact EncryptedTarget in the returned channel")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestNotificationChannelRepo_Create_DBError(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectQuery("INSERT INTO notification_channels").WillReturnError(errDB)
	if _, err := repo.Create(context.Background(), &models.NotificationChannel{Events: []string{}}); err == nil {
		t.Error("expected error")
	}
}

func TestNotificationChannelRepo_List(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	id := uuid.New()
	mock.ExpectQuery("FROM notification_channels ORDER BY created_at DESC").
		WillReturnRows(fullChannelRow(id, "ENC"))
	list, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	if list[0].EncryptedTarget != "" {
		t.Error("List must redact EncryptedTarget")
	}
	if list[0].LastStatus == nil || *list[0].LastStatus != "sent" {
		t.Error("expected LastStatus 'sent'")
	}
}

func TestNotificationChannelRepo_List_DBError(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectQuery("FROM notification_channels ORDER BY").WillReturnError(errDB)
	if _, err := repo.List(context.Background()); err == nil {
		t.Error("expected error")
	}
}

func TestNotificationChannelRepo_GetByID(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	id := uuid.New()
	mock.ExpectQuery("FROM notification_channels WHERE id").
		WillReturnRows(minimalChannelRow(id, "ENC"))
	ch, err := repo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if ch == nil || ch.ID != id {
		t.Fatalf("GetByID returned %+v", ch)
	}
	if len(ch.Events) != 0 {
		t.Errorf("expected empty events, got %v", ch.Events)
	}
	if ch.EncryptedTarget != "ENC" {
		t.Error("GetByID must return the encrypted target for decryption")
	}
}

func TestNotificationChannelRepo_GetByID_NotFound(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(sql.ErrNoRows)
	ch, err := repo.GetByID(context.Background(), uuid.New())
	if err != nil || ch != nil {
		t.Errorf("GetByID(no rows) = (%v, %v), want (nil, nil)", ch, err)
	}
}

func TestNotificationChannelRepo_GetByID_DBError(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(errDB)
	if _, err := repo.GetByID(context.Background(), uuid.New()); err == nil {
		t.Error("expected error")
	}
}

func TestNotificationChannelRepo_GetByID_BadEventsJSON(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	id := uuid.New()
	now := time.Now()
	rows := sqlmock.NewRows(notificationChannelTestCols).AddRow(
		id, "x", "webhook", "ENC", []byte("{not-json"), true,
		nil, nil, nil, now, now)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnRows(rows)
	if _, err := repo.GetByID(context.Background(), id); err == nil {
		t.Error("expected JSON unmarshal error")
	}
}

func TestNotificationChannelRepo_Update(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	id := uuid.New()
	mock.ExpectQuery("UPDATE notification_channels").
		WillReturnRows(fullChannelRow(id, "ENC"))
	updated, err := repo.Update(context.Background(), id, "ops", "webhook", []string{"cve_detected"}, true, "NEWENC")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated == nil || updated.EncryptedTarget != "" {
		t.Error("Update must return a redacted channel")
	}
}

func TestNotificationChannelRepo_Update_KeepTarget(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	id := uuid.New()
	mock.ExpectQuery("UPDATE notification_channels").
		WillReturnRows(minimalChannelRow(id, "ENC"))
	// Empty encryptedTarget => COALESCE keeps the existing one.
	if _, err := repo.Update(context.Background(), id, "ops", "email", nil, false, ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestNotificationChannelRepo_Update_NotFound(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectQuery("UPDATE notification_channels").WillReturnError(sql.ErrNoRows)
	ch, err := repo.Update(context.Background(), uuid.New(), "n", "webhook", nil, true, "E")
	if err != nil || ch != nil {
		t.Errorf("Update(no rows) = (%v, %v), want (nil, nil)", ch, err)
	}
}

func TestNotificationChannelRepo_Update_DBError(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectQuery("UPDATE notification_channels").WillReturnError(errDB)
	if _, err := repo.Update(context.Background(), uuid.New(), "n", "webhook", nil, true, "E"); err == nil {
		t.Error("expected error")
	}
}

func TestNotificationChannelRepo_Delete(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectExec("DELETE FROM notification_channels").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.Delete(context.Background(), uuid.New()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestNotificationChannelRepo_Delete_DBError(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectExec("DELETE FROM notification_channels").WillReturnError(errDB)
	if err := repo.Delete(context.Background(), uuid.New()); err == nil {
		t.Error("expected error")
	}
}

func TestNotificationChannelRepo_ListEnabledForEvent(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	id := uuid.New()
	mock.ExpectQuery("WHERE enabled").WillReturnRows(fullChannelRow(id, "ENC"))
	list, err := repo.ListEnabledForEvent(context.Background(), "cve_detected")
	if err != nil {
		t.Fatalf("ListEnabledForEvent: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	// The encrypted target must be retained here (it is needed to send).
	if list[0].EncryptedTarget != "ENC" {
		t.Error("ListEnabledForEvent must retain the encrypted target")
	}
}

func TestNotificationChannelRepo_ListEnabledForEvent_DBError(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectQuery("WHERE enabled").WillReturnError(errDB)
	if _, err := repo.ListEnabledForEvent(context.Background(), "cve_detected"); err == nil {
		t.Error("expected error")
	}
}

func TestNotificationChannelRepo_RecordDelivery(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectExec("UPDATE notification_channels SET last_status").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.RecordDelivery(context.Background(), uuid.New(), "sent", "", time.Now()); err != nil {
		t.Fatalf("RecordDelivery: %v", err)
	}
}

func TestNotificationChannelRepo_RecordDelivery_DBError(t *testing.T) {
	repo, mock := newNotificationChannelRepo(t)
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnError(errDB)
	if err := repo.RecordDelivery(context.Background(), uuid.New(), "failed", "boom", time.Now()); err == nil {
		t.Error("expected error")
	}
}
