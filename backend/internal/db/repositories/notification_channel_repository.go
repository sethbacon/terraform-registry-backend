// notification_channel_repository.go is the DAO for notification_channels:
// admin-configured delivery destinations (webhook, Slack, Microsoft Teams, or
// an ad-hoc email recipient list) for notification events, in addition to the
// shared SMTP recipients list.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

const notificationChannelColumns = `id, name, type, encrypted_target, events, enabled,
	last_status, last_error, last_sent_at, created_at, updated_at`

// NotificationChannelRepository is the DAO for notification_channels.
type NotificationChannelRepository struct {
	db *sql.DB
}

// NewNotificationChannelRepository constructs the repository over the app connection.
func NewNotificationChannelRepository(db *sql.DB) *NotificationChannelRepository {
	return &NotificationChannelRepository{db: db}
}

func scanNotificationChannel(scanner interface{ Scan(dest ...any) error }) (*models.NotificationChannel, error) {
	var ch models.NotificationChannel
	var eventsJSON []byte
	var lastStatus, lastError sql.NullString
	var lastSentAt sql.NullTime
	if err := scanner.Scan(&ch.ID, &ch.Name, &ch.Type, &ch.EncryptedTarget, &eventsJSON, &ch.Enabled,
		&lastStatus, &lastError, &lastSentAt, &ch.CreatedAt, &ch.UpdatedAt); err != nil {
		return nil, err
	}
	ch.HasTarget = ch.EncryptedTarget != ""
	if len(eventsJSON) > 0 {
		if err := json.Unmarshal(eventsJSON, &ch.Events); err != nil {
			return nil, err
		}
	}
	if ch.Events == nil {
		ch.Events = []string{}
	}
	if lastStatus.Valid {
		ch.LastStatus = &lastStatus.String
	}
	if lastError.Valid {
		ch.LastError = &lastError.String
	}
	if lastSentAt.Valid {
		ch.LastSentAt = &lastSentAt.Time
	}
	return &ch, nil
}

// Create inserts a new channel and returns it (with the target redacted).
func (r *NotificationChannelRepository) Create(ctx context.Context, ch *models.NotificationChannel) (*models.NotificationChannel, error) {
	eventsJSON, err := json.Marshal(ch.Events)
	if err != nil {
		return nil, err
	}
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO notification_channels (name, type, encrypted_target, events, enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+notificationChannelColumns,
		ch.Name, ch.Type, ch.EncryptedTarget, eventsJSON, ch.Enabled)
	saved, err := scanNotificationChannel(row)
	if err != nil {
		return nil, err
	}
	saved.EncryptedTarget = "" // never expose the secret to callers
	return saved, nil
}

// List returns all channels without the encrypted target (for the admin UI).
func (r *NotificationChannelRepository) List(ctx context.Context) ([]models.NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+notificationChannelColumns+` FROM notification_channels ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.NotificationChannel{}
	for rows.Next() {
		ch, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		ch.EncryptedTarget = ""
		out = append(out, *ch)
	}
	return out, rows.Err()
}

// GetByID returns a channel including its encrypted target (for decryption by
// the notifier / test endpoint). Returns (nil, nil) when not found.
func (r *NotificationChannelRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.NotificationChannel, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+notificationChannelColumns+` FROM notification_channels WHERE id = $1`, id)
	ch, err := scanNotificationChannel(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ch, nil
}

// Update replaces the mutable fields. When encryptedTarget is empty the
// existing target is kept (so editing a channel without re-entering the
// secret is allowed). Returns (nil, nil) when the channel does not exist.
func (r *NotificationChannelRepository) Update(ctx context.Context, id uuid.UUID, name, typ string, events []string, enabled bool, encryptedTarget string) (*models.NotificationChannel, error) {
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	var targetArg any
	if encryptedTarget != "" {
		targetArg = encryptedTarget
	}
	row := r.db.QueryRowContext(ctx, `
		UPDATE notification_channels
		SET name=$2, type=$3, events=$4, enabled=$5,
		    encrypted_target=COALESCE($6, encrypted_target), updated_at=now()
		WHERE id=$1
		RETURNING `+notificationChannelColumns,
		id, name, typ, eventsJSON, enabled, targetArg)
	ch, err := scanNotificationChannel(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ch.EncryptedTarget = ""
	return ch, nil
}

// Delete removes a channel.
func (r *NotificationChannelRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	return err
}

// ListEnabledForEvent returns enabled channels subscribed to eventType (a
// channel with no events subscribes to all). Includes the encrypted target
// for sending.
func (r *NotificationChannelRepository) ListEnabledForEvent(ctx context.Context, eventType string) ([]models.NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+notificationChannelColumns+`
		FROM notification_channels
		WHERE enabled AND (jsonb_array_length(events) = 0 OR events @> to_jsonb($1::text))`, eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.NotificationChannel{}
	for rows.Next() {
		ch, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ch)
	}
	return out, rows.Err()
}

// RecordDelivery stamps the outcome of the most recent send attempt.
func (r *NotificationChannelRepository) RecordDelivery(ctx context.Context, id uuid.UUID, status, errMsg string, sentAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_channels SET last_status=$2, last_error=NULLIF($3,''), last_sent_at=$4, updated_at=now() WHERE id=$1`,
		id, status, errMsg, sentAt)
	return err
}
