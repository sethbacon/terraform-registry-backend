// Package models - notification_channel.go defines the NotificationChannel
// model: an admin-configured delivery destination (webhook, Slack, Microsoft
// Teams, or an ad-hoc email recipient list) for the module_published,
// approval_pending, cve_detected, and scanner_update_available notification
// events, in addition to the shared SMTP recipients list.
package models

import (
	"time"

	"github.com/google/uuid"
)

// NotificationChannel is a destination for admin-facing notification events.
// The target is held encrypted (EncryptedTarget) and never serialized to API
// callers; HasTarget reports whether one is configured without exposing the
// secret.
type NotificationChannel struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	Type            string     `json:"type"` // webhook | slack | teams | email
	EncryptedTarget string     `json:"-"`
	HasTarget       bool       `json:"has_target"`
	Events          []string   `json:"events"` // empty = all events
	Enabled         bool       `json:"enabled"`
	LastStatus      *string    `json:"last_status"`
	LastError       *string    `json:"last_error"`
	LastSentAt      *time.Time `json:"last_sent_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
