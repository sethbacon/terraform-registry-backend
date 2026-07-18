// Package models - notification_channel.go aliases the NotificationChannel
// model from the shared identity/notify package: an admin-configured delivery
// destination (webhook, Slack, Microsoft Teams, or an ad-hoc email recipient
// list) for the module_published, approval_pending, cve_detected, and
// scanner_update_available notification events, in addition to the shared
// SMTP recipients list.
package models

import identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

// NotificationChannel is a destination for admin-facing notification events.
// The target is held encrypted (EncryptedTarget) and never serialized to API
// callers; HasTarget reports whether one is configured without exposing the
// secret. Note: ID is a plain string (not uuid.UUID), matching the shared
// package's convention.
type NotificationChannel = identitynotify.NotificationChannel
