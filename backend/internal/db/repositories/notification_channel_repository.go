// notification_channel_repository.go aliases the ChannelRepository DAO from
// the shared identity/notify package: admin-configured delivery destinations
// (webhook, Slack, Microsoft Teams, or an ad-hoc email recipient list) for
// notification events, in addition to the shared SMTP recipients list.
package repositories

import identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

// NotificationChannelRepository is the DAO for notification_channels.
type NotificationChannelRepository = identitynotify.ChannelRepository

// NewNotificationChannelRepository constructs the repository over the app connection.
var NewNotificationChannelRepository = identitynotify.NewChannelRepository
