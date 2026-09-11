// notification_channel_repository.go aliases the ChannelRepository DAO from
// the shared identity/notify package: admin-configured delivery destinations
// (webhook, Slack, Microsoft Teams, or an ad-hoc email recipient list) for
// notification events, in addition to the shared SMTP recipients list.
//
// # These channels are PLATFORM-LEVEL, and that is a decision, not an omission
//
// notification_channels carries no organization_id (migration 000048 is still
// the only migration that touches the table) and its UNIQUE index is on name
// alone. Both are deliberate: a channel here is a delivery destination for the
// whole deployment, and every route that reaches this repository —
// list/create/update/delete/test, router_routes.go — is gated on
// auth.ScopeAdmin, which since #766 and migration 000054 is held only by a
// principal with a row in the platform-admin carrier and is never inherited by
// an API key. An organization admin cannot reach this surface, so there is no
// tenant whose channels another tenant could enumerate and none for a name to
// collide with.
//
// terraform-state-manager's equivalent table IS partitioned (its migration
// 000033 added a nullable organization_id) because its channels are per-tenant.
// The divergence is intentional and argued at length in the shared package's
// identity/notify/channel_scope.go. It is written down HERE as well because
// reading the two schemas side by side makes registry look like the app that
// is lagging, which is how #1055 came to be filed and then withdrawn.
//
// # What that means for the shared library's scoping options
//
// Every row-selecting method on ChannelRepository takes a variadic
// notify.ChannelQueryOption, and Create takes a notify.ChannelWriteOption.
// Registry passes NONE of them, at every call site, on purpose. Per
// channel_scope.go an absent option is not a scope that failed open — it is the
// statement that this table has nothing to scope by, and it keeps registry's
// emitted SQL byte-identical to the unscoped statements the package has always
// sent. Do not add notify.WithOrgScope here to "be safe": against a table with
// no organization_id it is a query error, and a zero OrgScope matches nothing.
//
// If registry ever grows per-organization channels, the library is already
// ready for it — add the column, backfill, re-key the name index to
// (organization_id, name), pass notify.WithOwningOrganization on create and
// notify.WithOrgScope on every read, and call
// notify.VerifyChannelOrganizationColumn at startup so the intent is a checked
// fact. That is a feature, with a migration and a scope resolver behind it, not
// a security repair.
package repositories

import identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

// NotificationChannelRepository is the DAO for notification_channels.
type NotificationChannelRepository = identitynotify.ChannelRepository

// NewNotificationChannelRepository constructs the repository over the app connection.
var NewNotificationChannelRepository = identitynotify.NewChannelRepository
