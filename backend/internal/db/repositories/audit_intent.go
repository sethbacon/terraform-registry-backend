// audit_intent.go carries the contract every privileged mutation in this
// package is held to: the audit record is written INSIDE the mutation's own
// transaction, or the mutation does not happen (issue #766, migration 000052).
package repositories

import (
	"context"
	"database/sql"
	"errors"
)

// AuditIntentWriter writes the audit intent describing a mutation into that
// mutation's own transaction.
//
// A function rather than a repository handle, deliberately: this package must
// not know what an audit record looks like or where it eventually lands. It
// knows only that something has to be written before the commit, and that a
// refusal here has to abort the mutation. internal/audit supplies the
// implementation (the transactional outbox); internal/api/admin supplies the
// content.
type AuditIntentWriter func(ctx context.Context, tx *sql.Tx) error

// ErrAuditIntentRequired is returned when a privileged mutation is attempted
// with no AuditIntentWriter.
//
// NOT AN OPTIONAL PARAMETER, AND NOT A WARNING. Before this existed the audit
// entry was written after the mutation, on a different connection, and a
// failure was logged while the mutation still reported success — so the
// highest-privilege operation in the product could commit unaudited. The
// argument is mandatory so that "forgot to audit it" is a compile-time
// omission that fails closed at runtime, and migration 000052's deferred
// constraint trigger refuses the commit even when this check is bypassed.
var ErrAuditIntentRequired = errors.New("privileged mutation requires an audit intent writer")
