// Package maintenance holds operator-invoked, one-shot data tasks that cannot be
// expressed as SQL migrations.
package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
)

// Converting a column to the row-bound ciphertext form (suite-identity #153)
// cannot be a SQL migration: AES-GCM re-encryption needs the key, which only
// exists in the running application. Each converted column therefore needs a
// sweep, and this service has five more to go.
//
// Rather than five bespoke commands, a column describes itself with three
// things — how to list its rows, how to derive a row's context, how to write a
// converted value — and the sweep logic below is shared. The alternative is five
// near-identical loops that drift in exactly the details that matter: whether a
// bad row aborts the run, whether verify writes, whether an already-converted
// row is skipped or double-sealed.

// sealedRow is one candidate: a row id and the ciphertext currently stored.
type sealedRow struct {
	id     string
	sealed string
}

// column is one convertible secret column.
type column struct {
	// name appears in output; use table.column so a partial run is readable.
	name string
	// list returns every row holding a secret. An empty ciphertext means
	// "unset", not "unbound", and must be excluded here rather than filtered
	// later — it is not a conversion candidate.
	list func(ctx context.Context, db *sql.DB) ([]sealedRow, error)
	// context derives the AAD binding for a row. It MUST match what the
	// application seals with, or the conversion writes values the app cannot
	// read.
	context func(id string) []byte
	// update writes the converted ciphertext back for one row.
	update func(ctx context.Context, db *sql.DB, id, bound string) error
}

// Result is what one column's sweep did. Total is rows examined, not changed.
type Result struct {
	Total        int
	Converted    int
	AlreadyBound int
	Failed       int
}

func (r Result) String() string {
	return fmt.Sprintf("examined=%d converted=%d already-bound=%d failed=%d",
		r.Total, r.Converted, r.AlreadyBound, r.Failed)
}

// ErrUnboundRemain is returned by a verify run that found rows still unbound.
//
// It exists so the check is scriptable. Verify is the gate that says whether a
// column's reads can stop accepting the unbound form, and a gate that only
// prints is not a gate — it needs a non-zero exit for CI or a runbook step to
// hang off.
var ErrUnboundRemain = errors.New("maintenance: secrets remain unbound")

// columns is the registry of convertible columns.
//
// One entry today. The remaining four (storage credentials, setup secrets, SCM
// client secret and app private key, SMTP password) are added here as each is
// converted in the application — the sweep for a column must not exist before
// the code that writes the bound form, or an operator can convert rows the
// running service then cannot read.
var columns = []column{
	{
		name:    "notification_channels.encrypted_target",
		context: func(id string) []byte { return identitynotify.TargetContext(id) },
		list: func(ctx context.Context, db *sql.DB) ([]sealedRow, error) {
			return listRows(ctx, db,
				`SELECT id, encrypted_target FROM notification_channels WHERE encrypted_target <> ''`)
		},
		update: func(ctx context.Context, db *sql.DB, id, bound string) error {
			_, err := db.ExecContext(ctx,
				`UPDATE notification_channels SET encrypted_target = $2, updated_at = now() WHERE id = $1`,
				id, bound)
			return err
		},
	},
}

// listRows runs a two-column (id, ciphertext) query and drains it.
//
// The cursor is closed by a single deferred call, and closed BEFORE any caller
// starts writing: holding a result set open across the conversion UPDATEs would
// pin a connection for the length of the sweep.
func listRows(ctx context.Context, db *sql.DB, query string) ([]sealedRow, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []sealedRow
	for rows.Next() {
		var r sealedRow
		if err := rows.Scan(&r.id, &r.sealed); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// BindSecrets converts every registered column to the row-bound form, or with
// verifyOnly reports what remains without writing.
//
// Safe to re-run and safe to interrupt: an already-bound row is detected by
// opening it under its own context — no schema flag can answer this, because the
// form is a property of the ciphertext, not of the row — and skipped rather than
// double-sealed.
//
// A row that cannot be decrypted at all is reported and stepped over. That is a
// pre-existing problem this sweep did not cause and cannot fix, and abandoning
// the remaining rows over it would be worse.
func BindSecrets(
	ctx context.Context,
	db *sql.DB,
	tc *crypto.TokenCipher,
	verifyOnly bool,
) (map[string]Result, error) {
	if tc == nil {
		return nil, errors.New("maintenance: no token cipher configured (set ENCRYPTION_KEY)")
	}

	results := make(map[string]Result, len(columns))
	var unbound bool

	for _, col := range columns {
		rows, err := col.list(ctx, db)
		if err != nil {
			return results, fmt.Errorf("maintenance: list %s: %w", col.name, err)
		}

		res := Result{Total: len(rows)}
		for _, row := range rows {
			if _, err := tc.OpenWithContext(row.sealed, col.context(row.id)); err == nil {
				res.AlreadyBound++
				continue
			}
			bound, err := tc.ReSealWithContext(row.sealed, col.context(row.id))
			if err != nil {
				res.Failed++
				slog.Error("secret could not be converted",
					"column", col.name, "row_id", row.id, "error", err)
				continue
			}
			if verifyOnly {
				res.Converted++ // would convert
				continue
			}
			if err := col.update(ctx, db, row.id, bound); err != nil {
				res.Failed++
				slog.Error("converted secret could not be written",
					"column", col.name, "row_id", row.id, "error", err)
				continue
			}
			res.Converted++
		}

		results[col.name] = res
		if res.Converted > 0 || res.Failed > 0 {
			unbound = true
		}
	}

	if verifyOnly && unbound {
		return results, ErrUnboundRemain
	}
	return results, nil
}
