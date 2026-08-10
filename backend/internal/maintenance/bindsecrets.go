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
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Converting a column to the row-bound ciphertext form (suite-identity #153)
// cannot be a SQL migration: AES-GCM re-encryption needs the key, which only
// exists in the running application. Each converted column therefore needs a
// sweep, and this service has several more to go.
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
// The remaining ones (the LDAP bind password and the SMTP password, both fields
// inside a JSON config blob rather than columns of their own) are added here as
// each is converted in the application — the sweep for a column must not exist
// before
// the code that writes the bound form, or an operator can convert rows the
// running service then cannot read. "The code" means EVERY writer: the four
// storage_config entries below were only registrable once both the admin CRUD
// handlers and the first-run setup path sealed with a context, since otherwise
// the next first-run save would re-introduce an unbound row behind the sweep.
//
// Each entry derives its context by calling the same exported function the
// application seals with, never by rebuilding the string here. That is the whole
// reason those functions are exported: a second copy of the format in this file
// would drift from the first, and the symptom is an operator credential that no
// longer decrypts.
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
	storageConfigColumn("azure_account_key_encrypted", models.StorageConfigAzureAccountKeyContext),
	storageConfigColumn("s3_access_key_id_encrypted", models.StorageConfigS3AccessKeyIDContext),
	storageConfigColumn("s3_secret_access_key_encrypted", models.StorageConfigS3SecretAccessKeyContext),
	storageConfigColumn("gcs_credentials_json_encrypted", models.StorageConfigGCSCredentialsJSONContext),
	{
		// Every saved configuration, not just the active one. A retired row's
		// secret is exactly what an attacker would promote onto the active row,
		// so leaving inactive rows unconverted would leave the move available.
		name:    "oidc_config.client_secret_encrypted",
		context: models.OIDCConfigClientSecretContext,
		list: func(ctx context.Context, db *sql.DB) ([]sealedRow, error) {
			return listRows(ctx, db,
				`SELECT id, client_secret_encrypted FROM oidc_config WHERE client_secret_encrypted <> ''`)
		},
		update: func(ctx context.Context, db *sql.DB, id, bound string) error {
			_, err := db.ExecContext(ctx,
				`UPDATE oidc_config SET client_secret_encrypted = $2, updated_at = now() WHERE id = $1`,
				id, bound)
			return err
		},
	},
	{
		name:    "scm_providers.client_secret_encrypted",
		context: scm.ProviderClientSecretContext,
		list: func(ctx context.Context, db *sql.DB) ([]sealedRow, error) {
			return listRows(ctx, db,
				`SELECT id, client_secret_encrypted FROM scm_providers WHERE client_secret_encrypted <> ''`)
		},
		update: func(ctx context.Context, db *sql.DB, id, bound string) error {
			_, err := db.ExecContext(ctx,
				`UPDATE scm_providers SET client_secret_encrypted = $2, updated_at = now() WHERE id = $1`,
				id, bound)
			return err
		},
	},
	{
		// Nullable, unlike the client secret: only a github_app provider has
		// one. IS NOT NULL keeps a NULL out of the sealedRow.sealed scan.
		name:    "scm_providers.encrypted_app_private_key",
		context: scm.ProviderAppPrivateKeyContext,
		list: func(ctx context.Context, db *sql.DB) ([]sealedRow, error) {
			return listRows(ctx, db,
				`SELECT id, encrypted_app_private_key FROM scm_providers
				 WHERE encrypted_app_private_key IS NOT NULL AND encrypted_app_private_key <> ''`)
		},
		update: func(ctx context.Context, db *sql.DB, id, bound string) error {
			_, err := db.ExecContext(ctx,
				`UPDATE scm_providers SET encrypted_app_private_key = $2, updated_at = now() WHERE id = $1`,
				id, bound)
			return err
		},
	},
}

// storageConfigColumn describes one of the four storage_config credential
// columns.
//
// A constructor rather than four literals because these four differ only in
// which column they name, and a copy-paste of a twelve-line literal is how a
// query ends up selecting one column and writing back another — a bug that
// would move a credential between columns, which is the exact class this whole
// change exists to prevent. The column name is interpolated into the SQL, which
// is safe here and only here: the four call sites are literals in this file, not
// input.
//
// Both clauses of the WHERE matter. The empty-string test excludes a column
// left blank, which is "unset" rather than "unbound" and is not a conversion
// candidate; IS NOT NULL is what keeps a NULL out of the sealedRow.sealed string
// scan, since these columns are nullable — only the backend actually in use has
// its credentials populated.
func storageConfigColumn(dbColumn string, contextFor func(string) []byte) column {
	return column{
		name:    "storage_config." + dbColumn,
		context: contextFor,
		list: func(ctx context.Context, db *sql.DB) ([]sealedRow, error) {
			return listRows(ctx, db, fmt.Sprintf(
				`SELECT id, %s FROM storage_config WHERE %s IS NOT NULL AND %s <> ''`,
				dbColumn, dbColumn, dbColumn))
		},
		update: func(ctx context.Context, db *sql.DB, id, bound string) error {
			_, err := db.ExecContext(ctx, fmt.Sprintf(
				`UPDATE storage_config SET %s = $2, updated_at = now() WHERE id = $1`, dbColumn),
				id, bound)
			return err
		},
	}
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
