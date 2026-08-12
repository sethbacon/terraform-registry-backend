// Package maintenance holds operator-invoked, one-shot data tasks that cannot be
// expressed as SQL migrations.
package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

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
	// singleton marks a secret with no row axis: a field inside a config blob
	// on system_settings, of which there is exactly one row. Its context binds
	// the purpose (which blob, which field) rather than a row id, so
	// TestRegisteredColumns_ContextsAreRowScoped cannot apply and this flag
	// tells it so.
	//
	// The flag is "singleton" rather than the more natural "rowScoped" so that
	// its ZERO VALUE is the strict setting. A rowScoped field would default to
	// false in Go, which means a column added without a thought about this
	// would be silently exempted from the row-scoping check — the guard would
	// quietly stop guarding exactly when someone was not paying attention.
	// This way, forgetting the field means being checked.
	singleton bool
}

// Result is what one column's sweep did. Total is rows examined, not changed.
//
// The two sweeps share this struct because they answer the same two questions
// per row — did it need work, and did the work land — and a second
// near-identical struct would drift from this one exactly the way five bespoke
// loops would have.
//
// They do NOT share a reason for skipping a row, though, and that difference is
// the whole of #848: bind-secrets skips a row that is already bound, a rekey run
// skips one that is already on the current key, and a row can be the first
// without being the second. AlreadyBound therefore carries the count and
// `skipped` carries what it means, so a rekey run never prints "already-bound"
// over a row that still needs the key the operator is about to delete.
type Result struct {
	Total        int
	Converted    int
	AlreadyBound int
	Failed       int

	// skipped labels AlreadyBound in String(). Empty means the binding sweep's
	// wording, so a zero Result still prints sensibly.
	skipped string
}

func (r Result) String() string {
	skipped := r.skipped
	if skipped == "" {
		skipped = "already-bound"
	}
	return fmt.Sprintf("examined=%d converted=%d %s=%d failed=%d",
		r.Total, r.Converted, skipped, r.AlreadyBound, r.Failed)
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
// This is now every secret this service seals. The rule that got them all here:
// the sweep for a column must not exist before
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
	blobField("notifications_config", "smtp_password_encrypted",
		models.SystemSettingsSMTPPasswordContext, "smtp"),
	blobField("ldap_config", "bind_password_enc",
		models.SystemSettingsLDAPBindPasswordContext),
}

// systemSettingsID is the single row every config blob lives on. It is passed
// through the sweep as the "row id" so the shared logic needs no special case,
// but the singleton contexts ignore it.
const systemSettingsID = "1"

// blobField describes a secret stored as a FIELD inside a JSON config blob on
// the system_settings singleton, rather than as a column of its own.
//
// path is the object nesting above the field ("smtp" for the SMTP password, none
// for the LDAP bind password). The whole blob is one column, so converting the
// secret means read-modify-write of the JSON.
//
// The rewrite goes through a generic map, NEVER through the typed struct the
// application unmarshals into. Round-tripping the blob through
// admin.NotificationsConfigDB would silently DROP every field that struct does
// not know about — an older key, a newer key written by a replica mid-upgrade,
// anything hand-added — and turn a credential conversion into config data loss.
// A map preserves what it does not understand, which is the only safe posture
// for a tool that runs once against production.
func blobField(
	blobColumn, field string,
	contextFor func() []byte,
	path ...string,
) column {
	name := "system_settings." + blobColumn + ":" + strings.Join(append(path, field), ".")
	return column{
		name:      name,
		singleton: true,
		context:   func(string) []byte { return contextFor() },
		list: func(ctx context.Context, db *sql.DB) ([]sealedRow, error) {
			blob, err := readBlob(ctx, db, blobColumn)
			if err != nil || blob == nil {
				return nil, err
			}
			sealed, _ := blobLookup(blob, append(path, field))
			if sealed == "" {
				return nil, nil // unset, not unbound
			}
			return []sealedRow{{id: systemSettingsID, sealed: sealed}}, nil
		},
		update: func(ctx context.Context, db *sql.DB, _, bound string) error {
			blob, err := readBlob(ctx, db, blobColumn)
			if err != nil {
				return err
			}
			if blob == nil {
				return fmt.Errorf("maintenance: %s disappeared between read and write", blobColumn)
			}
			if err := blobAssign(blob, append(path, field), bound); err != nil {
				return err
			}
			encoded, err := json.Marshal(blob)
			if err != nil {
				return err
			}
			// The blob column only; notifications_configured / ldap_configured
			// and their timestamps are untouched, because re-sealing a secret
			// is not the operator configuring anything.
			_, err = db.ExecContext(ctx,
				// #nosec G201 -- blobColumn is one of two literals passed by the registry
				// below, never caller input; the secret itself is a bound parameter.
				fmt.Sprintf(`UPDATE system_settings SET %s = $1, updated_at = now() WHERE id = 1`, blobColumn),
				encoded)
			return err
		},
	}
}

// readBlob loads one JSON config column from system_settings, or nil when it is
// absent or empty.
func readBlob(ctx context.Context, db *sql.DB, blobColumn string) (map[string]any, error) {
	var raw []byte
	err := db.QueryRowContext(ctx,
		// #nosec G201 -- blobColumn is one of two literals passed by the registry, never input
		fmt.Sprintf(`SELECT %s FROM system_settings WHERE id = 1`, blobColumn),
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || len(raw) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var blob map[string]any
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("maintenance: %s is not a JSON object: %w", blobColumn, err)
	}
	return blob, nil
}

// blobLookup walks path through nested objects and returns the string at the
// end, or "" if any step is missing or the wrong shape.
func blobLookup(blob map[string]any, path []string) (string, bool) {
	cur := blob
	for _, step := range path[:len(path)-1] {
		next, ok := cur[step].(map[string]any)
		if !ok {
			return "", false
		}
		cur = next
	}
	s, ok := cur[path[len(path)-1]].(string)
	return s, ok
}

// blobAssign sets the string at path, refusing rather than creating missing
// parents: the sweep only ever rewrites a field it has already READ, so an
// absent parent means the blob changed underneath the run and guessing at its
// shape would corrupt it.
func blobAssign(blob map[string]any, path []string, value string) error {
	cur := blob
	for _, step := range path[:len(path)-1] {
		next, ok := cur[step].(map[string]any)
		if !ok {
			return fmt.Errorf("maintenance: %q is missing from the config blob; it changed during the sweep", step)
		}
		cur = next
	}
	cur[path[len(path)-1]] = value
	return nil
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

// converter decides what a sweep does with one row. needsWork false means the
// row is already in the target form and must be left alone; otherwise
// replacement is the ciphertext to store.
//
// An error is a row-level failure — reported, stepped over, and counted against
// the verify gate. It is never a reason to abandon the remaining rows.
type converter func(col column, row sealedRow) (replacement string, needsWork bool, err error)

// sweep runs one converter over every registered column, writing unless
// verifyOnly, and reports whether any row needed work or failed.
//
// It is shared by BindSecrets and RekeySecrets so that the properties an
// operator relies on — verify writes nothing, one bad row does not abandon the
// rest, the whole registry is walked rather than a subset — are implemented once
// and cannot hold for one command and not the other. `skipped` is only the word
// the two use for a row they left alone.
//
// Writes are per row, not per sweep. A transaction spanning every credential in
// the database would hold locks for the length of the run and turn a partial
// failure into an all-or-nothing one; a single-row UPDATE is already atomic, so
// an interrupted sweep leaves each row either wholly converted or wholly
// untouched, and both forms still open. That is what makes it resumable.
func sweep(
	ctx context.Context,
	db *sql.DB,
	verifyOnly bool,
	skipped string,
	convert converter,
) (map[string]Result, bool, error) {
	results := make(map[string]Result, len(columns))
	var workRemains bool

	for _, col := range columns {
		rows, err := col.list(ctx, db)
		if err != nil {
			return results, workRemains, fmt.Errorf("maintenance: list %s: %w", col.name, err)
		}

		res := Result{Total: len(rows), skipped: skipped}
		for _, row := range rows {
			replacement, needsWork, err := convert(col, row)
			if err != nil {
				res.Failed++
				slog.Error("secret could not be converted",
					"column", col.name, "row_id", row.id, "error", err)
				continue
			}
			if !needsWork {
				res.AlreadyBound++
				continue
			}
			if verifyOnly {
				res.Converted++ // would convert
				continue
			}
			if err := col.update(ctx, db, row.id, replacement); err != nil {
				res.Failed++
				slog.Error("converted secret could not be written",
					"column", col.name, "row_id", row.id, "error", err)
				continue
			}
			res.Converted++
		}

		results[col.name] = res
		if res.Converted > 0 || res.Failed > 0 {
			workRemains = true
		}
	}

	return results, workRemains, nil
}

// BindSecrets converts every registered column to the row-bound form, or with
// verifyOnly reports what remains without writing.
//
// Safe to re-run and safe to interrupt: an already-bound row is detected by
// opening it under its own context — no schema flag can answer this, because the
// form is a property of the ciphertext, not of the row — and skipped rather than
// double-sealed.
//
// That skip is binding-only, and deliberately so: OpenWithContext falls back to
// the previous key, so a row bound before a key rotation opens here and is left
// where it is. Completing a rotation is RekeySecrets' job, not this one's
// (#848).
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

	results, unbound, err := sweep(ctx, db, verifyOnly, "already-bound",
		func(col column, row sealedRow) (string, bool, error) {
			if _, err := tc.OpenWithContext(row.sealed, col.context(row.id)); err == nil {
				return "", false, nil
			}
			bound, err := tc.ReSealWithContext(row.sealed, col.context(row.id))
			return bound, true, err
		})
	if err != nil {
		return results, err
	}

	if verifyOnly && unbound {
		return results, ErrUnboundRemain
	}
	return results, nil
}
