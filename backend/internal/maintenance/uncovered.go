// Package maintenance - uncovered.go makes the rekey gate say what it does NOT
// certify (#878).
//
// THE DEFECT THIS CLOSES IS A REPORTING ONE, NOT A COVERAGE ONE. `rekey-secrets
// verify` exists to answer exactly one question: is it safe to drop
// ENCRYPTION_KEY_PREVIOUS? It answers that for the columns it sweeps, and says
// NOTHING about the columns it does not. An operator can follow the runbook
// exactly, see verify exit zero, drop the previous key, and leave unrefreshed
// user SCM links unreadable until those users re-link.
//
// A gate that reports success over a set narrower than the operator believes it
// covers converts an unknown into a wrong answer. That is worse than no gate,
// and it is fixed by printing a number rather than by re-encrypting anything.
//
// WHY THIS COUNTS ROWS AND DOES NOT TOUCH CIPHERTEXT. The obvious next step --
// sweep the columns too -- is not safe to take blind, and the reason is
// specific. The AAD for these two columns derives from the row's user and
// provider ids, and a sweep that derives it WRONGLY is not fail-closed on the
// rows that matter: TokenCipher's legacy fallback discards the supplied AAD, so
// an unbound row opens anyway, gets re-sealed under the wrong AAD, passes the
// sweep's own round-trip proof, and reports green on every later verify. The
// gate cannot catch that, because the gate and the sweep derive the AAD the same
// way.
//
// A read-only count cannot do any of that. Its worst failure is an inaccurate
// number, which is loud and free to correct.
package maintenance

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// UncoveredColumn is an encrypted column the rekey sweep does not convert.
//
// ContextFunc names the AAD derivation, and is the join key with the coverage
// guard's exemption list -- so an exemption cannot be added without the operator
// being told about the rows behind it, and this list cannot name a column the
// guard does not know about.
//
// Name IS THE QUERY, not a label for it. The COUNT is built by splitting this
// one string, so the identifier a test checks against the migrations and the
// identifier the statement actually selects on cannot be different. An earlier
// draft carried the table and column a second time inside the count and was
// provably inert: misspelling them there left Name correct, the typo-catcher
// green, and the query erroring at runtime into "population unknown" -- a
// softer, more ignorable version of the silence this whole file replaces.
type UncoveredColumn struct {
	Name        string
	ContextFunc string
	Reason      string
}

// count returns how many rows currently hold a non-empty secret in this column.
func (c UncoveredColumn) count(ctx context.Context, db *sql.DB) (int, error) {
	table, column, ok := strings.Cut(c.Name, ".")
	if !ok {
		return 0, fmt.Errorf("uncovered column %q is not in table.column form", c.Name)
	}
	// Identifiers come from the constant registry below, never caller input.
	q := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s IS NOT NULL AND %s <> ''`, table, column, column) // #nosec G201
	var n int
	if err := db.QueryRowContext(ctx, q).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// UncoveredReport is one column's population at verify time.
type UncoveredReport struct {
	Column      string
	Reason      string
	Rows        int
	CountFailed error
}

// uncoveredColumns is the registry. Every entry must have a matching exemption
// in the coverage guard, and vice versa -- asserted bidirectionally in
// uncovered_test.go, so neither list can drift from the other.
var uncoveredColumns = []UncoveredColumn{
	{
		Name:        "scm_oauth_tokens.access_token_encrypted",
		ContextFunc: "UserTokenContext",
		Reason: "not swept: the AAD derives from the row's user and provider ids. " +
			"A lost token is restored by that user re-linking their account.",
	},
	{
		Name:        "scm_oauth_tokens.refresh_token_encrypted",
		ContextFunc: "UserRefreshTokenContext",
		Reason:      "not swept, as above. Without it a link cannot refresh and the user must re-link.",
	},
	{
		Name:        "scm_provider_tokens.access_token_encrypted",
		ContextFunc: "ProviderTokenContext",
		Reason: "not swept, and does not need to be: a cache with an expiry whose entries are " +
			"re-minted from the provider, so the table converts itself.",
	},
}

// ReportUncovered counts the rows in every column the rekey sweep does not
// convert.
//
// A failing count is reported per column rather than aborting: the point is to
// tell the operator what the gate does not cover, and losing that message
// because one table was unreadable would reinstate exactly the silence this
// exists to end.
func ReportUncovered(ctx context.Context, db *sql.DB) []UncoveredReport {
	out := make([]UncoveredReport, 0, len(uncoveredColumns))
	for _, c := range uncoveredColumns {
		r := UncoveredReport{Column: c.Name, Reason: c.Reason}
		n, err := c.count(ctx, db)
		if err != nil {
			r.CountFailed = err
		} else {
			r.Rows = n
		}
		out = append(out, r)
	}
	return out
}

// UncoveredContextFuncs returns the AAD derivations this registry declares
// uncovered, for the coverage guard to check itself against.
func UncoveredContextFuncs() []string {
	out := make([]string, 0, len(uncoveredColumns))
	for _, c := range uncoveredColumns {
		out = append(out, c.ContextFunc)
	}
	return out
}
