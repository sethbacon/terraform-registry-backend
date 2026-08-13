package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Issue #869. The binary mirror served terraform-docs with sha256:"" for six
// weeks: every fail-closed installer refused it, and nothing in the registry
// said a word. The hash had been ingested correctly and was then erased on each
// subsequent sync by an upsert that carried an empty value (see
// TerraformMirrorRepository.UpsertPlatform).
//
// That defect is fixed at the write, and the sync job now re-derives any
// missing hash from upstream on its next run. What was still absent is a way to
// ASK — a single, re-runnable question an operator or a CI step can put to a
// live registry: is there any binary here that we serve but cannot give a
// consumer a checksum for?
//
// This is that question. It is read-only by construction. It deliberately does
// not repair, and in particular it never reads the SHA256SUMS blob out of our
// own storage to populate the column: the mirror's SHA256SUMS file and the
// binary it describes sit on the same storage host, while the API's inline
// sha256 comes from the application. Sourcing one from the other would collapse
// two authorities into one and quietly retire the control that makes a
// storage-account compromise detectable. Repopulation belongs to the sync path,
// which fetches from the upstream release, and only there.

// UnverifiablePlatform is one mirrored binary that the registry serves without
// a checksum: a terraform_version_platforms row in sync_status='synced' whose
// sha256 column is empty.
type UnverifiablePlatform struct {
	Config   string
	Tool     string
	Version  string
	OS       string
	Arch     string
	Filename string
	// HasSums records whether the version has a stored SHA256SUMS blob. It
	// separates the two shapes this defect takes: with a SUMS file the mirror
	// holds the answer and merely failed to put it in the column (the
	// terraform-docs case), without one the version predates checksum
	// persistence entirely (the legacy terraform 1.13.x case). Both are
	// unusable to a checksum-enforcing client; they differ in what fixes them.
	HasSums bool
}

func (u UnverifiablePlatform) String() string {
	sums := "no-sums-blob"
	if u.HasSums {
		sums = "sums-blob-stored"
	}
	return fmt.Sprintf("%s (%s) %s %s/%s %s [%s]", u.Config, u.Tool, u.Version, u.OS, u.Arch, u.Filename, sums)
}

// ErrUnverifiableBinariesRemain is returned by VerifyMirrorSHA256 when the
// registry is still serving at least one binary with no checksum.
//
// It exists so the check is scriptable, for the same reason ErrUnboundRemain
// does. The asymmetry that makes this worth a non-zero exit: the download API
// fails OPEN on this state — it returns sha256:"" and a 200 — while every
// client that verifies fails CLOSED. Nobody downstream can raise the alarm, so
// the gate has to be here.
var ErrUnverifiableBinariesRemain = errors.New("maintenance: mirrored binaries remain without a checksum")

// verifyMirrorSHA256Query is the whole audit. Deprecated versions are excluded
// because their platforms are no longer offered for download; everything else
// the mirror will serve is in scope, including versions outside a config's
// current version filter — the filter governs what the mirror acquires, not
// what it is already publishing.
const verifyMirrorSHA256Query = `
	SELECT c.name, c.tool, v.version, p.os, p.arch, p.filename,
	       (v.sums_storage_key IS NOT NULL AND v.sums_storage_key <> '') AS has_sums
	FROM terraform_version_platforms p
	JOIN terraform_versions v        ON v.id = p.version_id
	JOIN terraform_mirror_configs c  ON c.id = v.config_id
	WHERE p.sync_status = 'synced'
	  AND p.sha256 = ''
	  AND v.is_deprecated = false
	ORDER BY c.name, v.version, p.os, p.arch
`

// VerifyMirrorSHA256 lists every mirrored binary the registry serves without a
// checksum, newest configs first, and returns ErrUnverifiableBinariesRemain if
// there is at least one.
//
// Callers get the rows even alongside the error: the point of the command is
// the list, and a caller that only learned "some" would have to re-query to say
// which.
func VerifyMirrorSHA256(ctx context.Context, db *sql.DB) ([]UnverifiablePlatform, error) {
	if db == nil {
		return nil, errors.New("maintenance: no database handle")
	}

	rows, err := db.QueryContext(ctx, verifyMirrorSHA256Query)
	if err != nil {
		return nil, fmt.Errorf("maintenance: failed to query mirrored platforms: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var found []UnverifiablePlatform
	for rows.Next() {
		var u UnverifiablePlatform
		if scanErr := rows.Scan(&u.Config, &u.Tool, &u.Version, &u.OS, &u.Arch, &u.Filename, &u.HasSums); scanErr != nil {
			return nil, fmt.Errorf("maintenance: failed to scan mirrored platform: %w", scanErr)
		}
		found = append(found, u)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("maintenance: failed to read mirrored platforms: %w", rows.Err())
	}

	if len(found) > 0 {
		return found, ErrUnverifiableBinariesRemain
	}
	return found, nil
}

// SummariseUnverifiable groups the findings by config and tool for a one-line
// summary per mirror, so an operator sees the shape of the problem before the
// per-row list. Sorted for a stable, diffable output.
func SummariseUnverifiable(found []UnverifiablePlatform) []string {
	counts := make(map[string]int, len(found))
	for _, u := range found {
		counts[u.Config+" ("+u.Tool+")"]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s: %d platform(s) with no sha256", k, counts[k]))
	}
	return out
}

// FormatUnverifiable renders the full finding list, one row per line.
func FormatUnverifiable(found []UnverifiablePlatform) string {
	var b strings.Builder
	for _, u := range found {
		b.WriteString(u.String())
		b.WriteString("\n")
	}
	return b.String()
}
