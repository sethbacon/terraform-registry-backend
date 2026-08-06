// Package identityerr classifies errors returned by the shared identity module
// (github.com/sethbacon/terraform-suite-identity).
//
// It exists for one distinction: "nothing matched" versus "the lookup failed".
// identity/store reports the former with a single sentinel, store.ErrNotFound,
// as of v0.24.0. Before that release a read that missed returned (nil, nil) and
// a by-identifier UPDATE/DELETE that matched zero rows returned nil, so the two
// outcomes were indistinguishable at the call site — which is why so many
// handlers in this package's callers were written as an `err != nil` branch
// followed by a `value == nil` branch.
//
// Routing every such decision through the two predicates here keeps the answer
// to "which HTTP status does a miss produce?" greppable, and keeps the
// dual-spelling rationale in ONE place instead of repeated at forty call sites.
package identityerr

import (
	"errors"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// IsNotFound reports whether err says an accessor matched no row.
//
// Use it on MUTATIONS — RemoveMember, Delete, Update, RevokeAPIKey — where
// there is no value to inspect and zero rows affected is the whole signal.
// Two shapes of caller want it:
//
//   - Handlers that must map the miss to a status (404, or 204 for a DELETE
//     that is documented as idempotent).
//   - Reconciliation loops, where the miss means "this element is already in
//     the desired state" and the loop must CONTINUE rather than abort. See
//     scim.deprovisionUser and credlifecycle's sweeps.
func IsNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound)
}

// Missing reports whether a read that can miss did miss, accepting BOTH
// spellings of the miss.
//
// The (err == nil && v == nil) half is not redundant defensiveness — it is what
// makes a call site behave identically against the identity version this
// repository currently pins, where a miss arrives as (nil, nil), and v0.24.0,
// where it arrives as store.ErrNotFound. That matters because this repository
// must build and behave correctly on BOTH sides of the module upgrade: the
// version bump lands in a separate change, so between the two commits every one
// of these call sites runs against the older contract.
//
// It deliberately does NOT swallow a real failure: a non-sentinel error leaves
// Missing false, so the caller's own `if err != nil` branch still runs and a
// database fault can never be reported to a client as "not found".
//
// Order matters at the call site. Test Missing BEFORE the generic error branch:
//
//	x, err := repo.GetThing(ctx, id)
//	if identityerr.Missing(x, err) {
//	    c.JSON(http.StatusNotFound, ...)
//	    return
//	}
//	if err != nil {
//	    c.JSON(http.StatusInternalServerError, ...)
//	    return
//	}
//
// Written the other way round, the sentinel is consumed by `err != nil` and
// every 404 silently becomes a 500 — the exact defect this module release was
// published to make visible.
func Missing[T any](v *T, err error) bool {
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	return err == nil && v == nil
}
