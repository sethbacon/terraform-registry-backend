package admin

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	errEmailNotVerified            = errors.New("oidc email is not verified")
	errEmailVerifiedMissing        = errors.New("oidc email_verified claim is required but absent")
	errEmailBoundToAnotherIdentity = errors.New("email is already bound to a different identity")
)

// authUserCols is the column order guardEmailRebind scans (matches the test's sqlmock rows).
var authUserCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

func enforceEmailVerified(verified *bool, require bool) error {
	if verified == nil {
		if require {
			return errEmailVerifiedMissing
		}
		return nil
	}
	if !*verified {
		return errEmailNotVerified
	}
	return nil
}

type claimReader interface{ Claims(v interface{}) error }

func emailVerifiedClaim(r claimReader) *bool {
	var c struct {
		EmailVerified *bool `json:"email_verified"`
	}
	if err := r.Claims(&c); err != nil {
		return nil
	}
	return c.EmailVerified
}

// guardEmailRebind refuses to link a login to an existing account owned by a
// DIFFERENT oidc_sub. Blank email, no existing user, NULL sub (pre-provisioned),
// and same-sub re-login are all allowed.
func (h *AuthHandlers) guardEmailRebind(ctx context.Context, oidcSub, email string) error {
	if email == "" {
		return nil
	}
	var id, em, name string
	var existingSub *string
	var created, updated time.Time
	err := h.db.QueryRowContext(ctx,
		`SELECT id, email, name, oidc_sub, created_at, updated_at FROM users WHERE email = $1`, email).
		Scan(&id, &em, &name, &existingSub, &created, &updated)
	switch err {
	case sql.ErrNoRows:
		return nil
	case nil:
		if existingSub == nil || *existingSub == oidcSub {
			return nil
		}
		return errEmailBoundToAnotherIdentity
	default:
		return err
	}
}
