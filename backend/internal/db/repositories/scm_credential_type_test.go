package repositories

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// entra_credential_type is NOT NULL with a CHECK constraining it to the two
// implemented values (migration 000062, issue #1037). Every caller that predates
// the column leaves the field zero, so the repository -- not the caller -- has to
// supply the default.
//
// This is asserted directly rather than through a handler because the failure it
// guards is invisible to sqlmock: an empty string is a perfectly good mock
// argument, and only a real database rejects it. Writing "" would fail the CHECK
// on EVERY provider insert, in every auth mode, not just entra_app ones.
func TestEntraCredentialType_DefaultsForCallersThatNeverSetIt(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"unset -- every caller written before the column existed", "", scm.EntraCredentialClientSecret},
		{"client_secret is preserved", scm.EntraCredentialClientSecret, scm.EntraCredentialClientSecret},
		{"federated is preserved", scm.EntraCredentialFederated, scm.EntraCredentialFederated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := entraCredentialType(&scm.SCMProvider{EntraCredentialType: tc.in})
			if got != tc.want {
				t.Errorf("entraCredentialType(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got == "" {
				t.Error("an empty credential type violates the column's CHECK on a real database, " +
					"which sqlmock-backed tests cannot see")
			}
		})
	}
}
