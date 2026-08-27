package repositories

// provider_namespace_resolution_test.go is the #972 regression.
//
// A provider owned by any organization other than the one literally named
// "default" was a permanent 404 to every Terraform client. The module half of
// the protocol resolved globally by namespace; the provider half resolved to
// the default organization, so the two halves of one protocol disagreed -- and
// a deployment that renamed or deleted its default organization served its
// modules correctly and its providers to nobody, with no error to say why.

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func providerRowCols() []string {
	return []string{"id", "organization_id", "namespace", "type", "description",
		"source", "created_by", "created_at", "updated_at", "created_by_name"}
}

func newProviderRepoMock(t *testing.T) (*ProviderRepository, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	return NewProviderRepository(db), mock, func() { _ = db.Close() }
}

// TestGetProviderByNamespace_TakesOnlyProtocolCoordinates pins the property.
//
// WithArgs is the assertion that matters: an organization predicate cannot be
// reintroduced without a third argument, and sqlmock refuses a call whose
// arguments do not match. The query regex pins the WHERE clause as well, so a
// filter smuggled in as a literal rather than a placeholder also fails.
func TestGetProviderByNamespace_TakesOnlyProtocolCoordinates(t *testing.T) {
	repo, mock, closeDB := newProviderRepoMock(t)
	defer closeDB()

	mock.ExpectQuery(`WHERE p\.namespace = \$1 AND p\.type = \$2 ORDER BY`).
		WithArgs("acme", "widget").
		WillReturnRows(sqlmock.NewRows(providerRowCols()))

	if _, _, err := repo.GetProviderByNamespace(context.Background(), "acme", "widget"); err != nil {
		t.Fatalf("GetProviderByNamespace: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the query was not the two-coordinate lookup: %v", err)
	}
}

// TestGetProviderByNamespace_ServesProvidersOwnedByAnyOrganization is the
// user-visible bug.
//
// The NULL case is called out separately because the old query's
// `OR p.organization_id IS NULL` was what kept mirrored and single-tenant
// providers working, and the issue explicitly cautions against "fixing" this by
// deleting that clause. Dropping the predicate entirely subsumes it -- but only
// if that is actually true, which is what this asserts.
func TestGetProviderByNamespace_ServesProvidersOwnedByAnyOrganization(t *testing.T) {
	for _, tc := range []struct {
		name    string
		orgID   any
		wantOrg string
	}{
		{"owned by a non-default organization", "11111111-1111-1111-1111-111111111111", "11111111-1111-1111-1111-111111111111"},
		{"mirrored or single-tenant (NULL organization)", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, mock, closeDB := newProviderRepoMock(t)
			defer closeDB()

			mock.ExpectQuery(`FROM providers`).
				WillReturnRows(sqlmock.NewRows(providerRowCols()).
					AddRow("prov-1", tc.orgID, "acme", "widget", nil, "acme/terraform-provider-widget",
						nil, time.Now(), time.Now(), nil))

			provider, others, err := repo.GetProviderByNamespace(context.Background(), "acme", "widget")
			if err != nil {
				t.Fatalf("GetProviderByNamespace: %v", err)
			}
			if provider == nil {
				t.Fatal("provider not found. Before #972 this was a permanent 404 to every " +
					"Terraform client for any provider not owned by the organization named \"default\".")
			}
			if provider.OrganizationID != tc.wantOrg {
				t.Errorf("OrganizationID = %q, want %q", provider.OrganizationID, tc.wantOrg)
			}
			if others != 0 {
				t.Errorf("others = %d, want 0", others)
			}
		})
	}
}

// TestGetProviderByNamespace_MissIsNotAnError keeps a 404 a 404.
//
// Returning an error for "no such provider" would turn every miss into a 500,
// which is a different wrong answer rather than a fix.
func TestGetProviderByNamespace_MissIsNotAnError(t *testing.T) {
	repo, mock, closeDB := newProviderRepoMock(t)
	defer closeDB()

	mock.ExpectQuery(`FROM providers`).WillReturnRows(sqlmock.NewRows(providerRowCols()))

	provider, others, err := repo.GetProviderByNamespace(context.Background(), "acme", "widget")
	if err != nil {
		t.Fatalf("a miss returned an error: %v", err)
	}
	if provider != nil || others != 0 {
		t.Errorf("got (%v, %d), want (nil, 0)", provider, others)
	}
}

// TestGetProviderByNamespace_ReportsCollisions covers what removing the
// organization predicate makes possible: two organizations publishing the same
// namespace/type.
//
// Provider storage keys carry no organization segment, so those two rows may
// already have overwritten each other's archives. The count is returned rather
// than swallowed so a caller that wants to refuse can, and it is deterministic
// -- ordered by created_at then id -- because a resolution that varies per
// request is worse than one that is consistently wrong.
func TestGetProviderByNamespace_ReportsCollisions(t *testing.T) {
	repo, mock, closeDB := newProviderRepoMock(t)
	defer closeDB()

	older := time.Now().Add(-time.Hour)
	mock.ExpectQuery(`ORDER BY p\.created_at ASC, p\.id ASC`).
		WillReturnRows(sqlmock.NewRows(providerRowCols()).
			AddRow("prov-older", "org-a", "acme", "widget", nil, "", nil, older, older, nil).
			AddRow("prov-newer", "org-b", "acme", "widget", nil, "", nil, time.Now(), time.Now(), nil))

	provider, others, err := repo.GetProviderByNamespace(context.Background(), "acme", "widget")
	if err != nil {
		t.Fatalf("GetProviderByNamespace: %v", err)
	}
	if provider == nil {
		t.Fatal("a collision returned nothing; it must still serve one row deterministically")
	}
	if provider.ID != "prov-older" {
		t.Errorf("served %q, want the oldest row %q -- resolution must not depend on row order", provider.ID, "prov-older")
	}
	if others != 1 {
		t.Errorf("others = %d, want 1; the collision would go unreported", others)
	}
}
