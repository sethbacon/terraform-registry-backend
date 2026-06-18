package services

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// fakeMinter records whether it was invoked and returns a canned token.
type fakeMinter struct {
	token  *scm.OAuthToken
	err    error
	called bool
}

func (f *fakeMinter) MintProviderToken(_ context.Context, _ *scm.SCMProvider) (*scm.OAuthToken, error) {
	f.called = true
	return f.token, f.err
}

// scmProviderCols matches SELECT * FROM scm_providers including the app-auth columns.
var scmProviderCols = []string{
	"id", "organization_id", "provider_type", "name", "base_url", "tenant_id",
	"client_id", "client_secret_encrypted", "webhook_secret",
	"auth_mode", "github_app_id", "github_installation_id", "encrypted_app_private_key",
	"is_active", "created_at", "updated_at",
}

func newSCMRepoMock(t *testing.T) (*repositories.SCMRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func providerRow(id uuid.UUID, authMode string) *sqlmock.Rows {
	return sqlmock.NewRows(scmProviderCols).AddRow(
		id, uuid.New(), "azuredevops", "ado", nil, "tenant",
		"client", "enc-secret", "wh",
		authMode, nil, nil, nil,
		true, time.Now(), time.Now(),
	)
}

func TestResolveSourceToken_AppModeUsesSharedMinter(t *testing.T) {
	repo, mock := newSCMRepoMock(t)
	id := uuid.New()
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").
		WillReturnRows(providerRow(id, scm.AuthModeEntraApp))

	fake := &fakeMinter{token: &scm.OAuthToken{AccessToken: "shared-token", TokenType: "Bearer"}}
	p := &SCMPublisher{scmRepo: repo, sharedMinter: fake}

	tok := p.resolveSourceToken(context.Background(), nil, id)
	if tok == nil || tok.AccessToken != "shared-token" {
		t.Fatalf("token = %+v, want shared-token", tok)
	}
	if !fake.called {
		t.Error("shared minter should have been invoked for an app-mode provider")
	}
}

func TestResolveSourceToken_OAuthUserSkipsMinter(t *testing.T) {
	repo, mock := newSCMRepoMock(t)
	id := uuid.New()
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").
		WillReturnRows(providerRow(id, scm.AuthModeOAuthUser))

	fake := &fakeMinter{token: &scm.OAuthToken{AccessToken: "should-not-be-used"}}
	p := &SCMPublisher{scmRepo: repo, sharedMinter: fake}

	// No module creator → legacy path resolves to nil (unauthenticated download).
	tok := p.resolveSourceToken(context.Background(), nil, id)
	if tok != nil {
		t.Errorf("token = %+v, want nil for oauth_user without a creator token", tok)
	}
	if fake.called {
		t.Error("shared minter must not be invoked for an oauth_user provider")
	}
}
