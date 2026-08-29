package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// The wrapper half of the group-mapping dual-write
// (terraform-suite-identity#206 phase 2), pinned without a database.
//
// Two contracts, and the second is the whole safety argument for the phase:
//
//  1. Each authoritative write that can change mapping content is FOLLOWED by
//     the corresponding mirror write, carrying the new list.
//  2. A mirror failure is ABSORBED: the authoritative write has committed and
//     reads still come from oidc_config.extra_config, so the caller's request
//     must succeed anyway -- turning the mirror's failure into a 500 on the
//     auth-config paths would make a nothing-observable-changes phase change
//     behaviour. And an authoritative failure must reach the mirror NEVER,
//     or the mirror would hold a list the source refused.

// newGroupMappingWrapper builds the wrapper over two scripted connections --
// identityDB backs the authoritative store, db backs the mirror -- mirroring
// NewRouter's wiring shape.
func newGroupMappingWrapper(t *testing.T) (*OIDCConfigRepository, *mockConn, *mockConn) {
	t.Helper()
	registry, identity := newMockConn(t), newMockConn(t)
	repo := NewOIDCConfigRepositoryWithIdentity(
		sqlx.NewDb(registry.db, "sqlmock"), sqlx.NewDb(identity.db, "sqlmock"))
	return repo, registry, identity
}

func gmWrapperConfig(t *testing.T) *models.OIDCConfig {
	t.Helper()
	now := time.Now()
	return &models.OIDCConfig{
		ID:                     mustUUID(t, gmCfgA),
		Name:                   "default",
		ProviderType:           "generic_oidc",
		IssuerURL:              "https://idp",
		ClientID:               "c",
		ClientSecretCiphertext: "s",
		RedirectURL:            "https://cb",
		Scopes:                 json.RawMessage(`["openid"]`),
		ExtraConfig:            json.RawMessage(gmExtraOneMapping),
		CreatedAt:              now,
		UpdatedAt:              now,
	}
}

// expectGroupMappingReplaced queues the mirror's whole replace transaction on
// the REGISTRY connection, asserting the list decoded from extra_config is
// what arrives.
func expectGroupMappingReplaced(t *testing.T, registry *mockConn) {
	t.Helper()
	registry.mock.ExpectBegin()
	registry.mock.ExpectExec("DELETE FROM group_mappings WHERE oidc_config_id").
		WithArgs(mustUUID(t, gmCfgA)).WillReturnResult(sqlmock.NewResult(0, 0))
	registry.mock.ExpectExec("INSERT INTO group_mappings").
		WithArgs(mustUUID(t, gmCfgA), 0, "eng", "alpha", "publisher").
		WillReturnResult(sqlmock.NewResult(0, 1))
	registry.mock.ExpectCommit()
}

func TestOIDCConfigWrapper_CreateMirrorsTheCarriedMappings(t *testing.T) {
	repo, registry, identity := newGroupMappingWrapper(t)
	identity.mock.ExpectExec("INSERT INTO oidc_config").WillReturnResult(sqlmock.NewResult(0, 1))
	expectGroupMappingReplaced(t, registry)

	if err := repo.CreateOIDCConfig(context.Background(), gmWrapperConfig(t)); err != nil {
		t.Fatalf("CreateOIDCConfig: %v", err)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCConfigWrapper_UpdateExtraConfigMirrorsTheNewList(t *testing.T) {
	repo, registry, identity := newGroupMappingWrapper(t)
	identity.mock.ExpectExec("UPDATE oidc_config SET extra_config").WillReturnResult(sqlmock.NewResult(0, 1))
	expectGroupMappingReplaced(t, registry)

	err := repo.UpdateOIDCConfigExtraConfig(context.Background(), mustUUID(t, gmCfgA),
		[]byte(gmExtraOneMapping))
	if err != nil {
		t.Fatalf("UpdateOIDCConfigExtraConfig: %v", err)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCConfigWrapper_DeleteClearsTheMirror(t *testing.T) {
	repo, registry, identity := newGroupMappingWrapper(t)
	identity.mock.ExpectExec("DELETE FROM oidc_config").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.mock.ExpectExec("DELETE FROM group_mappings WHERE oidc_config_id").
		WithArgs(mustUUID(t, gmCfgA)).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.DeleteOIDCConfig(context.Background(), mustUUID(t, gmCfgA)); err != nil {
		t.Fatalf("DeleteOIDCConfig: %v", err)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestOIDCConfigWrapper_MirrorFailureDoesNotFailTheRequest is contract 2's
// first half, per write shape.
func TestOIDCConfigWrapper_MirrorFailureDoesNotFailTheRequest(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		repo, registry, identity := newGroupMappingWrapper(t)
		identity.mock.ExpectExec("INSERT INTO oidc_config").WillReturnResult(sqlmock.NewResult(0, 1))
		registry.mock.ExpectBegin().WillReturnError(errors.New("mirror down"))
		if err := repo.CreateOIDCConfig(context.Background(), gmWrapperConfig(t)); err != nil {
			t.Fatalf("a mirror failure surfaced to the caller: %v", err)
		}
	})
	t.Run("update", func(t *testing.T) {
		repo, registry, identity := newGroupMappingWrapper(t)
		identity.mock.ExpectExec("UPDATE oidc_config SET extra_config").WillReturnResult(sqlmock.NewResult(0, 1))
		registry.mock.ExpectBegin().WillReturnError(errors.New("mirror down"))
		err := repo.UpdateOIDCConfigExtraConfig(context.Background(), mustUUID(t, gmCfgA), []byte(gmExtraOneMapping))
		if err != nil {
			t.Fatalf("a mirror failure surfaced to the caller: %v", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		repo, registry, identity := newGroupMappingWrapper(t)
		identity.mock.ExpectExec("DELETE FROM oidc_config").WillReturnResult(sqlmock.NewResult(0, 1))
		registry.mock.ExpectExec("DELETE FROM group_mappings").WillReturnError(errors.New("mirror down"))
		if err := repo.DeleteOIDCConfig(context.Background(), mustUUID(t, gmCfgA)); err != nil {
			t.Fatalf("a mirror failure surfaced to the caller: %v", err)
		}
	})
}

// TestOIDCConfigWrapper_AuthoritativeFailureNeverReachesTheMirror is contract
// 2's second half: sqlmock fails on any statement it was not told to expect,
// and the registry mocks below expect NONE.
func TestOIDCConfigWrapper_AuthoritativeFailureNeverReachesTheMirror(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		repo, registry, identity := newGroupMappingWrapper(t)
		identity.mock.ExpectExec("INSERT INTO oidc_config").WillReturnError(errors.New("refused"))
		if err := repo.CreateOIDCConfig(context.Background(), gmWrapperConfig(t)); err == nil {
			t.Fatal("want the authoritative error")
		}
		if err := registry.mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("update", func(t *testing.T) {
		repo, registry, identity := newGroupMappingWrapper(t)
		identity.mock.ExpectExec("UPDATE oidc_config SET extra_config").WillReturnError(errors.New("refused"))
		err := repo.UpdateOIDCConfigExtraConfig(context.Background(), mustUUID(t, gmCfgA), []byte(gmExtraOneMapping))
		if err == nil {
			t.Fatal("want the authoritative error")
		}
		if err := registry.mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		repo, registry, identity := newGroupMappingWrapper(t)
		identity.mock.ExpectExec("DELETE FROM oidc_config").WillReturnError(errors.New("refused"))
		if err := repo.DeleteOIDCConfig(context.Background(), mustUUID(t, gmCfgA)); err == nil {
			t.Fatal("want the authoritative error")
		}
		if err := registry.mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}
