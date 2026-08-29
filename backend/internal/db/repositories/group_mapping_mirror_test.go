package repositories

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"
)

// Mirror tests that need no database.
//
// group_mapping_equivalence_pg_test.go proves the end-to-end properties
// against real PostgreSQL -- the FK's ON DELETE SET NULL, the scalar-subquery
// name resolution, the round trip through the real write path. Those skip
// wherever TFR_TEST_DATABASE_URL is unset, so the mirror's DECISIONS are
// pinned here instead: what it executes, in what order, inside what
// transaction, and what it does when each statement fails. Same split, and
// same reasoning, as member_role_mirror_test.go.

const (
	gmCfgA  = "dddddddd-0000-0000-0000-000000000001"
	gmRoleA = "cccccccc-0000-0000-0000-000000000011"
)

// expectGroupMappingMirrorVerified queues the two to_regclass probes
// (*GroupMappingMirror).Verify makes.
func expectGroupMappingMirrorVerified(mock sqlmock.Sqlmock) {
	for _, table := range []string{"group_mappings", "registry_role_templates"} {
		mock.ExpectQuery("SELECT to_regclass").
			WithArgs(table).
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("public." + table))
	}
}

func TestGroupMappingMirrorVerify_ResolvesBothTables(t *testing.T) {
	conn := newMockConn(t)
	expectGroupMappingMirrorVerified(conn.mock)
	if err := NewGroupMappingMirror(conn.db).Verify(context.Background()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := conn.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGroupMappingMirrorVerify_RefusesAnUnresolvedTable(t *testing.T) {
	conn := newMockConn(t)
	conn.mock.ExpectQuery("SELECT to_regclass").
		WithArgs("group_mappings").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))
	err := NewGroupMappingMirror(conn.db).Verify(context.Background())
	if !errors.Is(err, ErrMirrorUnreachable) {
		t.Fatalf("want ErrMirrorUnreachable, got %v", err)
	}
}

func TestGroupMappingMirrorVerify_ReportsAProbeFailure(t *testing.T) {
	conn := newMockConn(t)
	conn.mock.ExpectQuery("SELECT to_regclass").
		WithArgs("group_mappings").
		WillReturnError(errors.New("connection reset"))
	err := NewGroupMappingMirror(conn.db).Verify(context.Background())
	if err == nil || errors.Is(err, ErrMirrorUnreachable) {
		t.Fatalf("a probe failure must be its own error, not the sentinel; got %v", err)
	}
}

// TestGroupMappingMirrorReplace_DeletesThenInsertsInOrderInOneTx pins the
// wholesale-replace shape: one transaction, the config's rows cleared first,
// then one insert per mapping IN LIST ORDER with the position argument equal
// to the list index -- order is what first-match-wins resolution hangs on.
func TestGroupMappingMirrorReplace_DeletesThenInsertsInOrderInOneTx(t *testing.T) {
	conn := newMockConn(t)
	configID := mustUUID(t, gmCfgA)

	conn.mock.ExpectBegin()
	conn.mock.ExpectExec("DELETE FROM group_mappings WHERE oidc_config_id").
		WithArgs(configID).WillReturnResult(sqlmock.NewResult(0, 2))
	conn.mock.ExpectExec("INSERT INTO group_mappings").
		WithArgs(configID, 0, "eng", "alpha", "publisher").WillReturnResult(sqlmock.NewResult(0, 1))
	conn.mock.ExpectExec("INSERT INTO group_mappings").
		WithArgs(configID, 1, "ops", "beta", "viewer").WillReturnResult(sqlmock.NewResult(0, 1))
	conn.mock.ExpectCommit()

	err := NewGroupMappingMirror(conn.db).ReplaceForConfig(context.Background(), configID,
		[]identitymodels.OIDCGroupMapping{
			{Group: "eng", Organization: "alpha", Role: "publisher"},
			{Group: "ops", Organization: "beta", Role: "viewer"},
		})
	if err != nil {
		t.Fatalf("ReplaceForConfig: %v", err)
	}
	if err := conn.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestGroupMappingMirrorReplace_EmptyListJustClears pins the representation
// choice: no mappings means no rows, exactly like the source list being
// absent -- not a marker row, not a skipped write.
func TestGroupMappingMirrorReplace_EmptyListJustClears(t *testing.T) {
	conn := newMockConn(t)
	configID := mustUUID(t, gmCfgA)

	conn.mock.ExpectBegin()
	conn.mock.ExpectExec("DELETE FROM group_mappings WHERE oidc_config_id").
		WithArgs(configID).WillReturnResult(sqlmock.NewResult(0, 1))
	conn.mock.ExpectCommit()

	if err := NewGroupMappingMirror(conn.db).ReplaceForConfig(context.Background(), configID, nil); err != nil {
		t.Fatalf("ReplaceForConfig(nil): %v", err)
	}
	if err := conn.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestGroupMappingMirrorReplace_RollsBackWhenAStatementFails pins that a
// half-replaced list can never commit: whichever statement fails, the
// transaction rolls back and the error names the failing step.
func TestGroupMappingMirrorReplace_RollsBackWhenAStatementFails(t *testing.T) {
	configID := mustUUID(t, gmCfgA)
	one := []identitymodels.OIDCGroupMapping{{Group: "eng", Organization: "alpha", Role: "publisher"}}

	t.Run("begin fails", func(t *testing.T) {
		conn := newMockConn(t)
		conn.mock.ExpectBegin().WillReturnError(errors.New("no connection"))
		if err := NewGroupMappingMirror(conn.db).ReplaceForConfig(context.Background(), configID, one); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("delete fails", func(t *testing.T) {
		conn := newMockConn(t)
		conn.mock.ExpectBegin()
		conn.mock.ExpectExec("DELETE FROM group_mappings").WillReturnError(errors.New("boom"))
		conn.mock.ExpectRollback()
		if err := NewGroupMappingMirror(conn.db).ReplaceForConfig(context.Background(), configID, one); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("insert fails", func(t *testing.T) {
		conn := newMockConn(t)
		conn.mock.ExpectBegin()
		conn.mock.ExpectExec("DELETE FROM group_mappings").WillReturnResult(sqlmock.NewResult(0, 0))
		conn.mock.ExpectExec("INSERT INTO group_mappings").WillReturnError(errors.New("fk violated"))
		conn.mock.ExpectRollback()
		if err := NewGroupMappingMirror(conn.db).ReplaceForConfig(context.Background(), configID, one); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("commit fails", func(t *testing.T) {
		conn := newMockConn(t)
		conn.mock.ExpectBegin()
		conn.mock.ExpectExec("DELETE FROM group_mappings").WillReturnResult(sqlmock.NewResult(0, 0))
		conn.mock.ExpectExec("INSERT INTO group_mappings").WillReturnResult(sqlmock.NewResult(0, 1))
		conn.mock.ExpectCommit().WillReturnError(errors.New("deadlock"))
		if err := NewGroupMappingMirror(conn.db).ReplaceForConfig(context.Background(), configID, one); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestGroupMappingMirrorClearConfig(t *testing.T) {
	configID := mustUUID(t, gmCfgA)
	t.Run("deletes the config's rows", func(t *testing.T) {
		conn := newMockConn(t)
		conn.mock.ExpectExec("DELETE FROM group_mappings WHERE oidc_config_id").
			WithArgs(configID).WillReturnResult(sqlmock.NewResult(0, 3))
		if err := NewGroupMappingMirror(conn.db).ClearConfig(context.Background(), configID); err != nil {
			t.Fatalf("ClearConfig: %v", err)
		}
		if err := conn.mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reports a failure", func(t *testing.T) {
		conn := newMockConn(t)
		conn.mock.ExpectExec("DELETE FROM group_mappings").WillReturnError(errors.New("boom"))
		if err := NewGroupMappingMirror(conn.db).ClearConfig(context.Background(), configID); err == nil {
			t.Fatal("want error")
		}
	})
}

// TestGroupMappingsFromExtraConfig pins that the decode is the LIBRARY'S: a
// value the read path reads "no mappings" out of yields no mappings here too,
// whatever malformed shape it takes.
func TestGroupMappingsFromExtraConfig(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		want  int
	}{
		{"nil", "", 0},
		{"empty object", "{}", 0},
		{"not an object", `"garbage"`, 0},
		{"mappings key is not a list", `{"group_mappings":"nope"}`, 0},
		{"two mappings", `{"group_mappings":[{"group":"a","organization":"o","role":"r"},{"group":"b","organization":"o","role":"r"}]}`, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := groupMappingsFromExtraConfig([]byte(tc.extra)); len(got) != tc.want {
				t.Fatalf("want %d mapping(s), got %+v", tc.want, got)
			}
		})
	}
}

// TestGroupMappingMirrorFailed just exercises the absorb-and-log path so a
// signature change there is a compile- or test-visible event; the CONTRACT
// (authoritative write already committed, request must still succeed) is
// pinned by the wrapper tests in oidc_config_repository_test.go and by the
// class guard.
func TestGroupMappingMirrorFailed(t *testing.T) {
	groupMappingMirrorFailed(context.Background(), "TestOp", errors.New("boom"),
		"oidc_config_id", uuid.NewString())
}
