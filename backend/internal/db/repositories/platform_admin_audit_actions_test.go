package repositories

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Issue #766 — the audit vocabulary is enforced by a database trigger, so a
// wrong string is not a wrong log line, it is a failed COMMIT.
//
// Migration 000052's platform_admins_require_audit_intent() matches on the
// EXACT action name, so that a revocation cannot be committed under a grant's
// record. Three packages now build carrier audit intents by hand — the setup
// wizard's bootstrap grant, and the two lifecycle cleanups that retire a
// destroyed principal's grant (issue #766) — and none of their unit tests can
// see the trigger: sqlmock accepts any string.
//
// So the failure mode these constants exist to prevent is a rename here (or in
// the migration) that nothing notices until a real deployment refuses to
// bootstrap. This pins the two against each other, in both directions.

func migrationSQL(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "migrations", name)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(src)
}

// TestCarrierAuditVocabularyMatchesTheTrigger asserts every constant is a
// string the trigger actually looks for.
func TestCarrierAuditVocabularyMatchesTheTrigger(t *testing.T) {
	sql := migrationSQL(t, "000052_audit_outbox.up.sql")

	// The literals must appear inside the assert calls, not merely somewhere in
	// the file's prose — a name mentioned only in a comment would pass a bare
	// substring check while the trigger looked for something else.
	for _, tc := range []struct {
		name  string
		value string
		call  string
	}{
		{"granted", AuditActionPlatformAdminGranted,
			"audit_outbox_assert_intent(NEW.user_id, 'platform_admin', 'platform_admin.granted')"},
		{"revoked", AuditActionPlatformAdminRevoked,
			"audit_outbox_assert_intent(OLD.user_id, 'platform_admin', 'platform_admin.revoked')"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.call, "'"+tc.value+"'") {
				t.Fatalf("constant %q does not appear in the expected trigger call %q — the "+
					"constant and this test have drifted apart", tc.value, tc.call)
			}
			if !strings.Contains(sql, tc.call) {
				t.Fatalf("migration 000052 no longer contains %s.\n"+
					"    The trigger matches on the exact action name, so a rename on either side "+
					"makes every carrier mutation fail at COMMIT in a real deployment while every "+
					"sqlmock test stays green (issue #766). Update both, or update this test.", tc.call)
			}
		})
	}

	if !strings.Contains(sql, "'"+AuditResourcePlatformAdmin+"'") {
		t.Fatalf("migration 000052 does not mention resource_type %q; the trigger matches on it",
			AuditResourcePlatformAdmin)
	}
}

// TestCarrierAuditVocabularyIsUsedRatherThanRetyped is the other direction: no
// non-test source outside this file may spell the action strings as literals.
//
// Without it the constants are advice. A call site that retyped
// "platform_admin.revoked" would work until somebody renamed one of them, and
// then fail only at COMMIT, only in a deployment, only on the path that carries
// the retyped copy.
func TestCarrierAuditVocabularyIsUsedRatherThanRetyped(t *testing.T) {
	root := repoBackendRoot(t)

	literals := map[string]string{
		AuditActionPlatformAdminGranted: "repositories.AuditActionPlatformAdminGranted",
		AuditActionPlatformAdminRevoked: "repositories.AuditActionPlatformAdminRevoked",
	}

	// This file defines them; the migration and its documentation quote them.
	allowed := map[string]bool{
		"internal/db/repositories/platform_admin_audit_actions.go": true,
	}

	var offenders []string
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if allowed[rel] {
			return nil
		}
		// PARSED, not grepped. The first run of this check flagged
		// internal/audit/outbox.go for the doc comment that names
		// "platform_admin.granted" as the example action — prose, not a second
		// spelling. A guard whose first finding is somebody's documentation
		// teaches its readers to add exemptions instead of reading them, which
		// is the failure this estate has hit before.
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if constant, retyped := literals[text]; retyped {
				offenders = append(offenders,
					fset.Position(lit.Pos()).String()+" retypes "+lit.Value+"; use "+constant)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, o := range offenders {
		t.Errorf("%s.\n    Migration 000052's trigger matches the action exactly, so a second "+
			"spelling survives until somebody renames one of them and a deployment refuses to "+
			"commit a carrier mutation (issue #766).", o)
	}
}

// repoBackendRoot walks up to the directory holding go.mod.
func repoBackendRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test's working directory")
		}
		dir = parent
	}
}
