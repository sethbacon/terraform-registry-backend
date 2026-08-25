package credlifecycle_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every production Sweeper must reach an audit sink (#961).
//
// WHY THIS IS A CLASS TEST AND NOT A UNIT TEST. The audit repository is an
// OPTIONAL dependency: with it nil the Sweeper still deletes and simply writes
// no audit row. That is deliberate -- it keeps every existing construction and
// its tests valid -- but it means a construction that was never given the sink
// behaves EXACTLY like one that was, right up until somebody needs the trail
// and finds it empty. There is no runtime signal, no error, and no failing
// unit test. The only way to notice is to ask, structurally, whether every
// construction was wired.
//
// There are three of them and they are easy to miss because two are built
// inside handler constructors rather than at the composition root:
//
//	internal/api/router.go              credSweeper, wired directly
//	internal/api/admin/organizations.go inside NewOrganizationHandlers
//	internal/api/admin/rbac.go          inside NewRBACHandlers
//
// The last is the highest-volume destruction path in the codebase.
//
// The test asks a QUESTION rather than matching a known list: "does the file
// that constructs a Sweeper also attach an audit sink?" A new construction in a
// new file fails this until it is wired, which is the point -- a hardcoded list
// of three files would pass forever while a fourth went unaudited.
func TestEveryProductionSweeperReachesAnAuditSink(t *testing.T) {
	root := repoRoot(t)

	// A file may attach the sink itself (WithAuditLog) or expose a chainable
	// that the composition root calls (WithCredentialAudit). Both count: what
	// matters is that the constructed Sweeper can receive one.
	const (
		construct = "NewSweeper"
		attachA   = "WithAuditLog"
		attachB   = "WithCredentialAudit"
	)

	constructors := map[string]bool{}
	attachers := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// vendor and testdata are not our wiring.
			if name := info.Name(); name == "vendor" || name == "testdata" || name == "docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // unparseable non-test file is a build problem, not this test's
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				switch fn.Sel.Name {
				case construct:
					constructors[rel] = true
				case attachA, attachB:
					attachers[rel] = true
				}
			case *ast.Ident:
				switch fn.Name {
				case construct:
					constructors[rel] = true
				case attachA, attachB:
					attachers[rel] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Positive control. If the sweep is ever renamed or moved and this test
	// stops finding ANY construction, an empty universe would pass silently --
	// the failure mode this whole file exists to prevent.
	if len(constructors) == 0 {
		t.Fatal("found no NewSweeper construction anywhere: this test has gone blind, fix its search before trusting a green run")
	}
	if len(attachers) == 0 {
		t.Fatal("found no audit-sink attachment anywhere: this test has gone blind")
	}

	var unwired []string
	for file := range constructors {
		if !attachers[file] {
			unwired = append(unwired, file)
		}
	}
	if len(unwired) > 0 {
		t.Errorf("these files construct a credential Sweeper but never attach an audit sink, so the keys they destroy leave no record:\n  %s\n\nAttach it with .WithAuditLog(auditRepo), or expose a WithCredentialAudit chainable and call it from the composition root.",
			strings.Join(unwired, "\n  "))
	}
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "internal")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate module root (no go.mod found walking up)")
	return ""
}
