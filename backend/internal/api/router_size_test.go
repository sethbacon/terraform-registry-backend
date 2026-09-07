package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// GUARD router-phases-do-not-regrow (issue #565 finding [39]).
//
// NewRouter was ~1240 lines mixing dependency construction, key material,
// background-job orchestration, persisted-config reload and ~150 route
// registrations. Route registration moved to router_routes.go, the reloads to
// router_startup.go, and the key material and rate limiters to
// router_wiring.go. What stops it growing back is this ceiling: nothing else
// can see the rule, because .golangci.yml enables neither funlen nor gocyclo
// nor cyclop, and enabling one repo-wide would flag eight unrelated functions
// and turn into a list of exclusions.
//
// THE CEILING MAY ONLY BE LOWERED. Raising it to make a change fit is the
// change this guard exists to refuse: extract the new phase instead, next to
// the ones already in router_wiring.go. Lower it whenever a phase comes out,
// so the ratchet keeps what the extraction won.
const newRouterLineCeiling = 801

// registerAPIV1Routes is longer still and is deliberately NOT ratcheted here.
// It is a flat list of route registrations -- the length is the route count,
// not tangled control flow -- and #565's finding is about NewRouter mixing
// concerns, which a list of routes does not do.

func TestNewRouterStaysWithinItsCeiling(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}

	var lines int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewRouter" || fn.Recv != nil {
			continue
		}
		lines = fset.Position(fn.End()).Line - fset.Position(fn.Pos()).Line + 1
	}
	if lines == 0 {
		t.Fatal("NewRouter not found in router.go: this guard is measuring nothing")
	}
	if lines > newRouterLineCeiling {
		t.Fatalf("NewRouter is %d lines, ceiling is %d. Extract the new work into a phase "+
			"in router_wiring.go rather than raising the ceiling -- growing back is what "+
			"this guard refuses (#565).", lines, newRouterLineCeiling)
	}
	if lines < newRouterLineCeiling {
		t.Fatalf("NewRouter is %d lines, below the %d ceiling. Lower the ceiling to %d so "+
			"the ratchet keeps what the extraction won.", lines, newRouterLineCeiling, lines)
	}
}
