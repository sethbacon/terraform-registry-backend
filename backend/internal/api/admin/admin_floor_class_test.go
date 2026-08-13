package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Issue #766 — the two never-zero administrator invariants have to hold on
// EVERY write path, not on the one that was reported.
//
//	A. the deployment always has at least one platform administrator
//	B. every organization with members has at least one member who can
//	   administer it
//
// PR #862 guarded the explicit revoke. That is one of ten paths that reduce
// administrative authority, and the other nine are the ones nobody looks at:
// a member removal, a role downgrade, a `role_template_id: null`, a user
// delete, a GDPR erasure, four SCIM deprovision entry points, both reducing
// branches of the IdP login reconciliation, and an organization delete whose
// membership rows go by FK cascade with no membership statement anywhere.
//
// The defect this file exists to catch is an ABSENT CALL, so no behavioural
// test of any one handler generalises to the next one somebody adds. This
// walks the module and requires the guard at every site, in the same shape as
// platform_admin_grant_class_test.go — including its bidirectional exemption
// map, so an exemption for code that no longer exists fails too.

// adminFloorGuardNames are the accepted ways a write can have proven that an
// administrator remains.
//
// Protect only. Guard.Serialize takes the same lock but evaluates NOTHING, so
// accepting it here would let a site claim the guard by taking a lock and
// checking nothing at all. Its one legitimate caller is named in
// adminFloorExemptions with the check it uses instead.
var adminFloorGuardNames = map[string]bool{
	"Protect": true,
	// idpReduce is auth.go's wrapper around Protect: it runs the same guarded
	// write and then decides what a REFUSAL means on a login path (skip the
	// reduction, keep the login). Accepted for the same reason PR #850 accepts
	// resolveProvisionableRole alongside guardProvisionableRole -- the wrapper
	// is the call site's spelling of the guard, not a way around it.
	"idpReduce": true,
}

// reducingCall reports what an authority-reducing call takes away, or "" when
// the call is not one.
//
// RECEIVER-QUALIFIED, deliberately. Matching on the method name alone produced
// two false positives immediately: registerSCIMRoutes' `scimHandlers.DeleteUser()`
// is a route registration, and `Delete` is the most generic method name in the
// module -- mirrors, providers and a dozen other repositories have one. The
// receiver is what distinguishes the identity store's membership methods from
// everything else that happens to share a verb.
//
// The vocabulary is pinned against the source by
// TestAdminFloorClass_EveryReducerNameStillMatches, so a receiver-naming change
// that quietly stopped one of these from matching fails rather than passing
// with a smaller universe.
func reducingCall(call *ast.CallExpr) string {
	recv := strings.ToLower(callReceiver(call))
	switch callName(call) {
	case "RemoveMember":
		if strings.HasSuffix(recv, "orgrepo") {
			return "removes one membership, with the role it carried"
		}
	case "RemoveAllMembershipsForUser":
		if strings.HasSuffix(recv, "orgrepo") {
			return "removes every membership the principal holds in scope"
		}
	case "UpdateMemberRole", "UpdateMemberRoleTemplate":
		if strings.HasSuffix(recv, "orgrepo") {
			return "re-roles a member, which is a downgrade whenever the new role carries less -- " +
				"and a role template of nil clears it outright"
		}
	case "DeleteUser":
		if strings.HasSuffix(recv, "userrepo") {
			return "destroys the principal; its memberships follow by FK cascade"
		}
	case "Delete":
		if strings.HasSuffix(recv, "orgrepo") {
			return "deletes an organization, cascading away every membership in it"
		}
	case "Revoke":
		if strings.HasSuffix(recv, "carrier") {
			return "removes a platform_admins row"
		}
	}
	return ""
}

// reducerVocabulary is the same list as a set, for the pinning test below.
var reducerVocabulary = []string{
	"RemoveMember", "RemoveAllMembershipsForUser", "UpdateMemberRole",
	"UpdateMemberRoleTemplate", "DeleteUser", "Delete", "Revoke",
}

// adminFloorExemptions are authority-reducing writes that deliberately run
// without adminfloor.Protect, keyed by "<path>:<function>". A map rather than
// a prefix rule for the same reason as PR #850's: a new unguarded reduction
// cannot join the exemption by living in a plausible-looking file, somebody
// has to name it here and say why.
//
// Checked in BOTH directions — an entry naming a site that no longer reduces
// anything fails the test too, so the list cannot rot into names nobody has
// re-examined.
var adminFloorExemptions = map[string]string{
	"internal/api/admin/platform_admins.go:RevokePlatformAdmin": "Has its own last-standing check, and a STRICTER one: " +
		"requireAnotherExercisableAdmin runs inside a transaction holding SELECT ... FOR UPDATE over " +
		"platform_admins (PR #862) and refuses to drop the last CARRIER row even when role-template " +
		"administrators remain, which the floor would accept. Delegating to Protect would relax it. It " +
		"takes Guard.Serialize so it is still ordered against the membership paths, whose writes land on " +
		"the other connection where its row lock reaches nothing.",

	"internal/api/admin/users.go:revokePlatformAdminCarrier": "Cleanup AFTER a delete the floor has already " +
		"cleared, removing the carrier row of a principal that no longer exists. Re-checking here would " +
		"refuse to tidy up the very grant the floor just discounted as inert.",

	"internal/services/user_service.go:revokePlatformAdminCarrier": "The same cleanup after a GDPR erasure, " +
		"and for the same reason.",

	"internal/api/setup/handlers.go:ConfigureAdmin": "Setup-wizard bootstrap. Its UpdateMemberRole is the " +
		"fallback half of a PROMOTION to the admin template -- it raises the first operator's authority, " +
		"it cannot lower anybody's, and it runs before any principal exists whose floor could be " +
		"evaluated. This is the grant that makes every later refusal able to be satisfied by somebody.",
}

// rawReductionExemptions are the hand-written statements, kept apart from the
// map above because the two tests scan DIFFERENT universes: an entry that
// applies to one is stale in the other, and a shared map would report every
// entry as stale in whichever test did not find it.
var rawReductionExemptions = map[string]string{
	"internal/db/repositories/platform_admin_repository.go:Revoke": "The repository primitive behind " +
		"RevokePlatformAdmin, not a call site of its own. It takes the caller's last-standing predicate as " +
		"a parameter and refuses when the predicate does, so the check lives with the caller that has the " +
		"identity connection to resolve grants against.",
}

// rawReductionGuardedByCaller are hand-written reductions whose guard is ONE
// FRAME UP, mapped to the function that must be holding it.
//
// Kept apart from rawReductionExemptions, and checked rather than trusted. An
// exemption reading "EraseUser hands this whole function to the floor" is a
// claim about code the test never looks at: deleting EraseUser's Protect left
// every GDPR erasure unguarded and both class tests green, because the raw SQL
// was exempt and the enclosing function contains no repository call for the AST
// walk to notice.
var rawReductionGuardedByCaller = map[string]string{
	"internal/services/user_service.go:eraseTx": "EraseUser",
}

// reducingSite is one authority-reducing call with the function containing it.
type reducingSite struct {
	path string
	fn   string
	what string
	pos  token.Position
}

// callReceiver renders the receiver of a method call as source text, for the
// receiver-qualified matches above. Only the shapes that actually occur are
// handled (`ident.Sel`); anything else returns "" and simply does not match,
// which is the safe direction for a matcher used to WIDEN the universe.
func callReceiver(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	switch x := sel.X.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if inner, ok := x.X.(*ast.Ident); ok {
			return inner.Name + "." + x.Sel.Name
		}
	}
	return ""
}

// walkModuleSources visits every non-test .go file under root.
func walkModuleSources(t *testing.T, root string, visit func(rel string, fset *token.FileSet, file *ast.File, src []byte)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, src, parser.ParseComments)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			t.Fatalf("rel %s: %v", path, relErr)
		}
		visit(filepath.ToSlash(rel), fset, file, src)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// findAuthorityReductions returns every authority-reducing call in the module
// with the function containing it, plus the "path:fn" keys whose reduction is
// preceded by an adminfloor guard.
func findAuthorityReductions(t *testing.T, root string) (sites []reducingSite, guarded map[string]bool) {
	t.Helper()
	guarded = map[string]bool{}

	// The floor's own implementation reads these tables and must not be
	// measured against itself; it IS the guard.
	const guardPackage = "internal/adminfloor/"

	walkModuleSources(t, root, func(rel string, fset *token.FileSet, file *ast.File, _ []byte) {
		if strings.HasPrefix(rel, guardPackage) {
			return
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				what := reducingCall(call)
				if what == "" {
					return true
				}
				key := rel + ":" + fn.Name.Name
				sites = append(sites, reducingSite{path: rel, fn: fn.Name.Name, what: what, pos: fset.Position(call.Pos())})
				// Whole-function granularity, matching
				// platform_admin_grant_class_test.go: these handlers guard once
				// around the write, and this check only has to notice a
				// reduction with no guard anywhere near it.
				for _, g := range guardPositionsIn(fn.Body, call.Pos(), adminFloorGuardNames) {
					if g < call.Pos() {
						guarded[key] = true
						break
					}
				}
				return true
			})
		}
	})
	return sites, guarded
}

// TestAdminFloorClass_EveryAuthorityReductionProvesAnAdminRemains is the
// structural half.
func TestAdminFloorClass_EveryAuthorityReductionProvesAnAdminRemains(t *testing.T) {
	root := backendRoot(t)
	sites, guarded := findAuthorityReductions(t, root)

	// An empty universe is the failure this check cannot otherwise see: if the
	// method names drift, the walk matches nothing and reports green while
	// checking nothing. It is the same trap PR #850 named, and the one that let
	// three guards ship inert in this estate.
	if len(sites) == 0 {
		t.Fatal("found no authority-reducing calls under the module — authorityReducingWrites is " +
			"stale, so this guard is vacuous. Re-derive it from the identity store's membership and " +
			"user deletion methods.")
	}

	seen := map[string]bool{}
	for _, s := range sites {
		key := s.path + ":" + s.fn
		if _, exempt := adminFloorExemptions[key]; exempt {
			seen[key] = true
			continue
		}
		if guarded[key] {
			continue
		}
		t.Errorf("%s: %s %s with no adminfloor.Protect ahead of it.\n"+
			"    A write that reduces administrative authority without asking whether one remains can "+
			"leave the deployment with no platform administrator, or an organization with members and "+
			"nobody able to manage them (issue #766). Wrap it in floor.Protect with the adminfloor.Change "+
			"that describes it, or — if it genuinely cannot break either invariant — add it to "+
			"adminFloorExemptions with the reason.",
			s.pos, s.fn, s.what)
	}

	var stale []string
	for key := range adminFloorExemptions {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("adminFloorExemptions names site(s) that no longer reduce authority: %s.\n"+
			"    Remove the entry — an exemption for code that does not exist hides the day something "+
			"new moves into that function name.", strings.Join(stale, ", "))
	}

	t.Logf("checked %d authority-reducing call site(s) across the module", len(sites))
}

// rawAuthorityReductionRe matches a hand-written statement that removes
// administrative authority without going through a repository method.
//
// This is the way around the AST check above, and it is not hypothetical: the
// GDPR erasure really does run `DELETE FROM organization_members WHERE user_id
// = $1` with no organization predicate at all, stripping the subject's role in
// every organization on the platform. Nothing in authorityReducingWrites
// matches it.
//
// Deliberately WIDER than platform_admin_grant_class_test.go's
// rawMembershipWriteRe, which excludes DELETE on purpose because it reasons
// about grants. A decrease is exactly what this file reasons about.
var rawAuthorityReductionRe = regexp.MustCompile(`(?i)(` +
	`DELETE\s+FROM\s+organization_members|` +
	`UPDATE\s+organization_members\s+SET|` +
	`DELETE\s+FROM\s+platform_admins|` +
	`DELETE\s+FROM\s+organizations\b|` +
	`DELETE\s+FROM\s+users\b)`)

// commentRanges collects the source-offset spans of every comment in a file.
func commentRanges(fset *token.FileSet, file *ast.File) [][2]int {
	out := make([][2]int, 0, len(file.Comments))
	for _, group := range file.Comments {
		out = append(out, [2]int{fset.Position(group.Pos()).Offset, fset.Position(group.End()).Offset})
	}
	return out
}

func inComment(ranges [][2]int, offset int) bool {
	for _, r := range ranges {
		if offset >= r[0] && offset < r[1] {
			return true
		}
	}
	return false
}

// TestAdminFloorClass_RawSQLReductionsAreNamed requires every hand-written
// authority reduction to sit in a function the exemption map names, with a
// reason. Bidirectional, like the check above.
func TestAdminFloorClass_RawSQLReductionsAreNamed(t *testing.T) {
	root := backendRoot(t)

	type rawSite struct {
		key  string
		stmt string
		pos  token.Position
	}
	var found []rawSite

	walkModuleSources(t, root, func(rel string, fset *token.FileSet, file *ast.File, src []byte) {
		if strings.HasPrefix(rel, "internal/adminfloor/") {
			return
		}
		comments := commentRanges(fset, file)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			if start < 0 || end > len(src) || start >= end {
				continue
			}
			tokFile := fset.File(fn.Pos())
			for _, loc := range rawAuthorityReductionRe.FindAllIndex(src[start:end], -1) {
				// PROSE IS NOT SQL. The first run of this check flagged
				// DeleteOrganizationHandler twice, for the two comments that
				// explain why `DELETE FROM organizations` cascades memberships
				// away -- comments this very change wrote. A guard whose first
				// two findings are its own documentation trains its readers to
				// add exemptions instead of reading them.
				if inComment(comments, start+loc[0]) {
					continue
				}
				found = append(found, rawSite{
					key:  rel + ":" + fn.Name.Name,
					stmt: strings.Join(strings.Fields(string(src[start+loc[0]:start+loc[1]])), " "),
					pos:  fset.Position(tokFile.Pos(start + loc[0])),
				})
			}
		}
	})

	if len(found) == 0 {
		t.Fatal("found no hand-written authority reductions under the module — the regexp no longer " +
			"matches the estate's SQL, so this guard is vacuous. The GDPR erasure alone should match.")
	}

	seen := map[string]bool{}
	seenDelegated := map[string]bool{}
	for _, s := range found {
		if _, exempt := rawReductionExemptions[s.key]; exempt {
			seen[s.key] = true
			continue
		}
		if caller, delegated := rawReductionGuardedByCaller[s.key]; delegated {
			seenDelegated[s.key] = true
			assertCallerGuards(t, root, s.key, caller)
			continue
		}
		t.Errorf("%s: %q is a hand-written authority reduction in an unnamed function.\n"+
			"    It bypasses every repository method the guard above reasons about, so it can strip the "+
			"last administrator with nothing to notice (issue #766). Route it through the floor, or add "+
			"%s to rawReductionExemptions with the reason.", s.pos, s.stmt, s.key)
	}

	var stale []string
	for key := range rawReductionExemptions {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	for key := range rawReductionGuardedByCaller {
		if !seenDelegated[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("rawReductionExemptions names site(s) with no hand-written reduction any more: %s.\n"+
			"    Remove the entry — an exemption for SQL that no longer exists hides the day something "+
			"new moves into that function name.", strings.Join(stale, ", "))
	}

	t.Logf("checked %d hand-written authority reduction(s) across the module", len(found))
}

// TestAdminFloorClass_EveryFloorInjectorIsWired closes the last way the guard
// can be absent: a handler that HAS a floor field, and calls Protect correctly,
// but is constructed by a router that never passes one.
//
// The floor is nil-tolerant by design — hundreds of existing handler tests
// construct one without it, on the same "wired as a unit" convention as
// credlifecycle.Sweeper — so an unwired handler compiles, passes its own tests
// and enforces nothing. The injector list is DERIVED from the source (every
// function taking a *adminfloor.Guard) rather than written by hand, so a new
// handler with a new injector fails here until the router uses it.
func TestAdminFloorClass_EveryFloorInjectorIsWired(t *testing.T) {
	root := backendRoot(t)

	injectors := map[string][]string{} // name -> declaring files
	walkModuleSources(t, root, func(rel string, fset *token.FileSet, file *ast.File, _ []byte) {
		if strings.HasPrefix(rel, "internal/adminfloor/") {
			return
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Type.Params == nil {
				continue
			}
			for _, param := range fn.Type.Params.List {
				star, ok := param.Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				sel, ok := star.X.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "adminfloor" || sel.Sel.Name != "Guard" {
					continue
				}
				injectors[fn.Name.Name] = append(injectors[fn.Name.Name], rel)
			}
		}
	})

	if len(injectors) == 0 {
		t.Fatal("found no function taking a *adminfloor.Guard — either the guard is wired nowhere, " +
			"or this check no longer recognises how it is passed. Both are failures.")
	}

	// The router files are the deployment's single wiring point.
	var wiring strings.Builder
	for _, name := range []string{"internal/api/router.go", "internal/api/router_routes.go"} {
		src, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		wiring.Write(src)
	}
	routerText := wiring.String()

	var names []string
	for name := range injectors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// COUNTED, not merely present. Five different handler types declare an
		// injector called WithAdminFloor, so a `strings.Contains` check is
		// satisfied by any ONE of them being wired: removing the floor from
		// three of the five handlers left this test green, which is how this
		// weakness was found. One wiring call per declaration is the weakest
		// count that notices.
		declared := len(injectors[name])
		wired := strings.Count(routerText, name+"(")
		if wired < declared {
			sort.Strings(injectors[name])
			t.Errorf("%s is declared %d time(s) (%s) but the router calls it %d time(s).\n"+
				"    A handler with a nil floor compiles, passes its own tests and enforces neither "+
				"invariant (issue #766). Wire every one of them in internal/api/router.go.",
				name, declared, strings.Join(injectors[name], ", "), wired)
		}
	}

	// And the deployment must build exactly one Guard, from BOTH connections.
	if !strings.Contains(routerText, "adminfloor.New(db, identityDB)") {
		t.Error("internal/api/router.go no longer constructs the floor as adminfloor.New(db, identityDB).\n" +
			"    The carrier is on the registry connection and the membership tables are on identity's; " +
			"handing the same handle twice would make the floor read platform_admins from a database " +
			"that may not have it (migration 000051).")
	}

	t.Logf("checked %d floor injector(s)", len(injectors))
}

// TestAdminFloorClass_EveryReducerNameStillMatches pins the vocabulary against
// the source.
//
// The empty-universe check in the main test only fires when the walk matches
// NOTHING. Partial drift is the more likely failure and the invisible one: a
// receiver renamed from orgRepo to organizations would silently drop every
// membership reduction from the universe while DeleteUser kept matching, and
// the guard would report green over a shrunken world.
func TestAdminFloorClass_EveryReducerNameStillMatches(t *testing.T) {
	root := backendRoot(t)

	matched := map[string]int{}
	walkModuleSources(t, root, func(rel string, _ *token.FileSet, file *ast.File, _ []byte) {
		if strings.HasPrefix(rel, "internal/adminfloor/") {
			return
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if reducingCall(call) != "" {
				matched[callName(call)]++
			}
			return true
		})
	})

	for _, name := range reducerVocabulary {
		if matched[name] == 0 {
			t.Errorf("no call to %s matched reducingCall anywhere in the module. Either the method is "+
				"gone -- remove it from the vocabulary -- or its receiver was renamed and this guard is "+
				"now blind to every one of its call sites (issue #766).", name)
		}
	}
	t.Logf("reducer match counts: %v", matched)
}

// assertCallerGuards checks the claim a delegated exemption makes: that
// callerName, in the same file, both calls the reducing function AND wraps it
// in adminfloor.Protect.
//
// Whole-function granularity, like the AST check: the caller guards once around
// the write, and this only has to notice a delegation with no guard in it.
func assertCallerGuards(t *testing.T, root, siteKey, callerName string) {
	t.Helper()
	path := strings.SplitN(siteKey, ":", 2)[0]
	reducerName := strings.SplitN(siteKey, ":", 2)[1]

	src, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != callerName {
			continue
		}
		callsReducer, callsProtect := false, false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch callName(call) {
			case reducerName:
				callsReducer = true
			case "Protect":
				callsProtect = true
			}
			return true
		})
		if !callsReducer {
			t.Errorf("%s no longer calls %s, so the delegated exemption for %s guards nothing. "+
				"Re-point rawReductionGuardedByCaller or guard the reduction where it now lives.",
				callerName, reducerName, siteKey)
		}
		if !callsProtect {
			t.Errorf("%s calls %s but no longer wraps it in adminfloor.Protect. Every hand-written "+
				"reduction in %s is unguarded (issue #766).", callerName, reducerName, siteKey)
		}
		return
	}
	t.Errorf("rawReductionGuardedByCaller says %s is guarded by %s, but no function of that name "+
		"exists in %s.", siteKey, callerName, path)
}

// TestAdminFloorClass_EveryAcceptedWrapperReachesProtect closes the hole that
// an accepted guard NAME opens.
//
// adminFloorGuardNames accepts idpReduce as well as Protect, because idpReduce
// is auth.go's spelling of the guard. Nothing made it stay one: replacing its
// body's `h.floor.Protect(ctx, ch, write)` with a bare `write(ctx)` left every
// IdP reduction unguarded and the class test green, because the call sites
// still called something on the accepted list.
//
// PR #850's ceilingGuardNames has the same shape and the same latent hole for
// resolveProvisionableRole; this check is written over a parameterised list so
// it can be pointed at that one too.
func TestAdminFloorClass_EveryAcceptedWrapperReachesProtect(t *testing.T) {
	root := backendRoot(t)

	// Everything on the accepted list except the real thing.
	wrappers := map[string]bool{}
	for name := range adminFloorGuardNames {
		if name != "Protect" {
			wrappers[name] = true
		}
	}
	if len(wrappers) == 0 {
		t.Skip("no wrapper names are accepted as the guard")
	}

	reaches := map[string]bool{}
	declared := map[string]bool{}
	walkModuleSources(t, root, func(rel string, _ *token.FileSet, file *ast.File, _ []byte) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !wrappers[fn.Name.Name] {
				continue
			}
			declared[fn.Name.Name] = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && callName(call) == "Protect" {
					reaches[fn.Name.Name] = true
				}
				return true
			})
		}
	})

	for name := range wrappers {
		if !declared[name] {
			t.Errorf("adminFloorGuardNames accepts %q but no function of that name exists. An "+
				"accepted name that matches nothing lets a call site claim a guard that is not "+
				"there.", name)
			continue
		}
		if !reaches[name] {
			t.Errorf("%s is accepted as the administrator-floor guard but its body never calls "+
				"Protect.\n    Every call site that reaches the floor through it is unguarded, and "+
				"TestAdminFloorClass_EveryAuthorityReductionProvesAnAdminRemains cannot see it "+
				"(issue #766).", name)
		}
	}
}
