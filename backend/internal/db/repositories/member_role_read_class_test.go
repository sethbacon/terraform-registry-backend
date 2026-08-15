package repositories

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Class guard for the role-read cutover
// (sethbacon/terraform-suite-identity#206, phase 3b).
//
// The property: EVERY accessor that returns a member's role, or what that role
// confers, resolves it from registry's own tables. Not most of them. All.
//
// A partial cutover is worse than none. Two accessors reading two copies give
// the product two answers to one question, and they differ ONLY on the rows
// that are wrong -- which is to say, only where it matters, and never in a way
// a passing test would show. The failure mode is a principal who is allowed
// through one route and denied through another, with no error anywhere.
//
// The defect is an ABSENT OVERRIDE, and an absent override cannot be caught by
// testing the overrides that are present:
//
//  1. The shared store grows a role-bearing reader that this package does not
//     override. Go promotes it, every caller compiles, and it serves identity's
//     answer forever. No diff in this repository at all -- it arrives with a
//     dependency bump.
//  2. An override is added that delegates correctly and never consults
//     registry's tables. It passes every behavioural test, because the shared
//     store's answer is still correct on every row that has not drifted.
//
// There is a test below for each, on BOTH wrapper types, and every one of them
// fails on an empty universe. A guard that inspects zero read paths and reports
// green is how three earlier guards in this repository certified nothing.

// selectorPath renders a call's function expression as a DOTTED PATH --
// "r.roles.RoleFor", "r.GetMemberWithRole", "r.OrganizationRepository.GetMember",
// "compareRole".
//
// The receiver is the whole point, and the first version of this guard did not
// have it. Matching on the bare method NAME cannot tell
// `r.OrganizationRepository.GetMemberWithRole` -- the DELEGATION every override
// starts with -- from `r.GetMemberWithRole`, the sibling call by which a derived
// accessor legitimately reaches the reader. With names alone, an override gutted
// down to nothing but its delegation still "reached a reader call", and both
// guards below certified it. That was verified by mutation, not reasoned about:
// deleting the body of GetMemberWithRole left them green.
//
// This is the same failure this estate has recorded before -- an AST scanner
// that returned an empty receiver for nested selectors and passed.
func selectorPath(expr ast.Expr) string {
	switch f := expr.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		base := selectorPath(f.X)
		if base == "" {
			return f.Sel.Name
		}
		return base + "." + f.Sel.Name
	}
	return ""
}

// calledPaths returns every dotted call path in fn.
func calledPaths(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if p := selectorPath(call.Fun); p != "" {
				out[p] = true
			}
		}
		return true
	})
	return out
}

// siblingCall reports the method name when path is a call on THIS type
// (`r.Foo`), and "" for anything else -- including `r.Embedded.Foo`, which is
// delegation to the shared store and reaches nothing of registry's.
func siblingCall(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) != 2 || parts[0] != "r" {
		return ""
	}
	return parts[1]
}

// overlayHelpers are the two package-local helpers that perform the overlay and
// the comparison on behalf of a caller. They are named rather than derived
// because one is a plain function and one is a method, so neither is reachable
// by the per-type fixpoint below -- and both are themselves verified by
// TestMemberRoleReadClass_TheOverlayHelpersReachBoth.
var overlayHelpers = map[string]bool{
	"overlayMemberships": true,
	"r.overlayUsers":     true,
}

// coveredOverrides returns the overrides that reach `direct` -- either by
// calling one of those functions themselves, or transitively through a SIBLING
// override that does.
//
// The fixpoint is what lets GetUserScopesForOrg, GetUserCombinedScopes and
// OrgScopeForUser be correct implementations rather than exemptions: each is
// nothing but a call to a sibling override plus a reduction, which is exactly
// how they should be written, and the guard follows them there.
func coveredOverrides(overrides map[string]*ast.FuncDecl, direct func(path string) bool) map[string]bool {
	covered := map[string]bool{}
	for name, fn := range overrides {
		for path := range calledPaths(fn) {
			if direct(path) || overlayHelpers[path] {
				covered[name] = true
				break
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for name, fn := range overrides {
			if covered[name] {
				continue
			}
			for path := range calledPaths(fn) {
				if sib := siblingCall(path); sib != "" && covered[sib] {
					covered[name] = true
					changed = true
					break
				}
			}
		}
	}
	return covered
}

// readsRegistryTables reports whether a call path reaches the reader directly.
func readsRegistryTables(path string) bool { return strings.HasPrefix(path, "r.roles.") }

// reportsDivergence reports whether a call path is the comparison itself.
func reportsDivergence(path string) bool { return path == "compareRole" }

// roleReadSQL matches a projection that carries a MEMBERSHIP's role template.
//
// It is anchored on SELECT deliberately, so the membership WRITERS are not
// swept in: `INSERT INTO organization_members (..., role_template_id, ...)` and
// `UPDATE organization_members SET role_template_id = $3` both name the column
// and neither returns it. Those are the write guard's universe
// (member_role_mirror_class_test.go), and a method that appeared in both
// universes would have to satisfy two contradictory requirements.
//
// The bounded gap tolerates the column lists these queries actually have
// without letting a SELECT hundreds of lines earlier match an unrelated
// mention.
var roleReadSQL = regexp.MustCompile(`(?is)SELECT[^;]{0,800}?\brole_template_id\b`)

// storeSQLConstants returns every package-level string constant declared in the
// shared store, so a method that references its query by NAME can be expanded.
//
// Without this the guard would see `GetMemberWithRole` as having no SQL at all:
// the identity module hoisted its membership projections into named constants
// in membership.go, and five of the store's role-bearing reads are now nothing
// but a constant reference plus a scan. A guard that matched only inline
// literals would derive a universe missing exactly the accessors that matter
// most, and report green.
func storeSQLConstants(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, file := range parseDir(t, dir) {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if s, ok := constStringValue(vs.Values[i], out); ok {
						out[name.Name] = s
					}
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("found no string constants in the shared identity store — the module layout " +
			"changed and the SQL expansion below would silently see empty query bodies")
	}
	return out
}

// constStringValue renders a constant's value, following `A + B` concatenation
// and already-known constant references. The membership constants are built
// exactly that way (`"SELECT " + userMembershipColumns + userMembershipFrom`).
func constStringValue(expr ast.Expr, known map[string]string) (string, bool) {
	switch v := expr.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return v.Value, true
		}
		return s, true
	case *ast.Ident:
		s, ok := known[v.Name]
		return s, ok
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, lok := constStringValue(v.X, known)
		r, rok := constStringValue(v.Y, known)
		if !lok && !rok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// parseDir parses every non-test .go file under dir.
func parseDir(t *testing.T, dir string) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		out = append(out, file)
	}
	return out
}

// expandedBody renders a method's SQL: its own string literals, plus the value
// of every package-level string constant it names.
func expandedBody(t *testing.T, fn *ast.FuncDecl, consts map[string]string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(bodyText(t, fn))
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			if s, found := consts[ident.Name]; found {
				sb.WriteString(s)
				sb.WriteString("\n")
			}
		}
		return true
	})
	return sb.String()
}

// storeRoleReaders derives, from the pinned module's own source, every method on
// the named store type that returns a membership's role -- directly in its own
// SQL, or by calling one that does.
//
// The transitive step is not decoration. GetUserCombinedScopes,
// GetUserScopesForOrg and OrgScopeForUser contain no SQL whatsoever: they
// delegate and then reduce. Those three are the token mint, the per-organization
// authorization check, and the tenant predicate -- i.e. the three most
// consequential role reads in the product -- and a guard matching only SQL would
// miss all three.
func storeRoleReaders(t *testing.T, typeName string) map[string]bool {
	t.Helper()
	dir := identityStoreDir(t)
	consts := storeSQLConstants(t, dir)
	methods := methodsOn(t, dir, typeName)
	if len(methods) == 0 {
		t.Fatalf("found no methods on the shared store's %s — the module layout changed "+
			"and this guard has no universe", typeName)
	}

	readers := map[string]bool{}
	for name, fn := range methods {
		if roleReadSQL.MatchString(expandedBody(t, fn, consts)) {
			readers[name] = true
		}
	}
	if len(readers) == 0 {
		t.Fatalf("found no role-bearing SELECT in the shared store's %s — either the SQL moved "+
			"or roleReadSQL is stale. Refusing to certify the read cutover against an empty universe", typeName)
	}

	for changed := true; changed; {
		changed = false
		for name, fn := range methods {
			if readers[name] {
				continue
			}
			for called := range calledMethodNames(fn) {
				if readers[called] {
					readers[name] = true
					changed = true
					break
				}
			}
		}
	}
	return readers
}

// storeRoleReadersNotNeedingOverride records EXPORTED methods the closure pulls
// in that do not, in fact, return a role, with the reason.
//
// Checked in BOTH directions: an entry naming a method the pinned module no
// longer derives as a reader fails the test, so the list cannot rot into a
// permanent exemption for something that changed shape. It is empty today, and
// that is the correct state -- it exists so that a future exemption has to be
// written down and justified rather than smuggled into the regex.
var storeRoleReadersNotNeedingOverride = map[string]map[string]string{
	"OrganizationRepository": {},
	"UserRepository":         {},
}

// unexportedReaderCoverage asserts the ONE structural exemption this guard
// grants: an UNEXPORTED store method cannot be overridden from this package,
// and does not need to be, PROVIDED every exported method that reaches it is.
//
// UserRepository.loadMembershipsForUsers is exactly that case -- it is the bulk
// membership fetch behind ListUsersWithMemberships and SearchWithMemberships,
// and both of those are overridden. The exemption is therefore not "trust us":
// the closure in storeRoleReaders marks any caller of a reader as a reader, so
// the exported callers are already in the universe the test above requires an
// override for. What this function adds is the other half -- that such an
// exported caller EXISTS. An unexported reader nobody calls would otherwise be
// exempted by a rule with nothing behind it, and a future refactor that made it
// the only path would be exempted too.
func unexportedReaderCoverage(t *testing.T, typeName string, readers map[string]bool) {
	t.Helper()
	dir := identityStoreDir(t)
	methods := methodsOn(t, dir, typeName)

	for name := range readers {
		if ast.IsExported(name) {
			continue
		}
		var callers []string
		for caller, fn := range methods {
			if !ast.IsExported(caller) || !readers[caller] {
				continue
			}
			if calledMethodNames(fn)[name] {
				callers = append(callers, caller)
			}
		}
		if len(callers) == 0 {
			t.Errorf("the shared identity store's %s.%s returns a member's role and is UNEXPORTED, "+
				"so repositories.%s cannot override it — and no exported reader on the same type "+
				"calls it, so nothing overridable covers it either. Every route through it resolves "+
				"roles from the identity tables with no way to intercept. This needs a change in the "+
				"identity module, not an exemption here.", typeName, name, typeName)
			continue
		}
		sort.Strings(callers)
		t.Logf("%s.%s is unexported (not overridable); covered through %v, which are overridden",
			typeName, name, callers)
	}
}

// wrapperTypes are the two types in this package that wrap a store repository
// with role-bearing reads.
var wrapperTypes = []string{"OrganizationRepository", "UserRepository"}

// TestMemberRoleReadClass_EveryStoreRoleReaderIsOverridden is bypass 1.
func TestMemberRoleReadClass_EveryStoreRoleReaderIsOverridden(t *testing.T) {
	for _, typeName := range wrapperTypes {
		t.Run(typeName, func(t *testing.T) {
			readers := storeRoleReaders(t, typeName)
			overrides := methodsOn(t, ".", typeName)
			if len(overrides) == 0 {
				t.Fatalf("repositories.%s declares no methods — it is a type alias again, or it was "+
					"renamed. Either way every role read is promoted straight from the shared store "+
					"and resolves from the identity tables", typeName)
			}

			exempt := storeRoleReadersNotNeedingOverride[typeName]
			unexportedReaderCoverage(t, typeName, readers)

			var missing []string
			seen := map[string]bool{}
			for name := range readers {
				if !ast.IsExported(name) {
					// Not reachable from this package; unexportedReaderCoverage
					// has already proved an overridden exported caller exists.
					continue
				}
				if exempt[name] != "" {
					seen[name] = true
					continue
				}
				if overrides[name] == nil {
					missing = append(missing, name)
				}
			}
			sort.Strings(missing)
			for _, name := range missing {
				t.Errorf("the shared identity store's %s.%s returns a member's role template, but "+
					"repositories.%s does not override it. Go promotes the embedded method, so every "+
					"caller keeps compiling and this one accessor keeps resolving roles from "+
					"`organization_members.role_template_id` while every other resolves them from "+
					"registry's own tables (terraform-suite-identity#206 phase 3b). Add an override "+
					"that delegates and then overlays, or — if it returns no role — record it in "+
					"storeRoleReadersNotNeedingOverride with the reason.", typeName, name, typeName)
			}

			for name := range exempt {
				if !seen[name] {
					t.Errorf("storeRoleReadersNotNeedingOverride[%q] names %q, which the pinned module "+
						"no longer derives as a role reader — drop the entry", typeName, name)
				}
			}
			t.Logf("%s: checked %d store role reader(s) against %d override(s)",
				typeName, len(readers), len(overrides))
		})
	}
}

// TestMemberRoleReadClass_EveryOverrideReadsRegistrysTables is bypass 2: an
// override that delegates correctly and then returns identity's role unchanged.
// It compiles, it passes every behavioural test, and it cuts nothing over.
func TestMemberRoleReadClass_EveryOverrideReadsRegistrysTables(t *testing.T) {
	for _, typeName := range wrapperTypes {
		t.Run(typeName, func(t *testing.T) {
			readers := storeRoleReaders(t, typeName)
			overrides := methodsOn(t, ".", typeName)
			exempt := storeRoleReadersNotNeedingOverride[typeName]
			covered := coveredOverrides(overrides, readsRegistryTables)

			var checked int
			for name := range overrides {
				if !readers[name] || exempt[name] != "" {
					continue
				}
				checked++
				if !covered[name] {
					t.Errorf("repositories.%s.%s overrides a store role reader but never reaches "+
						"r.roles -- not directly, and not through a sibling override. The override "+
						"exists precisely so the role comes from registry's own tables; without that "+
						"call it is a pass-through that returns identity's answer and looks like a "+
						"cutover. Note that delegating to r.%s.%s does NOT count: that is the shared "+
						"store, which is what the cutover moved away from.",
						typeName, name, typeName, name)
				}
			}
			if checked == 0 {
				t.Fatalf("%s: no override matched a store role reader — the two derivations have "+
					"drifted apart and this guard is vacuous", typeName)
			}
			t.Logf("%s: checked %d override(s) for a registry-table read", typeName, checked)
		})
	}
}

// TestMemberRoleReadClass_TheOverlayHelpersReachBoth verifies the two named
// helpers in overlayHelpers, which the fixpoint above trusts.
//
// Without this the allowlist would be the guard's one unchecked assumption:
// naming a helper that had stopped calling the reader, or stopped comparing,
// would silently exempt every override that goes through it -- which is most of
// them on UserRepository.
func TestMemberRoleReadClass_TheOverlayHelpersReachBoth(t *testing.T) {
	local := parseDir(t, ".")
	bodies := map[string]map[string]bool{}
	for _, file := range local {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			if fn.Recv != nil {
				name = "r." + name
			}
			bodies[name] = calledPaths(fn)
		}
	}

	for helper := range overlayHelpers {
		calls, found := bodies[helper]
		if !found {
			t.Errorf("overlayHelpers names %q, which does not exist in this package — the fixpoint "+
				"is exempting overrides through a helper that is gone", helper)
			continue
		}
		var reads, compares bool
		for path := range calls {
			if readsRegistryTables(path) {
				reads = true
			}
			if reportsDivergence(path) {
				compares = true
			}
			// A helper may reach either through the other helper.
			if overlayHelpers[path] {
				reads, compares = true, true
			}
		}
		if !reads && !compares {
			t.Errorf("%s neither reads registry's tables nor reports divergence, yet the fixpoint "+
				"treats a call to it as satisfying both", helper)
		}
	}
}

// TestMemberRoleReadClass_EveryOverrideReportsDivergence is the third property,
// and it is the one that keeps the cutover from going silent.
//
// Every override holds BOTH answers -- the store's, from the identity tables it
// still queries, and registry's. Comparing them is free, and it is the only
// per-principal signal that a dual-write gap exists at all: the drift check runs
// when somebody runs it, while this fires on the request that is actually being
// served the wrong role.
//
// An override that overlays without comparing loses that for nothing, and loses
// it invisibly.
func TestMemberRoleReadClass_EveryOverrideReportsDivergence(t *testing.T) {
	for _, typeName := range wrapperTypes {
		t.Run(typeName, func(t *testing.T) {
			readers := storeRoleReaders(t, typeName)
			overrides := methodsOn(t, ".", typeName)
			exempt := storeRoleReadersNotNeedingOverride[typeName]
			covered := coveredOverrides(overrides, reportsDivergence)

			var checked int
			for name := range overrides {
				if !readers[name] || exempt[name] != "" {
					continue
				}
				checked++
				if !covered[name] {
					t.Errorf("repositories.%s.%s serves registry's role without ever reaching "+
						"compareRole -- not directly, and not through a sibling override. That "+
						"comparison is free (both answers are already in hand) and it is the only "+
						"signal that a dual-write gap has left this principal with the wrong role; "+
						"without it the divergence is silent until somebody runs the drift check.",
						typeName, name)
				}
			}
			if checked == 0 {
				t.Fatalf("%s: no override matched a store role reader — this guard is vacuous", typeName)
			}
			t.Logf("%s: checked %d override(s) for a divergence report", typeName, checked)
		})
	}
}

// sharedRoleTemplateRead matches a hand-written SELECT/JOIN against the SHARED
// role_templates table.
//
// The optional schema qualifier is there because the same read appears
// unqualified, as `public.role_templates`, and as `identity.role_templates`
// depending on the topology the author had in mind. The `\s+` after FROM/JOIN is
// what keeps `registry_role_templates` -- registry's OWN table, which every one
// of these should now name -- from matching.
var sharedRoleTemplateRead = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+(?:public\.|identity\.)?role_templates\b`)

// sharedRoleTemplateReadExemptions are files permitted to READ the shared table,
// keyed by module-relative path, with the reason.
//
// Checked in both directions: an entry whose file no longer contains such a read
// fails the test, so a stale exemption cannot quietly cover a new one.
var sharedRoleTemplateReadExemptions = map[string]string{}

// TestMemberRoleReadClass_NoHandWrittenSharedRoleTemplateRead is bypass 3, and
// it is the one the first version of this change did not have.
//
// The two tests above reason about the WRAPPER TYPES. They are blind to a
// handler that issues its own SQL, and two did: role_ceiling.go's
// checkRoleAssignment -- which decides whether a role may be assigned at all,
// and refuses the platform-admin template -- and group_mapping_guard.go's
// guardProvisionableRole, which decides what an IdP group claim may confer and
// supplies the retention filter for the credential sweep. Both read
// `SELECT scopes FROM role_templates`, both are authorization decisions, and
// both would have kept computing them from the copy registry no longer enforces.
//
// Neither was found by the wrapper guards. Neither would have been found by any
// behavioural test, because the two copies agree until they do not. It took
// reading the diff, which is exactly the review step a class guard exists to
// replace.
func TestMemberRoleReadClass_NoHandWrittenSharedRoleTemplateRead(t *testing.T) {
	// Self-check FIRST: a regex that matches nothing would make every assertion
	// below vacuous, and this file's whole subject is guards that certify
	// nothing.
	for _, positive := range []string{
		"SELECT scopes FROM role_templates WHERE id = $1",
		"LEFT JOIN role_templates rt ON rt.id = om.role_template_id",
		"FROM identity.role_templates",
	} {
		if !sharedRoleTemplateRead.MatchString(positive) {
			t.Fatalf("sharedRoleTemplateRead does not match %q — the scan below would certify nothing", positive)
		}
	}
	for _, negative := range []string{
		"SELECT scopes FROM registry_role_templates WHERE id = $1",
		"LEFT JOIN registry_role_templates rrt ON rrt.id = omr.role_template_id",
	} {
		if sharedRoleTemplateRead.MatchString(negative) {
			t.Fatalf("sharedRoleTemplateRead matches %q — it cannot tell registry's own table "+
				"from the shared one, so every correct read would be reported", negative)
		}
	}

	root := moduleRoot(t)
	var scanned int
	offenders := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || name == "migrations" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		src, readErr := os.ReadFile(path) //nolint:gosec // G304: path comes from WalkDir over the module root
		if readErr != nil {
			return readErr
		}
		if m := sharedRoleTemplateRead.FindString(string(src)); m != "" {
			offenders[rel] = m
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned == 0 {
		t.Fatal("scanned no Go files — this guard has no universe and would certify nothing")
	}

	for rel, match := range offenders {
		if reason := sharedRoleTemplateReadExemptions[rel]; reason != "" {
			continue
		}
		t.Errorf("%s reads the SHARED role_templates by hand (%q). Since the read cutover "+
			"(terraform-suite-identity#206 phase 3b) registry's authorization is decided by "+
			"registry_role_templates, so this computes an answer the product does not enforce — "+
			"and the two copies agree until the moment they matter. Read registry's own table, "+
			"or record the file in sharedRoleTemplateReadExemptions with the reason.", rel, match)
	}
	for rel := range sharedRoleTemplateReadExemptions {
		if _, still := offenders[rel]; !still {
			t.Errorf("sharedRoleTemplateReadExemptions names %q, which no longer reads the shared "+
				"role_templates — drop the entry", rel)
		}
	}
	t.Logf("scanned %d Go file(s) for a hand-written shared role_templates read", scanned)
}
