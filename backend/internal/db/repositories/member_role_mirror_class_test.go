package repositories

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Class guard for the role-assignment dual-write
// (sethbacon/terraform-suite-identity#206, migration 000055).
//
// The property: EVERY path that assigns or changes a member's role, or that
// writes a role template, writes registry's own tables as well as the existing
// location. Nothing reads registry's tables yet, so no behavioural test can
// observe a path that forgets — the divergence would surface at the read
// cutover, after the rows are already wrong, which is the worst possible time.
//
// A defect that is an ABSENT CALL cannot be caught by testing the calls that
// are present. There are four ways a new assignment path could bypass the
// dual-write, and there is a test below for each:
//
//  1. The shared store grows a new membership writer that
//     repositories.OrganizationRepository does not override. Go promotes the
//     embedded method, every caller compiles, and the mirror is never touched.
//  2. An override is added but forgets the mirror call.
//  3. Somebody builds identitystore.NewOrganizationRepository directly and
//     writes memberships through a repository that has no mirror at all.
//  4. Somebody writes membership SQL by hand.
//
// Every test here fails on an empty universe. A guard that inspects zero write
// paths and reports green is the failure mode this file exists to prevent, and
// it is how three earlier guards in this repository certified nothing at all.

// mirrorCallNames are the accepted ways an override reaches registry's own
// tables. mirrorMemberFromSource is the wrapper's shared helper: it re-reads the
// membership and calls MemberRoleMirror.AssignRole with what the source
// actually says.
var mirrorCallNames = map[string]bool{
	"mirrorMemberFromSource": true,
	"AssignRole":             true,
	"ClearMember":            true,
	"ClearUserEverywhere":    true,
	"UpsertRoleTemplate":     true,
	"DeleteRoleTemplate":     true,
}

// storeMembershipWriteSQL matches a statement that creates, re-roles or removes
// an organization_members row.
//
// DELETE is included here, unlike in
// TestPlatformAdminGrantClass_NoRawSQLMembershipWrites where it is deliberately
// excluded. That test is about AUTHORITY GRANTS, and a delete grants nothing.
// This one is about KEEPING TWO TABLES EQUAL, and a delete that lands in one
// and not the other leaves authority behind in exactly the copy the read
// cutover switches onto.
var storeMembershipWriteSQL = regexp.MustCompile(`(?i)(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+organization_members\b`)

// identityStoreDir locates the source of the pinned terraform-suite-identity
// module, so the universe below is derived from the version this build
// actually links against rather than from a list somebody typed.
//
// A module bump that adds a membership writer therefore fails this guard on the
// bump, which is the moment it can still be handled cheaply.
func identityStoreDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}",
		"github.com/sethbacon/terraform-suite-identity").Output()
	if err != nil {
		t.Fatalf("locate the pinned terraform-suite-identity module: %v "+
			"(without it this guard has no universe and would certify nothing)", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "identity", "store")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("identity store source not at %s: %v", dir, err)
	}
	return dir
}

// methodsOn returns every method declared on *typeName under dir, keyed by
// method name.
func methodsOn(t *testing.T, dir, typeName string) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			ident, ok := star.X.(*ast.Ident)
			if !ok || ident.Name != typeName {
				continue
			}
			out[fn.Name.Name] = fn
		}
	}
	return out
}

// bodyText renders a function body back to source so SQL in string literals can
// be matched whatever shape the literal takes (raw, concatenated, or built by a
// helper that appends a scope predicate).
func bodyText(t *testing.T, fn *ast.FuncDecl) string {
	t.Helper()
	var sb strings.Builder
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			sb.WriteString(lit.Value)
			sb.WriteString("\n")
		}
		return true
	})
	return sb.String()
}

// calledMethodNames returns the names of every method called inside fn.
func calledMethodNames(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			out[f.Sel.Name] = true
		case *ast.Ident:
			out[f.Name] = true
		}
		return true
	})
	return out
}

// storeMembershipWriters derives, from the pinned module's own source, every
// method on the shared store's OrganizationRepository that writes
// organization_members — directly in its own SQL, or by calling one that does.
//
// The transitive step is not decoration. AddMemberWithParams and
// UpdateMemberRole contain no SQL at all: they resolve a role-template name and
// delegate. A guard that matched only SQL would miss both, and those two are
// precisely the methods the IdP group-mapping reconciliation calls.
func storeMembershipWriters(t *testing.T) map[string]bool {
	t.Helper()
	methods := methodsOn(t, identityStoreDir(t), "OrganizationRepository")
	if len(methods) == 0 {
		t.Fatal("found no methods on the shared store's OrganizationRepository — " +
			"the module layout changed and this guard has no universe")
	}

	writers := map[string]bool{}
	for name, fn := range methods {
		if storeMembershipWriteSQL.MatchString(bodyText(t, fn)) {
			writers[name] = true
		}
	}
	if len(writers) == 0 {
		t.Fatal("found no organization_members write statements in the shared store — " +
			"either the SQL moved or storeMembershipWriteSQL is stale. Refusing to " +
			"certify the dual-write against an empty universe")
	}

	// Closure: anything calling a writer is a writer.
	for changed := true; changed; {
		changed = false
		for name, fn := range methods {
			if writers[name] {
				continue
			}
			for called := range calledMethodNames(fn) {
				if writers[called] {
					writers[name] = true
					changed = true
					break
				}
			}
		}
	}
	return writers
}

// storeReadOnlyDespiteCallingAWriter records methods the closure above pulls in
// that are NOT role assignments needing a mirror, with the reason. Checked in
// both directions, like bootstrapExemptions in
// internal/api/admin/platform_admin_grant_class_test.go: an entry naming a
// method that no longer exists fails the test, so the list cannot rot.
var storeReadOnlyDespiteCallingAWriter = map[string]string{}

// TestMemberRoleMirrorClass_EveryStoreMembershipWriterIsOverridden is bypass 1.
//
// repositories.OrganizationRepository embeds the shared store's repository, so
// any method it does not re-declare is PROMOTED: it compiles, it runs, it writes
// organization_members, and it never touches registry's tables. That is a
// silent bypass introduced by upgrading a dependency, with no diff in this
// repository at all.
func TestMemberRoleMirrorClass_EveryStoreMembershipWriterIsOverridden(t *testing.T) {
	writers := storeMembershipWriters(t)
	overrides := methodsOn(t, ".", "OrganizationRepository")
	if len(overrides) == 0 {
		t.Fatal("repositories.OrganizationRepository declares no methods — it is an alias " +
			"again, or the type was renamed. Either way nothing is mirrored")
	}

	var missing []string
	seen := map[string]bool{}
	for name := range writers {
		if reason := storeReadOnlyDespiteCallingAWriter[name]; reason != "" {
			seen[name] = true
			continue
		}
		if overrides[name] == nil {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("the shared identity store's OrganizationRepository.%s writes organization_members, "+
			"but repositories.OrganizationRepository does not override it. Go promotes the embedded "+
			"method, so every caller keeps compiling and the role change never reaches registry's own "+
			"organization_member_roles (terraform-suite-identity#206). Add an override that delegates "+
			"and then mirrors, or — if it is not a role assignment — record it in "+
			"storeReadOnlyDespiteCallingAWriter with the reason.", name)
	}

	for name := range storeReadOnlyDespiteCallingAWriter {
		if !seen[name] {
			t.Errorf("storeReadOnlyDespiteCallingAWriter names %q, which is no longer a membership "+
				"writer in the pinned module — drop the entry", name)
		}
	}

	t.Logf("checked %d store membership writer(s) against %d override(s)", len(writers), len(overrides))
}

// TestMemberRoleMirrorClass_EveryOverrideWritesTheMirror is bypass 2: an
// override that delegates correctly and then forgets the mirror. It would pass
// the test above, pass every behavioural test, and mirror nothing.
func TestMemberRoleMirrorClass_EveryOverrideWritesTheMirror(t *testing.T) {
	writers := storeMembershipWriters(t)
	overrides := methodsOn(t, ".", "OrganizationRepository")

	var checked int
	for name, fn := range overrides {
		if !writers[name] {
			continue // not a membership writer; nothing to mirror
		}
		checked++
		var reaches bool
		for called := range calledMethodNames(fn) {
			if mirrorCallNames[called] {
				reaches = true
				break
			}
		}
		if !reaches {
			t.Errorf("repositories.OrganizationRepository.%s overrides a store membership writer but "+
				"reaches none of the mirror calls %v. The override exists precisely so the role change "+
				"also lands in registry's own tables; without the mirror call it is a pass-through that "+
				"looks like a dual-write.", name, sortedNames(mirrorCallNames))
		}
	}

	if checked == 0 {
		t.Fatal("no override matched a store membership writer — the two derivations have drifted " +
			"apart and this guard is vacuous")
	}
	t.Logf("checked %d override(s) for a mirror call", checked)
}

// storeConstructorExemptions are the files permitted to build the shared store's
// organization repository directly, keyed by module-relative path.
//
// Exactly one: the wrapper, which must build the thing it wraps.
var storeConstructorExemptions = map[string]string{
	"internal/db/repositories/organization_repository.go": "the wrapper itself; it embeds what it constructs",
}

// TestMemberRoleMirrorClass_NoDirectStoreConstruction is bypass 3.
//
// repositories.NewOrganizationRepository returns the mirroring wrapper, but
// identitystore.NewOrganizationRepository is still importable, and a repository
// built that way has no mirror at all. Every membership write through it is
// invisible to both tests above, because both reason about the wrapper's
// methods rather than about which object a caller happens to hold.
func TestMemberRoleMirrorClass_NoDirectStoreConstruction(t *testing.T) {
	root := moduleRoot(t)

	var offenders []string
	var scanned int
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
		scanned++
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		// Any REFERENCE to the symbol, not just a call of it.
		//
		// This started as a check on *ast.CallExpr and that version certified a
		// live bypass: `var X = identitystore.NewOrganizationRepository` names
		// the constructor without calling it, so no CallExpr matches, and every
		// use of X afterwards builds an un-mirrored repository. That is not a
		// hypothetical shape — it is exactly what this file's
		// NewOrganizationRepository was before the wrapper landed. Matching the
		// selector covers the call form too, since a call's Fun IS the selector.
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewOrganizationRepository" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "identitystore" {
				return true
			}
			if _, exempt := storeConstructorExemptions[rel]; exempt {
				return true
			}
			offenders = append(offenders, fset.Position(sel.Pos()).String())
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned == 0 {
		t.Fatal("scanned no Go files — the walk is broken and this guard is vacuous")
	}

	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s — builds identitystore.NewOrganizationRepository directly. That repository has no "+
			"mirror, so every membership role written through it is missing from registry's own "+
			"organization_member_roles (terraform-suite-identity#206). Use "+
			"repositories.NewOrganizationRepository, which returns the mirroring wrapper.", o)
	}
	t.Logf("scanned %d Go file(s) for a direct store construction", scanned)
}

// rawMembershipWriteSQL matches a hand-written organization_members write —
// including DELETE, for the reason given on storeMembershipWriteSQL.
var rawMembershipWriteSQL = regexp.MustCompile(`(?i)(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+organization_members\b`)

// rawWriteMustMirror names the files that write organization_members by hand
// and must therefore mirror by hand too, keyed by module-relative path.
//
// One entry, and it is the reason this test exists. The GDPR erasure issues its
// own unscoped DELETE inside the erasure transaction rather than going through
// the repository, so the dual-write built into the wrapper never sees it, and
// an erased subject's authorization would survive in registry's own table.
//
// Checked in both directions: a file here with no raw write is a stale entry,
// and a raw write in a file that is not here fails outright.
var rawWriteMustMirror = map[string]string{
	"internal/services/user_service.go": "GDPR erasure deletes memberships in its own transaction (EraseUser)",
}

// TestMemberRoleMirrorClass_RawMembershipWritesMirrorToo is bypass 4.
//
// TestPlatformAdminGrantClass_NoRawSQLMembershipWrites already forbids a raw
// INSERT/UPDATE, but deliberately permits a raw DELETE because a delete grants
// no authority. For the dual-write a delete matters just as much as a grant, so
// the remaining raw writes are enumerated here and each must reach the mirror
// somewhere in the same file.
func TestMemberRoleMirrorClass_RawMembershipWritesMirrorToo(t *testing.T) {
	root := moduleRoot(t)

	found := map[string]bool{}
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
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		// The wrapper and the reconcile are the mirror's own implementation.
		if strings.HasPrefix(rel, "internal/db/repositories/member_role_") ||
			rel == "internal/db/repositories/organization_repository.go" {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if !rawMembershipWriteSQL.Match(src) {
			return nil
		}
		found[rel] = true
		if _, known := rawWriteMustMirror[rel]; !known {
			t.Errorf("%s writes organization_members by hand and is not listed in rawWriteMustMirror. "+
				"A hand-written membership write bypasses the dual-write in "+
				"repositories.OrganizationRepository entirely, so registry's own "+
				"organization_member_roles silently diverges (terraform-suite-identity#206). Either "+
				"write it through the repository, or add it here and mirror it in the same file.", rel)
			return nil
		}
		var mirrored bool
		for name := range mirrorCallNames {
			if strings.Contains(string(src), "."+name+"(") {
				mirrored = true
				break
			}
		}
		if !mirrored {
			t.Errorf("%s writes organization_members by hand but reaches none of the mirror calls %v. "+
				"Its role changes never reach registry's own organization_member_roles.",
				rel, sortedNames(mirrorCallNames))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	if len(found) == 0 {
		t.Fatal("found no hand-written organization_members statements anywhere — either every raw " +
			"write moved behind the repository (in which case delete this test and its list) or " +
			"rawMembershipWriteSQL is stale. It must not pass by matching nothing")
	}
	for rel := range rawWriteMustMirror {
		if !found[rel] {
			t.Errorf("rawWriteMustMirror lists %q, which no longer writes organization_members by hand "+
				"— drop the entry", rel)
		}
	}
}

// roleTemplateWriteMethods are the shared store's role-template writers. A role
// template IS an authorization record: changing its scopes changes what every
// member holding it may do, and deleting it clears the assignment on every
// membership through a foreign key, with no statement naming a membership
// anywhere. Both must reach registry's copy.
var roleTemplateWriteMethods = map[string]bool{
	"CreateRoleTemplate": true,
	"UpdateRoleTemplate": true,
	"DeleteRoleTemplate": true,
}

// TestMemberRoleMirrorClass_EveryRoleTemplateWriteMirrors closes the same gap on
// the role-template half. RBACRepository delegates each write to the shared
// store; each delegation must also write registry's own registry_role_templates.
func TestMemberRoleMirrorClass_EveryRoleTemplateWriteMirrors(t *testing.T) {
	methods := methodsOn(t, ".", "RBACRepository")
	if len(methods) == 0 {
		t.Fatal("found no methods on RBACRepository — the type moved and this guard is vacuous")
	}

	var checked int
	for name, fn := range methods {
		if !roleTemplateWriteMethods[name] {
			continue
		}
		checked++
		var reaches bool
		for called := range calledMethodNames(fn) {
			if mirrorCallNames[called] {
				reaches = true
				break
			}
		}
		if !reaches {
			t.Errorf("RBACRepository.%s writes a role template but reaches none of the mirror calls %v. "+
				"Registry's own registry_role_templates would not see the change, and every mirrored "+
				"assignment naming that template would be wrong (terraform-suite-identity#206).",
				name, sortedNames(mirrorCallNames))
		}
	}

	if checked != len(roleTemplateWriteMethods) {
		t.Fatalf("matched %d of %d role-template writers on RBACRepository — the vocabulary is stale, "+
			"so this guard checks less than it claims", checked, len(roleTemplateWriteMethods))
	}
}

// moduleRoot walks up to the directory holding go.mod so the scans cover the
// whole module however the test is invoked.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs cwd: %v", err)
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

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
