// Command credlifecycle is the executable signature for the
// "authority reduced without credential invalidation" defect class
// (terraform-registry-backend #732, #736).
//
//	go run ./tools/credlifecycle [-root .] [extra package patterns ...]
//
// It is type-aware (go/packages + go/types), so every sink and every call edge
// is resolved to a fully-qualified method object — "Update" on APIKeyRepository
// is never confused with "Update" on MirrorRepository.
//
// It does NOT contain a list of known-bad files. Three phases:
//
// PHASE 1 — DERIVE the vocabulary from the persistence layer.
//
//	authority-reducing sink : a func whose body contains SQL that deletes or
//	                          narrows the row granting derived authority
//	                          (organization_members, users, role_templates).
//	jwt-invalidation sink   : a func whose body contains SQL writing
//	                          revoked_tokens / user_token_revocations.
//	apikey-invalidation sink: a func whose body contains SQL deleting an
//	                          api_keys row or flipping it inactive/expired.
//
// PHASE 2 — ENUMERATE every func in the scanned module that reaches an
//
//	authority-reducing sink through the resolved call graph.
//
// PHASE 3 — For each such site, require that its call closure ALSO reaches
//
//	BOTH invalidation families. Missing either => an instance of the class.
//
// Sites are reported at their outermost enclosing FuncDecl, which for gin is
// the handler constructor (e.g. RemoveMemberHandler) — the stable identity a
// route maps to.
//
// PHASE 3b — BRANCH GRANULARITY. Phase 3 asks the question per FUNCTION, and a
//
//	function is the wrong unit whenever it reduces authority in more than one
//	mutually exclusive branch. reconcileGroupMemberships is exactly that: its
//	`!wanted && isMember` branch removes a membership AND sweeps the org's API
//	keys, while its `wanted && isMember` branch commits a role reassignment —
//	which is a REDUCTION whenever the new template grants less — and swept
//	nothing. The function reached both families, so Phase 3 scored it OK and
//	the unswept branch survived a clean run of this signature.
//
//	So for every authority-reducing call that sits inside a conditional
//	branch, Phase 3b re-asks the question with the coverage available to THAT
//	branch: the calls inside the branch itself, plus the function's own
//	unconditional statements (a sweep placed after the switch covers every
//	arm). A family the function has but this branch does not is a defect,
//	reported at the branch.

package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
)

var (
	// A row that GRANTS derived authority is deleted, re-pointed, or narrowed.
	//
	// `delete from organizations` belongs here even though it names no
	// principal: organization_members.organization_id is ON DELETE CASCADE, so
	// dropping an organization silently reduces every one of its members'
	// authority. Omitting the verb is how DeleteOrganizationHandler escaped an
	// earlier run of this signature -- a reduction the vocabulary could not
	// spell was a reduction the enumeration could not find. (The \b matters:
	// "organization_members" must not match here, it has its own pattern.)
	reReduce = regexp.MustCompile(`(?is)` + strings.Join([]string{
		`delete\s+from\s+organization_members`,
		`delete\s+from\s+organizations\b`,
		`delete\s+from\s+users\b`,
		`delete\s+from\s+role_templates`,
		`update\s+organization_members\s+set[^;]*role_template_id`,
		`update\s+role_templates\s+set[^;]*scopes`,
		`update\s+users\s+set[^;]*(is_active|active|disabled|deleted_at)`,
	}, "|"))

	reJWT = regexp.MustCompile(`(?is)` + strings.Join([]string{
		`insert\s+into\s+revoked_tokens`,
		`insert\s+into\s+user_token_revocations`,
		`update\s+user_token_revocations`,
	}, "|"))

	// A DELETE is unambiguous. An UPDATE is not, and is classified by
	// isKeyInvalidatingUpdate below rather than by a regexp: the previous
	// pattern `update api_keys set[^;]*(is_active|revoked|expires_at)` also
	// matched the ORDINARY key-edit path
	//
	//	UPDATE api_keys SET name = $2, description = $3, scopes = $4, expires_at = $5
	//
	// (identity/store.APIKeyRepository.Update), so any future site that merely
	// RENAMED a key would have scored as having swept it. A signature that
	// counts an edit as a revocation cannot detect a missing revocation.
	reAPIKeyDelete = regexp.MustCompile(`(?is)delete\s+from\s+api_keys`)

	// The SET clause of an `UPDATE api_keys`, captured for column analysis.
	reAPIKeyUpdate = regexp.MustCompile(`(?is)update\s+api_keys\s+set\s+([^;]*?)(?:\s+where\b|$)`)

	// Columns whose assignment retires a key rather than editing it.
	revocationColumns = map[string]bool{
		"is_active": true, "revoked": true, "revoked_at": true,
		"expires_at": true, "deleted_at": true, "disabled": true,
	}

	// Left-hand side of one assignment in a SET clause.
	reAssignedColumn = regexp.MustCompile(`(?i)([a-z_][a-z0-9_]*)\s*=`)
)

// isKeyInvalidatingUpdate reports whether an `UPDATE api_keys` in this body
// retires keys rather than editing them.
//
// The rule: EVERY column the statement assigns must be a revocation column,
// and there must be at least one. `SET expires_at = NOW()` and
// `SET is_active = false` are revocations; `SET name = $2, ..., expires_at =
// $5` is an edit that merely happens to touch a revocation column, and
// `SET last_used_at = $2` is neither.
func isKeyInvalidatingUpdate(body string) bool {
	for _, m := range reAPIKeyUpdate.FindAllStringSubmatch(body, -1) {
		assigned := reAssignedColumn.FindAllStringSubmatch(m[1], -1)
		if len(assigned) == 0 {
			continue
		}
		allRevoking := true
		for _, a := range assigned {
			if !revocationColumns[strings.ToLower(a[1])] {
				allRevoking = false
				break
			}
		}
		if allRevoking {
			return true
		}
	}
	return false
}

// exemptions are sites the analysis reaches but which are NOT instances of the
// defect, each with the concrete technical reason. Keyed by the full type-
// checked object name, so a rename or a new site is never silently covered:
// anything not listed here that reaches an authority-reducing sink without both
// invalidation families is reported as a defect and exits non-zero.
//
// The value is (missingFamiliesTolerated, reason). "*" tolerates both.
var exemptions = map[string]struct {
	tolerate string
	reason   string
}{
	// The IdP login paths sweep API keys but deliberately do NOT move the JWT
	// revoke-all watermark: reconcileGroupMemberships runs microseconds before
	// the same request mints the user's new session token, whose iat is floored
	// to the second, so the watermark would revoke the token being issued and
	// the user could never log in. The new token is derived AFTER the removal
	// and so already carries the reduced authority.
	//
	// The exemption is NARROWER than it looks, and is granted knowingly: it
	// covers the token minted by THIS request, not the user's other live
	// sessions from earlier logins, which keep the pre-reduction scope union
	// until their TTL expires. See credlifecycle.Sweeper.OrgKeysOnly, which
	// states the residual in full, and docs/upgrade-guide.md, which states it
	// to operators.
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).reconcileGroupMemberships": {"JWT", "this request's fresh token already carries reduced scopes and the watermark would revoke it; other live sessions are a stated residual"},
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).CallbackHandler":           {"JWT", "caller of reconcileGroupMemberships"},
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).SAMLACSHandler":            {"JWT", "caller of reconcileGroupMemberships"},
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).LDAPLoginHandler":          {"JWT", "caller of reconcileGroupMemberships"},

	// NOTE: admin.UserHandlers.DeleteUserHandler was exempted here on the
	// grounds that "api_keys.user_id is ON DELETE CASCADE, so every key
	// vanishes with the row". That premise was FALSE for the schema that
	// actually serves this table. Only the registry's own legacy
	// public.api_keys declares CASCADE
	// (internal/db/migrations/000001_initial_schema.up.sql:60); the shared
	// identity schema declares
	//
	//	identity.api_keys.user_id UUID REFERENCES identity.users(id) ON DELETE SET NULL
	//
	// so deleting a principal DETACHED its keys instead of destroying them,
	// leaving userless org-bound rows that the namespace authorizer reads as
	// organization service credentials and exempts from membership checks.
	// The exemption is removed and the site now sweeps explicitly. Leaving
	// this as a comment rather than deleting it: an exemption is a claim about
	// the world, and this one records how to check the claim.

	// First-boot setup promoting the bootstrap admin. It reaches the shared
	// UpdateMemberRole implementation, but the direction is an authority
	// INCREASE, and it runs before any credential for that principal exists.
	"(*github.com/terraform-registry/terraform-registry/internal/api/setup.Handlers).ConfigureAdmin": {"*", "authority increase during first-boot setup, not a reduction"},

	// One-line delegation shims onto the shared identity store. They carry no
	// policy; the control belongs to their handler callers, which are covered.
	"(*github.com/terraform-registry/terraform-registry/internal/db/repositories.RBACRepository).UpdateRoleTemplate": {"*", "delegation shim; control lives in admin.RBACHandlers.UpdateRoleTemplate"},
	"(*github.com/terraform-registry/terraform-registry/internal/db/repositories.RBACRepository).DeleteRoleTemplate": {"*", "delegation shim; control lives in admin.RBACHandlers.DeleteRoleTemplate"},
}

type node struct {
	obj      *types.Func
	pos      string
	inModule bool
	callees  map[*types.Func]bool
	// fd/info/fset are retained for the branch-granular pass (Phase 3b), which
	// needs the syntax back to ask which conditional arm a reducing call sits
	// in. The flattened callee set above cannot answer that.
	fd   *ast.FuncDecl
	info *types.Info
	fset *token.FileSet
}

func main() {
	root := flag.String("root", ".", "module directory to scan")
	prefixes := flag.String("prefixes", strings.Join(firstPartyPrefixes, ","),
		"comma-separated import-path prefixes treated as first-party")
	flag.Parse()
	firstPartyPrefixes = strings.Split(*prefixes, ",")

	patterns := append([]string{"./..."}, flag.Args()...)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports |
			packages.NeedDeps | packages.NeedModule,
		Dir:   *root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(2)
	}

	scanned := 0
	graph := map[*types.Func]*node{}
	reduceSinks := map[*types.Func]bool{}
	jwtSinks := map[*types.Func]bool{}
	keySinks := map[*types.Func]bool{}

	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if len(p.Syntax) == 0 || p.TypesInfo == nil {
			return
		}
		// Only analyse first-party code: the scanned module plus any extra
		// pattern the caller asked for (shared identity module).
		//
		// The scanned module is always in scope regardless of its import path
		// -- deciding scope from a hardcoded prefix list silently reported
		// "0 sites" when this tool was first pointed at a repo whose module
		// path was not on the list, which is the worst possible failure mode
		// for a signature. -prefixes only widens scope to dependencies.
		inModule := p.Module != nil && p.Module.Main
		if !inModule && !firstParty(p.PkgPath) {
			return
		}
		scanned++
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				obj, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
				if obj == nil {
					continue
				}
				n := &node{
					obj:      obj,
					pos:      trimPos(p.Fset.Position(fd.Pos()).String()),
					inModule: inModule,
					callees:  map[*types.Func]bool{},
					fd:       fd,
					info:     p.TypesInfo,
					fset:     p.Fset,
				}
				var sb strings.Builder
				astutil.Apply(fd, func(c *astutil.Cursor) bool {
					switch e := c.Node().(type) {
					case *ast.BasicLit:
						if e.Kind == token.STRING {
							if s, uerr := strconv.Unquote(e.Value); uerr == nil {
								sb.WriteString(s + "\n")
							}
						}
					case *ast.CallExpr:
						if callee, _ := typeutil.Callee(p.TypesInfo, e).(*types.Func); callee != nil {
							n.callees[callee] = true
						}
					}
					return true
				}, nil)
				body := sb.String()
				if reReduce.MatchString(body) {
					reduceSinks[obj] = true
				}
				if reJWT.MatchString(body) {
					jwtSinks[obj] = true
				}
				if reAPIKeyDelete.MatchString(body) || isKeyInvalidatingUpdate(body) {
					keySinks[obj] = true
				}
				graph[obj] = n
			}
		}
	})

	if scanned == 0 {
		fmt.Fprintf(os.Stderr, "credlifecycle: no first-party packages with syntax were loaded from %q -- "+
			"the scan is vacuous, not clean. Check that the path is a Go module root.\n", *root)
		os.Exit(2)
	}
	if len(reduceSinks) == 0 {
		fmt.Fprintln(os.Stderr, "credlifecycle: no authority-reducing sinks derived -- "+
			"the identity data layer was not in scope. Pass its package pattern as an argument.")
		os.Exit(2)
	}

	dump("DERIVED authority-reducing sinks", reduceSinks)
	dump("DERIVED jwt-invalidation sinks", jwtSinks)
	dump("DERIVED apikey-invalidation sinks", keySinks)

	memo := map[*types.Func]map[string]bool{}
	var reach func(f *types.Func, seen map[*types.Func]bool) map[string]bool
	reach = func(f *types.Func, seen map[*types.Func]bool) map[string]bool {
		if r, ok := memo[f]; ok {
			return r
		}
		if seen[f] {
			return map[string]bool{}
		}
		seen[f] = true
		out := map[string]bool{}
		if reduceSinks[f] {
			out["reduce"] = true
		}
		if jwtSinks[f] {
			out["jwt"] = true
		}
		if keySinks[f] {
			out["key"] = true
		}
		if n := graph[f]; n != nil {
			for c := range n.callees {
				for k := range reach(c, seen) {
					out[k] = true
				}
			}
		}
		delete(seen, f)
		if len(seen) == 0 {
			memo[f] = out
		}
		return out
	}

	reachOf := func(f *types.Func) map[string]bool { return reach(f, map[*types.Func]bool{}) }

	type row struct{ id, pos, missing, exempt, note string }
	var sites, defects []row
	// applyExemption blanks `missing` when an exemption covers exactly the
	// families that are absent. Shared by the function-level and branch-level
	// rows so a branch cannot be reported under an exemption its function does
	// not have, nor escape one its function does.
	applyExemption := func(id string, r *row) {
		if ex, ok := exemptions[id]; ok && r.missing != "" &&
			(ex.tolerate == "*" || ex.tolerate == r.missing) {
			r.exempt = ex.reason
			r.missing = ""
		}
	}
	for obj, n := range graph {
		if !n.inModule || reduceSinks[obj] {
			continue
		}
		// Only report the OUTERMOST site: if a caller of this func is itself a
		// site, this one is an implementation detail of that site. Keep both
		// only when the inner one is exported-handler-shaped. Simplest honest
		// rule: report every func that DIRECTLY calls a reducing sink, plus any
		// exported func that transitively reaches one.
		direct := false
		for c := range n.callees {
			if reduceSinks[c] {
				direct = true
			}
		}
		r := reach(obj, map[*types.Func]bool{})
		if !r["reduce"] {
			continue
		}
		if !direct && !obj.Exported() {
			continue
		}
		id := obj.FullName()
		rw := row{id: id, pos: n.pos, missing: missingFamilies(r)}
		applyExemption(id, &rw)
		sites = append(sites, rw)
		if rw.missing != "" {
			defects = append(defects, rw)
		}

		// Phase 3b: the same question, per conditional arm. Only families the
		// FUNCTION has are asked for -- one the function lacks entirely is
		// already reported (or exempted) by the row above, and reporting it
		// again at every branch would be noise.
		for _, g := range branchGaps(n, reduceSinks, reachOf) {
			g.missing = subtractFamilies(g.missing, rw.missing)
			if g.missing == "" {
				continue
			}
			brw := row{
				id:      id,
				pos:     g.pos,
				missing: g.missing,
				note:    "branch: " + g.desc,
			}
			applyExemption(id, &brw)
			sites = append(sites, brw)
			if brw.missing != "" {
				defects = append(defects, brw)
			}
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].pos < sites[j].pos })
	sort.Slice(defects, func(i, j int) bool { return defects[i].pos < defects[j].pos })

	fmt.Println("\n=== AUTHORITY-REDUCTION SITES ===")
	for _, s := range sites {
		st := "OK"
		switch {
		case s.missing != "":
			st = "DEFECT missing=" + s.missing
		case s.exempt != "":
			st = "EXEMPT"
		}
		line := fmt.Sprintf("%-26s %-78s %s", st, s.id, s.pos)
		if s.note != "" {
			line += "\n" + strings.Repeat(" ", 27) + s.note
		}
		if s.exempt != "" {
			line += "\n" + strings.Repeat(" ", 27) + "reason: " + s.exempt
		}
		fmt.Println(line)
	}
	fmt.Printf("\n%d site(s), %d defect(s)\n", len(sites), len(defects))
	if len(defects) > 0 {
		os.Exit(1)
	}
}

// missingFamilies renders the invalidation families absent from a reach set.
func missingFamilies(r map[string]bool) string {
	var miss []string
	if !r["jwt"] {
		miss = append(miss, "JWT")
	}
	if !r["key"] {
		miss = append(miss, "APIKEY")
	}
	return strings.Join(miss, "+")
}

// subtractFamilies removes from `have` every family already named in `also`, so
// a branch never re-reports a gap its enclosing function is reported for.
func subtractFamilies(have, also string) string {
	if also == "" || have == "" {
		return have
	}
	drop := map[string]bool{}
	for _, f := range strings.Split(also, "+") {
		drop[f] = true
	}
	var keep []string
	for _, f := range strings.Split(have, "+") {
		if !drop[f] {
			keep = append(keep, f)
		}
	}
	return strings.Join(keep, "+")
}

// gap is one authority-reducing call whose own conditional arm does not reach
// an invalidation family the enclosing function reaches elsewhere.
type gap struct {
	pos     string
	missing string
	desc    string
}

// branchGaps runs Phase 3b over one function: for every call to an
// authority-reducing sink that sits inside a conditional arm, it recomputes the
// invalidation coverage from that arm's own statements plus the function's
// unconditional ones, and reports the families the arm cannot reach.
//
// The "plus unconditional" half matters: the common and correct shape is a
// switch that decides WHAT changed followed by a single sweep afterwards, and
// counting only the arm's own statements would call every one of those a
// defect. Statements in a SIBLING arm never count -- that is the whole point,
// and precisely the mistake the function-level pass made.
func branchGaps(n *node, reduceSinks map[*types.Func]bool, reachOf func(*types.Func) map[string]bool) []gap {
	if n.fd == nil || n.info == nil || n.fd.Body == nil {
		return nil
	}
	parent := parentMap(n.fd)

	var allCalls []*ast.CallExpr
	var reduceCalls []*ast.CallExpr
	ast.Inspect(n.fd, func(x ast.Node) bool {
		ce, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		allCalls = append(allCalls, ce)
		// REACHES a reducing sink, not just IS one. The arm that missed the
		// sweep called (*OrganizationRepository).UpdateMemberRole, a one-line
		// convenience wrapper around the UpdateMemberRoleTemplate sink; keying
		// on direct sink identity found the sibling arm's RemoveMember (which
		// carries its own DELETE) and nothing else, so the pass reproduced the
		// very blindness it exists to remove.
		if f, _ := typeutil.Callee(n.info, ce).(*types.Func); f != nil && reachOf(f)["reduce"] {
			reduceCalls = append(reduceCalls, ce)
		}
		return true
	})

	var out []gap
	seen := map[string]bool{}
	for _, rc := range reduceCalls {
		arm, cond := enclosingBranch(rc, n.fd, parent)
		if arm == nil {
			// Unconditional reduction: the function-level pass already asks the
			// question at the right granularity.
			continue
		}
		inArm := subtreeCalls(arm)
		inCond := subtreeCalls(cond)

		fams := map[string]bool{}
		for _, ce := range allCalls {
			if !inArm[ce] && inCond[ce] {
				continue // a sibling arm's statement; not available here
			}
			f, _ := typeutil.Callee(n.info, ce).(*types.Func)
			if f == nil {
				continue
			}
			for k := range reachOf(f) {
				fams[k] = true
			}
		}
		miss := missingFamilies(fams)
		if miss == "" {
			continue
		}
		pos := trimPos(n.fset.Position(rc.Pos()).String())
		if seen[pos] {
			continue
		}
		seen[pos] = true
		out = append(out, gap{
			pos:     pos,
			missing: miss,
			desc: fmt.Sprintf("%s arm at %s reduces authority without sweeping; a sibling arm does",
				branchKind(arm), trimPos(n.fset.Position(arm.Pos()).String())),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out
}

// parentMap indexes every node under root by its parent, so a call expression
// can be walked back up to the conditional arm containing it.
func parentMap(root ast.Node) map[ast.Node]ast.Node {
	parent := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(root, func(x ast.Node) bool {
		if x == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parent[x] = stack[len(stack)-1]
		}
		stack = append(stack, x)
		return true
	})
	return parent
}

// enclosingBranch returns the INNERMOST conditional arm containing x (a switch
// case, a select case, or an if/else block) and the OUTERMOST conditional
// statement containing it. Both are nil when x is unconditional within fd.
func enclosingBranch(x ast.Node, fd *ast.FuncDecl, parent map[ast.Node]ast.Node) (arm ast.Node, cond ast.Node) {
	for cur := ast.Node(x); cur != nil && cur != ast.Node(fd); cur = parent[cur] {
		p := parent[cur]
		switch cur.(type) {
		case *ast.CaseClause, *ast.CommClause:
			if arm == nil {
				arm = cur
			}
		case *ast.BlockStmt:
			// The Body or the Else of an if statement is an arm; a bare block,
			// a loop body or a function body is not.
			if ifs, ok := p.(*ast.IfStmt); ok && arm == nil && (ifs.Body == cur || ifs.Else == cur) {
				arm = cur
			}
		}
		switch cur.(type) {
		case *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			cond = cur // keep climbing: the last one wins, i.e. the outermost
		}
	}
	if arm == nil {
		return nil, nil
	}
	if cond == nil {
		cond = arm
	}
	return arm, cond
}

// subtreeCalls is the set of call expressions syntactically inside root.
func subtreeCalls(root ast.Node) map[*ast.CallExpr]bool {
	out := map[*ast.CallExpr]bool{}
	if root == nil {
		return out
	}
	ast.Inspect(root, func(x ast.Node) bool {
		if ce, ok := x.(*ast.CallExpr); ok {
			out[ce] = true
		}
		return true
	})
	return out
}

func branchKind(arm ast.Node) string {
	switch arm.(type) {
	case *ast.CaseClause:
		return "switch-case"
	case *ast.CommClause:
		return "select-case"
	default:
		return "if/else"
	}
}

// firstPartyPrefixes bounds the analysis to code the suite owns; third-party
// dependencies never define these sinks and parsing them all is wasteful.
// Override with -prefixes when running against another repository.
var firstPartyPrefixes = []string{
	"github.com/terraform-registry/terraform-registry/",
	"github.com/sethbacon/terraform-suite-identity/",
	"github.com/sethbacon/terraform-state-manager/",
}

func firstParty(path string) bool {
	for _, p := range firstPartyPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func dump(label string, s map[*types.Func]bool) {
	var keys []string
	for f := range s {
		keys = append(keys, shortName(f))
	}
	sort.Strings(keys)
	fmt.Printf("%s (%d):\n  %s\n", label, len(keys), strings.Join(keys, "\n  "))
}

func shortName(f *types.Func) string {
	n := f.FullName()
	n = strings.ReplaceAll(n, "github.com/terraform-registry/terraform-registry/internal/", "")
	n = strings.ReplaceAll(n, "github.com/sethbacon/terraform-suite-identity/identity/", "identity/")
	n = strings.ReplaceAll(n, "github.com/sethbacon/terraform-state-manager/", "")
	return n
}

func trimPos(p string) string {
	for _, m := range []string{"/backend/", "/identity/", "/wt/"} {
		if i := strings.Index(p, m); i >= 0 {
			return p[i+1:]
		}
	}
	return p
}
