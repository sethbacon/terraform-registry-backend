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
	reReduce = regexp.MustCompile(`(?is)` + strings.Join([]string{
		`delete\s+from\s+organization_members`,
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

	reAPIKey = regexp.MustCompile(`(?is)` + strings.Join([]string{
		`delete\s+from\s+api_keys`,
		`update\s+api_keys\s+set[^;]*(is_active|revoked|expires_at)`,
	}, "|"))
)

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
	// and so already carries the reduced authority. See
	// credlifecycle.Sweeper.OrgKeysOnly.
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).reconcileGroupMemberships": {"JWT", "fresh token minted in the same request already carries reduced scopes; watermark would revoke it"},
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).CallbackHandler":           {"JWT", "caller of reconcileGroupMemberships"},
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).SAMLACSHandler":            {"JWT", "caller of reconcileGroupMemberships"},
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.AuthHandlers).LDAPLoginHandler":          {"JWT", "caller of reconcileGroupMemberships"},

	// Hard DELETE FROM users. api_keys.user_id is ON DELETE CASCADE, so every
	// key vanishes with the row; and AuthMiddleware aborts 401 "User not found"
	// when a JWT's subject no longer resolves. Both families are invalidated by
	// the schema plus the auth path rather than by an explicit sweep.
	"(*github.com/terraform-registry/terraform-registry/internal/api/admin.UserHandlers).DeleteUserHandler": {"*", "FK ON DELETE CASCADE removes api_keys; AuthMiddleware 401s a JWT whose user is gone"},

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
				if reAPIKey.MatchString(body) {
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

	type row struct{ id, pos, missing, exempt string }
	var sites, defects []row
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
		var miss []string
		if !r["jwt"] {
			miss = append(miss, "JWT")
		}
		if !r["key"] {
			miss = append(miss, "APIKEY")
		}
		id := obj.FullName()
		rw := row{id: id, pos: n.pos, missing: strings.Join(miss, "+")}
		if ex, ok := exemptions[id]; ok && len(miss) > 0 &&
			(ex.tolerate == "*" || ex.tolerate == rw.missing) {
			rw.exempt = ex.reason
			rw.missing = ""
		}
		sites = append(sites, rw)
		if rw.missing != "" {
			defects = append(defects, rw)
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
