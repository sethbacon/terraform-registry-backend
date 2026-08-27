package api

// provider_protocol_orgblind_class_test.go pins the fix for #972 as a CLASS
// property rather than as five separate patched call sites.
//
// THE DEFECT. A provider source is host/namespace/type: two identifier segments
// and no slot for an organization, so a Terraform client cannot supply one.
// Every public provider route nevertheless resolved the organization literally
// named "default" and passed it as a filter, which made a provider owned by any
// OTHER organization a permanent 404 -- with no error, so it read as "that
// provider does not exist" rather than as a misconfiguration. Modules were
// unaffected, which is what made it hard to notice: the same deployment served
// its modules correctly and its providers not at all.
//
// WHY A GUARD AND NOT JUST THE FIX. There were seven call sites across five
// files, all written the same way, and the idiom (resolve the default org, pass
// its ID to a lookup) is the obvious thing to write again. One of the seven was
// not a lookup at all but the mirrored-version APPROVAL GATE, which did not
// return a wrong answer -- it silently DID NOT RUN, fell through its nested
// conditions, and served the archive. A guard that only checks the routes that
// 404 would have missed exactly the one that mattered most.
//
// WHAT IS DELIBERATELY NOT COVERED. The admin write surface
// (create/update/delete, upload) still resolves an organization and still
// should: those routes decide who may PUBLISH under a namespace, which IS an
// organization question. Only READ resolution is org-blind.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// orgScopedProviderLookup is the repository method that takes an organization
// and filters by it. Reaching it from a protocol read path is the defect.
const orgScopedProviderLookup = "GetProvider"

// providerProtocolReadFuncs are the functions that answer, or gate, a request
// addressed by protocol coordinates alone. None of them may filter a provider
// lookup by organization.
//
// Listed by name rather than by file so a function moving between files does not
// silently leave the guard. Each entry must be found, which is asserted.
var providerProtocolReadFuncs = map[string]string{
	"ListVersionsHandler":   "GET /v1/providers/:namespace/:type/versions — the Terraform protocol listing",
	"DownloadHandler":       "GET /v1/providers/:namespace/:type/:version/download/:os/:arch — the protocol download",
	"IndexHandler":          "the provider network mirror index",
	"PlatformIndexHandler":  "the provider network mirror platform index",
	"GetProvider":           "GET /api/v1/providers/:namespace/:type — the public detail route",
	"ServeFileHandler":      "GET /v1/files/*filepath — carries the mirrored-version APPROVAL GATE",
	"trackProviderDownload": "the detached download counter for a protocol download",
}

// defaultOrgExemptForPullThrough are the functions that may still resolve the
// default organization, with the reason.
//
// A named exemption rather than a narrower guard, because "this function is
// allowed to do the dangerous thing" is a claim that should be written down and
// re-read, not encoded as an absence.
//
// The two mirror handlers resolve an organization for the PULL-THROUGH mirror
// configuration -- which upstream to fetch from, and with which credentials.
// That genuinely is owned by an organization, unlike the lookup of an
// already-published provider, which is why only the lookup was changed in #972.
//
// It is not obviously RIGHT, either: a provider published under organization B
// whose pull-through config lives under the organization named "default" will
// use A's upstream. That is a separate question from the 404 this issue is
// about, and it belongs to the host-scoping work rather than being decided here
// by a guard that happened to notice it.
var defaultOrgExemptForPullThrough = map[string]string{
	"IndexHandler":         "resolves the org for pull-through mirror config, not for the provider lookup",
	"PlatformIndexHandler": "resolves the org for pull-through mirror config, not for the provider lookup",
}

// minWatchedProviderReads is the shrink-the-universe guard.
//
// Every assertion in this file runs only for a function named in
// providerProtocolReadFuncs, so DELETING an entry silently stops checking that
// call site while the whole file still reports green -- the same failure the
// map exists to prevent, one level up. Raise this when adding entries; a
// reduction has to be deliberate.
const minWatchedProviderReads = 7

// approvalGateFunc must always be watched, by name.
//
// A floor alone would let someone drop this entry and add a trivial one. This
// is the site whose failure is silent: it does not return a wrong answer, it
// skips the mirrored-version approval gate and serves the archive.
const approvalGateFunc = "ServeFileHandler"

// providerProtocolPackages are the directories searched for those functions.
var providerProtocolPackages = []string{
	"internal/api/providers",
	"internal/api/mirror",
	"internal/api/modules",
	"internal/api/admin",
}

func TestProviderProtocolReadsAreOrganizationBlind(t *testing.T) {
	if len(providerProtocolReadFuncs) < minWatchedProviderReads {
		t.Fatalf("only %d provider read functions are watched (floor %d): entries have been removed, "+
			"so those call sites are no longer checked and this file passes without looking at them",
			len(providerProtocolReadFuncs), minWatchedProviderReads)
	}
	if _, ok := providerProtocolReadFuncs[approvalGateFunc]; !ok {
		t.Fatalf("%s is not watched. It carries the mirrored-version approval gate, whose failure "+
			"mode is silence: an org-scoped lookup there does not 404, it skips the gate and serves "+
			"the archive (#972).", approvalGateFunc)
	}

	root := moduleRoot(t)
	found := map[string]bool{}

	for _, pkg := range providerProtocolPackages {
		dir := filepath.Join(root, pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", pkg, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				why, watched := providerProtocolReadFuncs[fn.Name.Name]
				if !watched {
					return true
				}
				found[fn.Name.Name] = true

				// Two signatures, because the defect had two shapes: calling
				// the org-taking lookup, and resolving the default org at all.
				// The second matters on its own -- in ServeFileHandler the
				// resolution WAS the gate's outer condition, and a failed
				// resolve skipped the gate rather than refusing the request.
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pos := fset.Position(call.Pos())
					switch sel.Sel.Name {
					case orgScopedProviderLookup:
						// Distinguish the repository method from same-named
						// handlers: the repository call carries a context plus
						// an org id plus the two coordinates.
						if len(call.Args) == 4 {
							t.Errorf("%s:%d: %s calls the organization-scoped %s.\n"+
								"%s\nUse GetProviderByNamespace: the protocol has no slot for an "+
								"organization, so filtering by one makes every provider owned by "+
								"another organization a 404 (#972).",
								pos.Filename, pos.Line, fn.Name.Name, orgScopedProviderLookup, why)
						}
					case "GetDefaultOrganization":
						if _, exempt := defaultOrgExemptForPullThrough[fn.Name.Name]; exempt {
							return true
						}
						t.Errorf("%s:%d: %s resolves the default organization.\n"+
							"%s\nA provider read addressed by protocol coordinates must not depend "+
							"on which organization is named \"default\" -- and where the resolution "+
							"gates something, a failed resolve skips the gate rather than refusing "+
							"the request (#972).",
							pos.Filename, pos.Line, fn.Name.Name, why)
					}
					return true
				})
				return true
			})
		}
	}

	// Empty-universe guard. Every assertion above runs inside a walk; if the
	// walk found none of these functions they all pass while checking nothing.
	var missing []string
	for name := range providerProtocolReadFuncs {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	for name := range defaultOrgExemptForPullThrough {
		if _, watched := providerProtocolReadFuncs[name]; !watched {
			t.Errorf("defaultOrgExemptForPullThrough exempts %q, which is not a watched function. "+
				"An exemption for something nobody checks is not an exemption.", name)
		}
	}

	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s was not found in any of %v, so it is not being checked.\n"+
			"If it was renamed or moved, update providerProtocolReadFuncs -- do not drop the entry.",
			name, providerProtocolPackages)
	}
}
