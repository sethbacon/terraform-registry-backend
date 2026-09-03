package db

// swagger_ci_parity_test.go keeps `make swag` and CI producing the same
// openapi3.json (#947).
//
// WHAT WENT WRONG. The Makefile's openapi3 target ran swagger2openapi and then
// post-processed the result, promoting operation-level path parameters to path
// level. CI's "Swagger generation" step ran the conversion alone. They
// disagreed for months, and CI always won: the swagger-docs-sync job
// regenerated the spec and committed ITS output to the PR branch, so a
// contributor following the documented workflow produced a ~44,000-line diff
// that CI then reverted.
//
// CI NO LONGER COMMITS (#999): a pull request whose generated docs have drifted
// now FAILS, and the contributor regenerates. That removes the "CI always wins"
// half of the story but makes this test matter more, not less — the human's
// output is now the only output, so a Makefile recipe that disagrees with the
// CI step is a pull request that cannot be made green by running the documented
// command.
//
// Neither output was wrong, exactly -- they were answers to different
// questions, and nothing compared them. The hoisting has since been removed
// (no consumer needed it: terraform-provider-registry generates models only,
// and the frontend reads swagger.json rather than openapi3.json), which makes
// them agree TODAY. This test is about tomorrow.
//
// THE PROPERTY, stated so it survives a rewrite of either side: neither the
// Makefile recipe nor the CI step may transform openapi3.json beyond the
// swagger2openapi invocation that produces it. The moment one of them grows a
// post-process the other lacks, the two diverge again and the loser is
// whichever a human ran.
//
// Deliberately NOT asserted: that the two command lines are textually
// identical. They legitimately differ -- the Makefile runs from the repo root
// with a node_modules/.bin path, CI runs from backend/ with ../node_modules.
// A textual comparison would fail on that difference and teach whoever hits it
// to delete the test.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// specArtifact is the file both sides produce.
const specArtifact = "openapi3.json"

// repoRoot walks up from this package to the directory holding the Makefile.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find the repository root (no Makefile found walking up)")
	return ""
}

// makefileOpenAPIRecipe returns the lines of the `openapi3:` target's recipe,
// comments and blank lines excluded.
//
// A make recipe is exactly the run of TAB-indented lines following the target,
// which is what makes this parseable without a make parser.
func makefileOpenAPIRecipe(t *testing.T, root string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	var recipe []string
	in := false
	for _, ln := range lines {
		if strings.HasPrefix(ln, "openapi3:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(ln, "\t") {
			break // the recipe ends at the first non-tab line
		}
		body := strings.TrimSpace(strings.TrimPrefix(ln, "\t"))
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}
		recipe = append(recipe, body)
	}
	if len(recipe) == 0 {
		t.Fatal("the openapi3 target has no recipe, or it was renamed. If it moved, point this " +
			"test at it -- do not delete it: it is what keeps `make swag` and CI from diverging (#947).")
	}
	return recipe
}

// ciSwaggerStep returns the shell body of ci.yml's "Swagger generation" step.
func ciSwaggerStep(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	s := string(b)
	i := strings.Index(s, "- name: Swagger generation")
	if i < 0 {
		t.Fatal("ci.yml has no \"Swagger generation\" step. If it was renamed, point this test at " +
			"the new name rather than deleting it (#947).")
	}
	rest := s[i:]
	// The step ends at the next step at the same indentation.
	if j := strings.Index(rest[1:], "\n      - name: "); j >= 0 {
		rest = rest[:j+1]
	}
	return rest
}

// writesSpecOutsideConversion reports the lines in body that touch
// openapi3.json for any reason OTHER than being swagger2openapi's -o argument.
func writesSpecOutsideConversion(body string) []string {
	conversion := regexp.MustCompile(`swagger2openapi\b`)
	var offenders []string
	for _, ln := range strings.Split(body, "\n") {
		if !strings.Contains(ln, specArtifact) {
			continue
		}
		if conversion.MatchString(ln) {
			continue // the line that legitimately produces it
		}
		trimmed := strings.TrimSpace(ln)
		// Comments explain; they do not transform.
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		offenders = append(offenders, trimmed)
	}
	return offenders
}

// TestMakefileDoesNotPostProcessTheSpec is one half of the parity property.
func TestMakefileDoesNotPostProcessTheSpec(t *testing.T) {
	root := repoRoot(t)
	recipe := makefileOpenAPIRecipe(t, root)

	if got := writesSpecOutsideConversion(strings.Join(recipe, "\n")); len(got) > 0 {
		t.Errorf("the Makefile's openapi3 target touches %s outside the swagger2openapi call:\n  %s\n\n"+
			"CI's \"Swagger generation\" step runs the conversion alone and its output is what gets "+
			"committed, so a transformation here is reverted -- and a contributor who runs `make swag` "+
			"gets a large diff CI throws away. That was #947.\n\n"+
			"If the transformation is genuinely needed (a consumer that generates a CLIENT or SERVER "+
			"from this spec does need path-level parameters), add it to BOTH sides in the same change.",
			specArtifact, strings.Join(got, "\n  "))
	}

	// And the conversion itself must still be there -- a target that produces
	// nothing would satisfy the check above trivially.
	if !strings.Contains(strings.Join(recipe, "\n"), "swagger2openapi") {
		t.Error("the openapi3 target no longer invokes swagger2openapi, so it produces no spec at all")
	}
}

// TestCIDoesNotPostProcessTheSpec is the other half.
//
// Checked in both directions on purpose: the divergence is symmetric, and a
// guard that only watched the Makefile would miss CI growing a step of its own.
func TestCIDoesNotPostProcessTheSpec(t *testing.T) {
	root := repoRoot(t)
	step := ciSwaggerStep(t, root)

	if got := writesSpecOutsideConversion(step); len(got) > 0 {
		t.Errorf("ci.yml's \"Swagger generation\" step touches %s outside the swagger2openapi call:\n  %s\n\n"+
			"`make openapi3` runs the conversion alone, so a transformation here means the committed "+
			"spec can never be reproduced locally (#947). Add it to the Makefile in the same change.",
			specArtifact, strings.Join(got, "\n  "))
	}
	if !strings.Contains(step, "swagger2openapi") {
		t.Error("the CI step no longer invokes swagger2openapi")
	}
}

// TestBothSidesPassTheSameConversionFlags catches the subtler divergence: the
// same tool, invoked differently.
//
// -p is `--patch`, which repairs spec defects during conversion. One side
// running with it and the other without produces two different valid specs,
// which is exactly the shape of #947 one level down.
func TestBothSidesPassTheSameConversionFlags(t *testing.T) {
	root := repoRoot(t)
	// The INVOCATION line, not merely a line mentioning the tool. The Makefile
	// also has `test -x node_modules/.bin/swagger2openapi`, an existence guard
	// whose -x is not a conversion flag -- the first draft of this test picked
	// that line up and reported a difference that was entirely its own.
	// Requiring the input file narrows it to the line that actually converts.
	isInvocation := func(ln string) bool {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			return false
		}
		return strings.Contains(t, "swagger2openapi") &&
			strings.Contains(t, "swagger.json") &&
			strings.Contains(t, specArtifact) &&
			!strings.HasPrefix(strings.TrimPrefix(t, "@"), "test ")
	}
	flags := func(body string) []string {
		for _, ln := range strings.Split(body, "\n") {
			if !isInvocation(ln) {
				continue
			}
			var out []string
			for _, tok := range strings.Fields(ln) {
				if strings.HasPrefix(tok, "-") && tok != "-o" {
					out = append(out, tok)
				}
			}
			return out
		}
		return nil
	}
	mk := flags(strings.Join(makefileOpenAPIRecipe(t, root), "\n"))
	ci := flags(ciSwaggerStep(t, root))

	if strings.Join(mk, " ") != strings.Join(ci, " ") {
		t.Errorf("swagger2openapi is invoked with different flags:\n  Makefile: %v\n  CI:       %v\n\n"+
			"The same tool with different flags produces different specs, which is #947 one level down.",
			mk, ci)
	}
	if len(mk) == 0 {
		t.Error("no conversion flags were extracted from either side; this test is not reading the " +
			"invocations it claims to compare")
	}
}
