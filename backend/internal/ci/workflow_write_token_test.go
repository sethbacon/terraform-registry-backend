package ci

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// GUARD no-write-token-in-pull-request-ci (issue #999).
//
// THE DEFECT THIS EXISTS FOR. ci.yml's swagger-docs-sync job held
// contents:write and pushed regenerated docs onto the pull request's own head
// branch. GitHub does not trigger workflow runs from a push made with
// GITHUB_TOKEN — the documented recursion guard, unconditional — so the head
// moved to a commit no workflow would ever run against. Branch protection
// evaluates required contexts against the head, so the pull request reported
// BLOCKED with an empty check list: nothing failed, and there was no run to
// re-run. It survived at least five pull requests, because they were
// admin-merged and the block is invisible if nobody waits on it.
//
// The write token is the root of both halves. It is what made the push
// possible, and it is what made the push unrunnable. It also ran on a checkout
// built from pull-request content, which ci.yml's own header calls out as the
// reason that job is isolated in the first place.
//
// THE RULE, stated so it survives a rewrite: no job that can run on a
// pull_request event may request `contents: write`. A job that needs it runs on
// push/schedule/dispatch and opens a bot pull request instead, which is what
// swagger-docs-sync now does.
//
// CONTENTS SPECIFICALLY, and the first draft of this guard got that wrong. It
// forbade any write scope and immediately flagged two jobs that are fine:
// pr-checks.yml's dependency-review holds `pull-requests: write` to post its
// review, and release-pr-guard.yml's closing-keywords holds `statuses: write`
// to set a commit status. Neither can move a branch head, so neither can
// produce the unrunnable head that #999 is. `contents: write` is the capability
// that does, and narrowing to it is what keeps this guard about a real defect
// rather than about tidiness — a guard that flags working jobs is one people
// route around and then delete.
//
// NOT COVERED, deliberately: `pull-requests: write` on a job that runs against
// pull-request content is its own hazard (a job that can approve or merge), and
// `actions: write` is another. They are different findings with different
// remedies, and folding them in here would mean this guard could not be green
// while they were open.
//
// THE `on:` KEY IS SOMETIMES THE BOOLEAN `true`, and this guard was inert until
// it handled that. YAML 1.1 reads the bare word `on` as a boolean, so a parser
// following that spec turns the trigger block's key into `true` — and this
// repository's files disagree with each other about it: pr-checks.yml,
// zizmor.yml and release-pr-guard.yml come back keyed "on", while ci.yml,
// release.yml, weekly-security.yml and six others come back keyed "true".
//
// The first version of this guard read only "on". It therefore saw no triggers
// at all in ci.yml — the file it exists for — and reported clean while three
// separate planted regressions walked past it. It also passed its own
// count floor, because the handful of files that did parse contributed enough
// jobs to clear it. That is the failure this package is supposed to prevent:
// "the scan found nothing" and "there is nothing to find" reading identically.
//
// Both keys are read below, and the floor is no longer a count alone — it names
// ci.yml, so a parsing change that hides the subject fails instead of passing.
//
// WHAT THIS CAN SEE. Every workflow file in .github/workflows, every job's
// `permissions` block, and the `if:` expression that may exclude a job from
// pull requests. It reads the committed configuration rather than a copy of it,
// which is this package's whole rule.
//
// WHAT IT CANNOT SEE, and is therefore not evidence about:
//   - permissions granted at the STEP level by an action's own token input
//     (a PAT or App token passed as `with: token:`). Those are invisible here
//     and are what option 1 of #999 would have introduced.
//   - reusable workflows called with `uses:`, whose permissions live in the
//     called file, possibly in another repository.
//   - a workflow_call invocation from a caller that runs on pull_request.
func TestNoWriteTokenInPullRequestCI(t *testing.T) {
	dir := workflowsDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	type finding struct{ file, job, perms string }
	var findings []finding
	var pullRequestFiles []string
	jobsInspected := 0
	filesInspected := 0

	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		var wf workflow
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		filesInspected++
		if !wf.runsOnPullRequest() {
			continue
		}
		pullRequestFiles = append(pullRequestFiles, e.Name())
		for name, job := range wf.Jobs {
			jobsInspected++
			if job.excludesPullRequests() {
				continue
			}
			if w := job.Permissions.contentsWrite(); w != "" {
				findings = append(findings, finding{e.Name(), name, w})
			}
		}
	}

	// A scan that read nothing reports no violations for the same reason a clean
	// one does — so the floor is not a count alone. It NAMES ci.yml, because a
	// count floor is exactly what the inert first version of this guard passed:
	// the files that happened to parse contributed enough jobs to clear it while
	// the subject of the guard was invisible.
	if filesInspected < 5 {
		t.Fatalf("inspected %d workflow files, expected at least 5 — the scan is not looking at what it thinks it is",
			filesInspected)
	}
	sort.Strings(pullRequestFiles)
	if !slices.Contains(pullRequestFiles, "ci.yml") {
		t.Fatalf("ci.yml was not recognised as running on pull requests; the scan saw %v.\n"+
			"ci.yml is the file this guard exists for. If its triggers stopped parsing — the `on:` key is read "+
			"as the boolean `true` by a YAML 1.1 parser, which is why both spellings are handled — then this "+
			"guard is inspecting nothing and would report clean against the very regression it was written for.",
			pullRequestFiles)
	}
	if jobsInspected < 10 {
		t.Fatalf("inspected %d pull-request-reachable jobs, expected at least 10 — either every job now excludes "+
			"pull requests, or the `if:` parsing has started excluding everything", jobsInspected)
	}

	if len(findings) > 0 {
		sort.Slice(findings, func(i, j int) bool { return findings[i].file+findings[i].job < findings[j].file+findings[j].job })
		var b strings.Builder
		for _, f := range findings {
			b.WriteString("\n  " + f.file + " job " + f.job + " requests: " + f.perms)
		}
		t.Fatalf("these jobs can run on a pull request AND can write refs:%s\n\n"+
			"A write token in pull-request CI is what issue #999 was: the job pushed to the pull request's own "+
			"head branch, GitHub triggered no run for a push made with GITHUB_TOKEN, and the pull request sat "+
			"BLOCKED against a head that reported no checks at all. Either drop the permission, or gate the job "+
			"off pull requests (`if: github.event_name != 'pull_request'`) and have it open a bot pull request "+
			"the way swagger-docs-sync does.", b.String())
	}
}

// workflowsDir walks up from this package to .github/workflows.
func workflowsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, ".github", "workflows")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find .github/workflows above the test's working directory")
	return ""
}

// workflow is the subset of a workflow file this guard reads.
//
// BOTH trigger keys are declared. `On` catches the files whose key survives as
// the string "on"; `OnBool` catches the ones a YAML 1.1 parser turns into the
// boolean `true`. Reading only the first is what made this guard inert.
//
// Both are typed as free values: GitHub accepts the trigger block as a string
// ("on: push"), a list ("on: [push, pull_request]") and a map, and a struct
// that modelled only one of those would silently treat the others as "no
// triggers" — a guard that inspects nothing.
type workflow struct {
	On     interface{}    `json:"on"`
	OnBool interface{}    `json:"true"`
	Jobs   map[string]job `json:"jobs"`
}

// triggers returns whichever of the two spellings this file actually used.
func (w workflow) triggers() interface{} {
	if w.On != nil {
		return w.On
	}
	return w.OnBool
}

type job struct {
	If          interface{} `json:"if"`
	Permissions permissions `json:"permissions"`
}

// permissions models both spellings GitHub accepts: a map of scopes, or the
// shorthand strings `write-all` / `read-all` / `{}`.
type permissions struct {
	scopes map[string]string
	all    string
}

func (p *permissions) UnmarshalJSON(b []byte) error {
	var asString string
	if err := yaml.Unmarshal(b, &asString); err == nil {
		p.all = asString
		return nil
	}
	var asMap map[string]string
	if err := yaml.Unmarshal(b, &asMap); err != nil {
		return err
	}
	p.scopes = asMap
	return nil
}

// contentsWrite reports how this job asks for the ability to write refs, or ""
// when it does not.
//
// A job with NO permissions block returns "", and that is correct rather than a
// gap: the repository-level default applies, and this repository sets it to
// read-only. A guard that flagged an absent block would fail every job in the
// tree and be deleted within the week.
func (p permissions) contentsWrite() string {
	if p.all == "write-all" {
		return "write-all (includes contents)"
	}
	if p.scopes["contents"] == "write" {
		return "contents: write"
	}
	return ""
}

// runsOnPullRequest reports whether the workflow declares a pull_request or
// pull_request_target trigger.
func (w workflow) runsOnPullRequest() bool {
	switch on := w.triggers().(type) {
	case string:
		return isPullRequestEvent(on)
	case []interface{}:
		for _, e := range on {
			if s, ok := e.(string); ok && isPullRequestEvent(s) {
				return true
			}
		}
	case map[string]interface{}:
		for k := range on {
			if isPullRequestEvent(k) {
				return true
			}
		}
	}
	return false
}

func isPullRequestEvent(name string) bool {
	return name == "pull_request" || name == "pull_request_target"
}

// excludesPullRequests reports whether a job's `if:` expression keeps it off
// pull requests.
//
// Deliberately NARROW: it recognises the two spellings this repository uses and
// treats anything else as "still reachable". An expression evaluator here would
// be a second implementation of GitHub's, and the failure direction of getting
// it wrong is a job wrongly believed to be excluded — which is the guard
// reporting clean about the exact thing it exists to catch. Being too strict
// costs a comment; being too clever costs the guard.
func (j job) excludesPullRequests() bool {
	expr, ok := j.If.(string)
	if !ok {
		return false
	}
	normalized := strings.Join(strings.Fields(strings.ReplaceAll(expr, `"`, "'")), " ")
	for _, form := range []string{
		"github.event_name != 'pull_request'",
		"github.event_name == 'push'",
		"github.event_name == 'schedule'",
		"github.event_name == 'workflow_dispatch'",
	} {
		if strings.Contains(normalized, form) {
			return true
		}
	}
	return false
}
