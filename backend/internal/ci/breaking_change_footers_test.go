package ci

// Mutation self-test for the "Breaking-change footers survive the squash" job
// in .github/workflows/pr-checks.yml.
//
// That guard decides whether a pull request may merge, and it is a bash script
// living inside YAML. actionlint checks its syntax, zizmor checks the workflow
// around it, and until this file nothing ever RAN it — so a regex edit, a lost
// `set -euo pipefail`, or a silently renamed job would leave the check
// reporting green over a script that had stopped deciding anything.
//
// HOW. The `run:` block is EXTRACTED from the committed workflow rather than
// copied into this file. A copy would drift from the thing it claims to prove,
// which is the same defect one level up. `gh` is stubbed with a script that
// prints a fixture commit history, so no network, no token and no repository
// are involved.
//
// THE CASE THAT MATTERS is fail-closed, and it is the only one a lost
// `set -euo pipefail` fails. Without that line the failed `gh api` still
// creates an empty commits.ndjson through the redirect, the loop counts
// nothing, and the job prints "Breaking-change declarations in this PR: 0" and
// exits 0 — a required-shaped check that has stopped looking, and
// indistinguishable from a clean pull request. Every other case here runs
// against a `gh` that succeeds, so none of them can see it.
//
// VACUITY. If the job, or its `run:` block, cannot be found, this test FAILS.
// A self-test that quietly passes over a guard it could not locate is the
// failure mode it exists to prevent.
//
// ONE CAVEAT worth knowing locally. The workflow is outside this module's root
// (the module is backend/, the workflow is the repository's), and `go test`'s
// result cache does not treat a file read from there as an input: edit the
// guard, change no Go file, and a plain `go test ./internal/ci/` will replay a
// cached PASS. CI is unaffected because the "Backend Tests & Quality" job runs
// `go clean -testcache` immediately before `go test`. When exercising a change
// to the guard by hand, pass `-count=1`.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	// Relative to this package directory: backend/internal/ci -> repository root.
	footerGuardWorkflow = "../../../.github/workflows/pr-checks.yml"
	footerGuardJobKey   = "breaking-change-footers"
	footerGuardRepo     = "sethbacon/terraform-registry-backend"

	// The line the guard prints when it counts nothing. Asserting on it, and not
	// only on the exit code, is what separates "failed closed" from "crashed for
	// an unrelated reason while still reporting a clean count".
	footerGuardZeroCount = "declarations in this PR: 0"
)

var (
	footerGuardJobHeaderRE = regexp.MustCompile(`^ {2}[A-Za-z0-9_.-]+:\s*$`)
	footerGuardRunBlockRE  = regexp.MustCompile(`^\s+run:\s*\|\s*$`)
	footerGuardIndentRE    = regexp.MustCompile(`^(\s+)`)
)

// extractFooterGuard returns the dedented body of the first `run: |` block
// inside job key, read out of the workflow at path. Every failure path calls
// t.Fatalf: not finding the guard is a failure, not a pass.
func extractFooterGuard(t *testing.T, path, key string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nthe guard this test exists to prove could not be read, which is a failure and not a pass", path, err)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	start := -1
	for i, line := range lines {
		if line == "  "+key+":" {
			start = i
			break
		}
	}
	if start == -1 {
		t.Fatalf("no job `%s:` in %s\nthe guard is gone or has been renamed, which is a failure and not a pass", key, path)
	}

	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if footerGuardJobHeaderRE.MatchString(lines[i]) {
			end = i
			break
		}
	}
	body := lines[start:end]

	runAt := -1
	for i, line := range body {
		if footerGuardRunBlockRE.MatchString(line) {
			runAt = i
			break
		}
	}
	if runAt == -1 {
		t.Fatalf("job `%s` in %s has no `run: |` block", key, path)
	}

	// The indent comes from the first NON-BLANK line of the block. Reading it
	// from runAt+1 unconditionally would turn a block that merely opens with a
	// blank line — which is what deleting the `set -euo pipefail` line leaves
	// behind — into "block is empty", and this test would then report that
	// instead of running its cases against the guard it still has.
	first := runAt + 1
	for first < len(body) && strings.TrimSpace(body[first]) == "" {
		first++
	}
	var indent string
	if first < len(body) {
		if m := footerGuardIndentRE.FindStringSubmatch(body[first]); m != nil {
			indent = m[1]
		}
	}
	if indent == "" {
		t.Fatalf("job `%s`'s `run: |` block in %s is empty", key, path)
	}

	var script []string
	for i := runAt + 1; i < len(body); i++ {
		line := body[i]
		if strings.TrimSpace(line) == "" {
			script = append(script, "")
			continue
		}
		if !strings.HasPrefix(line, indent) {
			break
		}
		script = append(script, strings.TrimPrefix(line, indent))
	}
	return strings.Join(script, "\n")
}

// footerGuardHarness runs the extracted guard against fixture commit histories.
type footerGuardHarness struct {
	scriptPath string
	// workingGH prints the fixture history the case supplies.
	workingGH string
	// failingGH exits non-zero with a 403 on stderr, the way the real `gh` does
	// on an API error, a revoked token or a rate limit.
	failingGH string
	seq       int
}

func newFooterGuardHarness(t *testing.T) *footerGuardHarness {
	t.Helper()

	script := extractFooterGuard(t, footerGuardWorkflow, footerGuardJobKey)
	root := t.TempDir()

	scriptPath := filepath.Join(root, "guard.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write the extracted guard: %v", err)
	}

	stub := func(name, body string) string {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(body), 0o700); err != nil {
			t.Fatalf("write the %s `gh` stub: %v", name, err)
		}
		return dir
	}

	return &footerGuardHarness{
		scriptPath: scriptPath,
		workingGH:  stub("bin", "#!/bin/sh\ncat \"$FIXTURE_COMMITS\"\n"),
		failingGH:  stub("bin-failing", "#!/bin/sh\necho \"gh: HTTP 403: Resource not accessible by integration\" >&2\nexit 1\n"),
		seq:        0,
	}
}

type footerGuardResult struct {
	exitCode int
	output   string
	summary  string
}

func (h *footerGuardHarness) run(t *testing.T, ghDir string, commits ...string) footerGuardResult {
	t.Helper()

	h.seq++
	dir := t.TempDir()

	var fixture bytes.Buffer
	for i, msg := range commits {
		line, err := json.Marshal(struct {
			SHA string `json:"sha"`
			Msg string `json:"msg"`
		}{SHA: fmt.Sprintf("abc00%d", i), Msg: msg})
		if err != nil {
			t.Fatalf("encode fixture commit %d: %v", i, err)
		}
		fixture.Write(line)
		fixture.WriteByte('\n')
	}
	fixturePath := filepath.Join(dir, "commits.json")
	if err := os.WriteFile(fixturePath, fixture.Bytes(), 0o600); err != nil {
		t.Fatalf("write the fixture history: %v", err)
	}
	summaryPath := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(summaryPath, nil, 0o600); err != nil {
		t.Fatalf("create the job-summary file: %v", err)
	}

	cmd := exec.Command("bash", h.scriptPath)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + ghDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"FIXTURE_COMMITS=" + fixturePath,
		"GH_TOKEN=stub",
		"PR_NUMBER=123",
		"REPO=" + footerGuardRepo,
		"GITHUB_STEP_SUMMARY=" + summaryPath,
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run the extracted guard: %v\n%s", err, out.String())
		}
		exitCode = exitErr.ExitCode()
	}

	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read the job summary: %v", err)
	}

	return footerGuardResult{exitCode: exitCode, output: out.String(), summary: string(summary)}
}

func (r footerGuardResult) mustSay(t *testing.T, label string, phrases ...string) {
	t.Helper()
	for _, p := range phrases {
		if !strings.Contains(r.output, p) {
			t.Errorf("%s: the guard never said %q\n--- output ---\n%s", label, p, r.output)
		}
	}
}

func (r footerGuardResult) mustSummarise(t *testing.T, label string, phrases ...string) {
	t.Helper()
	for _, p := range phrases {
		if !strings.Contains(r.summary, p) {
			t.Errorf("%s: the job summary a reviewer reads never mentioned %q\n--- summary ---\n%s", label, p, r.summary)
		}
	}
}

// footerGuardAbacdb5Body is the verbatim body of
// sethbacon/azure-pipelines-terraform@abacdb5 -- the commit that ADDED that
// repository's copy of this guard. One sentence in it NAMES the hyphenated
// spelling of the token, mid-line, as prose describing what the guard detects.
// release-please read that as a real declaration, took the remainder of the line
// as the description, and proposed 2.0.0 over a 1.14.4 release whose honest
// successor was 1.14.5 -- with a changelog entry reading "` spelling". The guard,
// counting only line-anchored matches, said 0 and let it through.
//
// It is load bearing that this is the WHOLE body and not just that sentence: the
// body ALSO names the SPACED spelling mid-line, which release-please does not
// read. The only count that is right for it is 1.
var footerGuardAbacdb5Body = strings.Join([]string{
	"ci: count breaking-change declarations across the commits being squashed (#974)",
	"",
	"This repo squash-merges with `squash_merge_commit_message=COMMIT_MESSAGES`",
	"(re-verified on the live repo), so every commit body in a PR is concatenated",
	"into ONE merge commit -- and release-please keeps only the FIRST",
	"`BREAKING CHANGE:` footer of that commit, reading a `!` marker only from its",
	"header. A second declaration anywhere in the PR is dropped in silence: no",
	"changelog entry, no upgrade note, and nothing failing to say so.",
	"terraform-registry-backend v4.0.0 shipped two undocumented breaking changes",
	"exactly this way, and it reaches further from here: this extension publishes to",
	"the VS Marketplace, where the release notes are a pipeline author's only signal",
	"that a task changed incompatibly, and ADO agents cache tasks by Major.Minor.",
	"",
	"Five other suite repos carry this guard; the two ADO extensions did not. The",
	"only `BREAKING` matches here were prose inside",
	"`.github/commit-message-check/verify.mjs`, which parses the SINGLE message this",
	"PR would squash and asks whether release-please can read it at all -- it never",
	"counts declarations across the set being concatenated. The two are the halves of",
	"one pair and neither subsumes the other: a perfectly parseable squash can still",
	"swallow a second footer, and a single-footer PR can still be unparseable.",
	"",
	"Ported from `azure-pipelines-release-docs`, which took it from",
	"`terraform-registry-backend` and added the self-test. The self-test EXTRACTS the",
	"bash out of pr-checks.yml rather than copying it -- a copy drifts from the thing",
	"it claims to prove, which is the same defect one level up -- and runs it against",
	"fixture commit histories with `gh` stubbed. It runs in the already-required",
	"`Lint GitHub Actions` job, so the proof blocks a merge from the day it lands.",
	"",
	"Mutation-proved against the committed workflow, each rejection asserted by name:",
	"two footers, two `!` headers, three footers and the `BREAKING-CHANGE:` spelling",
	"are rejected; the single-declaration, no-declaration, many-clean-commits,",
	"prose-mention and footer-plus-`!`-in-one-commit shapes pass untouched. Five",
	"mutations of the guard were each seen failing the test: dropping the hyphen",
	"spelling, making the footer and `!` additive, raising the threshold to 2,",
	"renaming the job (the vacuity contract), and dropping `set -euo pipefail`.",
	"",
	"That last one is a case the source implementation could not see, so this port",
	"adds it: without `set -euo pipefail` a failed `gh api` leaves an empty commit",
	"list behind and the job reports \"declarations in this PR: 0\" and goes green. The",
	"new `gh-unavailable` case stubs a failing `gh` and requires the guard to fail",
	"closed.",
	"",
	"No task.json touched, and no existing job renamed or split.",
	"",
	"BRANCH PROTECTION: this adds one NEW context, `Breaking-change footers survive",
	"the squash`, which has to be added to main's required checks by hand. Until then",
	"the job reports on every PR without blocking one -- the same state as",
	"`release-please can read the merged commit`, the other half of the pair.",
	"",
	"Closes #966",
}, "\n")

const footerGuardFooter = "BREAKING CHANGE: the module upload response shape changed"

func TestBreakingChangeFooterGuard(t *testing.T) {
	h := newFooterGuardHarness(t)

	t.Run("the extracted script is the real guard", func(t *testing.T) {
		script := extractFooterGuard(t, footerGuardWorkflow, footerGuardJobKey)
		// An empty or truncated extraction would "pass" every case below.
		if lines := strings.Count(script, "\n"); lines < 20 {
			t.Fatalf("extracted only %d lines; that is not the guard", lines+1)
		}
		// Both halves of the rule, because they are DIFFERENT rules: the spaced
		// spelling counts only at the start of a line, the hyphenated one anywhere
		// in the body. A script matching one but not the other proves nothing.
		for _, want := range []string{
			"grep -cE '^BREAKING CHANGE:'",
			"grep -oF 'BREAKING-CHANGE:'",
			"gh api --paginate",
			"GITHUB_STEP_SUMMARY",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("the extracted script does not contain %q, so the cases below prove nothing", want)
			}
		}
	})

	t.Run("pull requests it must not obstruct", func(t *testing.T) {
		t.Run("declares nothing", func(t *testing.T) {
			r := h.run(t, h.workingGH, "fix: correct the namespace ownership check")
			r.mustSay(t, "clean-none", footerGuardZeroCount, "at most one declaration")
			if r.exitCode != 0 {
				t.Errorf("clean-none: exited %d on a pull request it must accept\n%s", r.exitCode, r.output)
			}
		})

		t.Run("declares exactly one, which the squash can carry", func(t *testing.T) {
			r := h.run(t, h.workingGH, "feat: rework the module upload response\n\n"+footerGuardFooter)
			r.mustSay(t, "clean-single", "declarations in this PR: 1")
			if r.exitCode != 0 {
				t.Errorf("clean-single: exited %d on a pull request it must accept\n%s", r.exitCode, r.output)
			}
		})

		t.Run("many commits, none of them breaking", func(t *testing.T) {
			r := h.run(t, h.workingGH, "ci: pin an action", "docs: fix a link", "test: cover the parser")
			r.mustSay(t, "clean-many-commits", footerGuardZeroCount)
			if r.exitCode != 0 {
				t.Errorf("clean-many-commits: exited %d on a pull request it must accept\n%s", r.exitCode, r.output)
			}
		})

		t.Run("a footer and a bang in ONE commit is ONE declaration", func(t *testing.T) {
			// release-please reads the footer; the `!` is the marker FOR it.
			// Counting them additively would fail the most ordinary way to write
			// a breaking change, and a guard that fires on correct usage is a
			// guard people learn to route around.
			r := h.run(t, h.workingGH, "feat!: rework the module upload response\n\n"+footerGuardFooter)
			r.mustSay(t, "footer-plus-bang-one-commit", "declarations in this PR: 1")
			if r.exitCode != 0 {
				t.Errorf("footer-plus-bang-one-commit: exited %d on a pull request it must accept\n%s", r.exitCode, r.output)
			}
		})

		// CORRECTED. This case used to assert that ANY mid-line mention is prose,
		// and it pinned a model release-please does not implement. Only the SPACED
		// spelling is ignored mid-line; the hyphenated one is matched anywhere, and
		// asserting otherwise is exactly what let abacdb5 through -- that body is
		// rejected below. What survives here is the half that is TRUE, and it has
		// to survive: a guard that failed a sentence release-please reads as prose
		// would be routed around and then deleted.
		//
		// The mention is in the BODY. The old fixture was a single-line message, so
		// it never exercised the body at all.
		t.Run("a mid-line mention of the SPACED spelling is prose, as release-please reads it", func(t *testing.T) {
			r := h.run(t, h.workingGH, "docs: explain the footer rule\n\n"+
				"A line that merely says BREAKING CHANGE: in the middle of a\n"+
				"sentence is prose, and release-please never reads it as a footer.")
			r.mustSay(t, "prose-mention", footerGuardZeroCount)
			if r.exitCode != 0 {
				t.Errorf("prose-mention: exited %d on a pull request it must accept\n%s", r.exitCode, r.output)
			}
		})

		// The hyphenated spelling written as a REAL footer is a real declaration,
		// and one of them is what the squash can carry. Rejecting it would be the
		// over-count mirror of the bug this change fixes, and an over-counting
		// guard gets bypassed and then deleted just as surely as a blind one.
		t.Run("a single hyphenated footer is a legitimate declaration", func(t *testing.T) {
			r := h.run(t, h.workingGH, "feat: rework the module upload response\n\nBREAKING-CHANGE: the input is no longer optional")
			r.mustSay(t, "hyphenated-footer-alone", "declarations in this PR: 1")
			if r.exitCode != 0 {
				t.Errorf("hyphenated-footer-alone: exited %d on a pull request it must accept\n%s", r.exitCode, r.output)
			}
		})
	})

	t.Run("pull requests whose squash would drop a declaration", func(t *testing.T) {
		t.Run("two footers, named in the job summary", func(t *testing.T) {
			// THE case: this repository's own v4.0.0 published two breaking
			// changes and documented one.
			r := h.run(t, h.workingGH,
				"feat: drop the legacy download route\n\n"+footerGuardFooter,
				"feat: require an org scope on publish\n\nBREAKING CHANGE: unscoped publish is gone",
			)
			if r.exitCode == 0 {
				t.Errorf("two-footers: exited 0 on a pull request that would lose a breaking change\n%s", r.output)
			}
			r.mustSay(t, "two-footers", "declares 2 breaking changes", "the squash keeps only the first")
			r.mustSummarise(t, "two-footers", "**2** breaking changes", "abc000", "abc001")
		})

		t.Run("two bang headers count the same as two footers", func(t *testing.T) {
			r := h.run(t, h.workingGH,
				"feat!: drop the legacy download route",
				"fix(publish)!: require an org scope",
			)
			if r.exitCode == 0 {
				t.Errorf("two-bang-headers: exited 0 on a pull request that would lose a breaking change\n%s", r.output)
			}
			r.mustSay(t, "two-bang-headers", "declares 2 breaking changes")
			r.mustSummarise(t, "two-bang-headers", "drop the legacy download route", "require an org scope")
		})

		t.Run("BREAKING-CHANGE is the same token as BREAKING CHANGE", func(t *testing.T) {
			// Both spellings are the spec's. A guard blind to the hyphen would be
			// routed around by the first person who writes it that way.
			r := h.run(t, h.workingGH,
				"feat: drop the legacy download route\n\n"+footerGuardFooter,
				"feat: require an org scope on publish\n\nBREAKING-CHANGE: unscoped publish is gone",
			)
			if r.exitCode == 0 {
				t.Errorf("hyphen-spelling: exited 0 on a pull request that would lose a breaking change\n%s", r.output)
			}
			r.mustSay(t, "hyphen-spelling", "declares 2 breaking changes")
		})

		t.Run("three footers, and it says how many would ship undocumented", func(t *testing.T) {
			r := h.run(t, h.workingGH,
				"feat: a\n\n"+footerGuardFooter,
				"feat: b\n\nBREAKING CHANGE: b changed",
				"feat: c\n\nBREAKING CHANGE: c changed",
			)
			if r.exitCode == 0 {
				t.Errorf("three-footers: exited 0 on a pull request that would lose two breaking changes\n%s", r.output)
			}
			r.mustSay(t, "three-footers", "declares 3 breaking changes")
			r.mustSummarise(t, "three-footers", "The other 2 would ship with no changelog entry")
		})
		// THE regression, and the reason this file changed. abacdb5 is the commit
		// that ADDED this guard in azure-pipelines-terraform; a sentence in its
		// body naming the hyphenated spelling was read by release-please as a
		// declaration, which proposed 2.0.0 over 1.14.4 with a changelog entry
		// reading "` spelling". The guard counted it 0 and passed it.
		//
		// The count asserted here is 1, and that number is load bearing in BOTH
		// directions: 0 is the under-count that shipped, and 2 is what merely
		// un-anchoring the old expression would give, because this body also names
		// the spaced spelling mid-line and release-please does not read that.
		t.Run("abacdb5, the accidental declaration that got through", func(t *testing.T) {
			r := h.run(t, h.workingGH, footerGuardAbacdb5Body)
			if r.exitCode == 0 {
				t.Errorf("abacdb5-accidental-declaration: exited 0 on a body release-please reads as breaking\n%s", r.output)
			}
			r.mustSay(t, "abacdb5-accidental-declaration", "declarations in this PR: 1", "off the start of a line")
			r.mustSummarise(t, "abacdb5-accidental-declaration", "A breaking change nobody declared")
		})

		// Two of them in one PR: two notes, and the squash keeps one. This is the
		// shape the old prose-mention assertion declared acceptable.
		t.Run("two mid-line mentions are two declarations", func(t *testing.T) {
			r := h.run(t, h.workingGH,
				"docs: describe the footer rule\n\nprose naming BREAKING-CHANGE: once",
				"docs: describe it again\n\nmore prose naming BREAKING-CHANGE: twice",
			)
			if r.exitCode == 0 {
				t.Errorf("two-mid-line-mentions: exited 0 on a pull request that would lose a breaking change\n%s", r.output)
			}
			r.mustSay(t, "two-mid-line-mentions", "declarations in this PR: 2", "off the start of a line")
		})
	})

	t.Run("it fails closed when it cannot read the commit list", func(t *testing.T) {
		// `set -euo pipefail` is the whole of this property, and this is the only
		// case in the file that notices when it goes. Both assertions are load
		// bearing: a non-zero exit for an unrelated reason would satisfy the
		// status alone while the guard still reported a clean count.
		r := h.run(t, h.failingGH, "feat: anything at all")
		if strings.Contains(r.output, footerGuardZeroCount) {
			t.Errorf("gh-unavailable: an unreadable commit list was counted as zero declarations, "+
				"so this check would report green over a history it never saw\n--- output ---\n%s", r.output)
		}
		if r.exitCode == 0 {
			t.Errorf("gh-unavailable: exited 0 when `gh` failed, so an unreadable commit list passes as clean\n--- output ---\n%s", r.output)
		}
	})
}
