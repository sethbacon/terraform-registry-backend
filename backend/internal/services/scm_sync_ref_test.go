package services

// scm_sync_ref_test.go covers pinning a manual sync to a ref (#879).
//
// WHAT THIS FIXES. A sync imported whatever the configured tag pattern resolved
// to AT SYNC TIME, so between a workflow's checkout and the registry's fetch
// there was a window in which a force-moved tag changed what got published
// while the publisher still reported success. The caller could not close that
// window, because it had no way to say which ref it meant.
//
// The interesting cases are all about a tag that moved, so that is what most of
// these are.

import (
	"errors"
	"strings"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

func TestSameCommitAcceptsAnAbbreviation(t *testing.T) {
	const full = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	for _, tc := range []struct {
		name     string
		actual   string
		asserted string
		want     bool
	}{
		{"identical", full, full, true},
		{"short asserted", full, full[:7], true},
		{"short asserted, longer", full, full[:12], true},
		{"case differs", full, strings.ToUpper(full), true},
		{"whitespace", full, "  " + full + "\n", true},
		{"different commit", full, "0000000000000000000000000000000000000000", false},
		{"different at the 8th char", full, full[:7] + "f", false},
		// Shorter than 7 is refused: it identifies too many commits to be an
		// assertion about one, and accepting it would make the pin look
		// stronger than it is.
		{"too short to mean anything", full, full[:6], false},
		{"empty asserted", full, "", false},
		{"empty actual", "", full, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameCommit(tc.actual, tc.asserted); got != tc.want {
				t.Errorf("sameCommit(%q, %q) = %v, want %v", tc.actual, tc.asserted, got, tc.want)
			}
		})
	}
}

// TestSameCommitIsNotSubstringMatching is the trap this comparison invites.
//
// A prefix test is correct; a `strings.Contains` is not. An asserted SHA that
// appears in the MIDDLE of the actual one identifies nothing, and accepting it
// would let a wrong commit pass the pin.
func TestSameCommitIsNotSubstringMatching(t *testing.T) {
	const actual = "aaaaaaa1234567bbbbbbb"
	if sameCommit(actual, "1234567") {
		t.Error("a SHA matched in the middle of another. The comparison must be a prefix test: " +
			"an abbreviation identifies a commit by its leading characters, and matching anywhere " +
			"lets an unrelated commit satisfy the pin.")
	}
}

// TestErrRefMovedIsDistinctFromNotFound. The handler maps one to 409 and the
// other to 404, and a publisher needs to tell "your tag moved" from "your tag
// does not exist" -- they call for different actions.
func TestErrRefMovedIsDistinctFromNotFound(t *testing.T) {
	if errors.Is(ErrRefMoved, ErrRefNotFound) || errors.Is(ErrRefNotFound, ErrRefMoved) {
		t.Fatal("the two ref errors are not distinguishable, so the handler cannot map them to " +
			"different status codes")
	}
}

// TestZeroSyncRefMeansEveryTag pins backwards compatibility: every existing
// caller passes no ref and must keep getting a full sync.
func TestZeroSyncRefMeansEveryTag(t *testing.T) {
	var ref SyncRef
	if ref.TagName != "" || ref.CommitSHA != "" {
		t.Fatal("the zero SyncRef is not empty, so an unpinned sync would be narrowed by accident")
	}
}

// TestSyncRefAdmits covers the narrowing itself.
//
// Extracted from TriggerManualSyncRef, which is integration-only: a mutation
// that deleted the tag filter entirely went undetected until this test existed,
// because nothing could reach the loop without a live SCM connector.
func TestSyncRefAdmits(t *testing.T) {
	const sha = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	tag := func(name, commit string) *scm.GitTag { return &scm.GitTag{TagName: name, TargetCommit: commit} }

	for _, tc := range []struct {
		name        string
		ref         SyncRef
		tag         *scm.GitTag
		wantInclude bool
		wantMoved   bool
	}{
		{
			name:        "unpinned admits everything",
			ref:         SyncRef{},
			tag:         tag("v9.9.9", sha),
			wantInclude: true,
		},
		{
			name:        "the named tag",
			ref:         SyncRef{TagName: "v1.2.3"},
			tag:         tag("v1.2.3", sha),
			wantInclude: true,
		},
		{
			// Skipped, not an error: it is simply not the tag asked for, and
			// the loop must carry on to find the one that is.
			name:        "a different tag is skipped",
			ref:         SyncRef{TagName: "v1.2.3"},
			tag:         tag("v1.2.4", sha),
			wantInclude: false,
		},
		{
			name:        "the named tag at the asserted commit",
			ref:         SyncRef{TagName: "v1.2.3", CommitSHA: sha},
			tag:         tag("v1.2.3", sha),
			wantInclude: true,
		},
		{
			name:        "abbreviated assertion still matches",
			ref:         SyncRef{TagName: "v1.2.3", CommitSHA: sha[:8]},
			tag:         tag("v1.2.3", sha),
			wantInclude: true,
		},
		{
			// THE CASE THIS FEATURE EXISTS FOR. An error, not a skip: skipping
			// would leave the sync reporting success having published nothing,
			// which is indistinguishable from the tag not matching the pattern.
			name:      "the named tag has moved",
			ref:       SyncRef{TagName: "v1.2.3", CommitSHA: sha},
			tag:       tag("v1.2.3", "0000000000000000000000000000000000000000"),
			wantMoved: true,
		},
		{
			name:        "a nil tag is skipped, not a panic",
			ref:         SyncRef{TagName: "v1.2.3"},
			tag:         nil,
			wantInclude: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			include, err := tc.ref.admits(tc.tag)
			if tc.wantMoved {
				if !errors.Is(err, ErrRefMoved) {
					t.Fatalf("err = %v, want ErrRefMoved. A tag that moved must stop the sync, not "+
						"be silently skipped -- a skip reports success having published nothing.", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if include != tc.wantInclude {
				t.Errorf("include = %v, want %v", include, tc.wantInclude)
			}
		})
	}
}

// TestSawNamedRef covers the helper behind "you named a tag that does not
// exist".
//
// A KNOWN GAP, stated rather than left implicit: this covers the helper, not
// its CALL SITE. The call lives inside TriggerManualSyncRef, which is
// coverage:skip:integration-only -- it needs a live SCM connector -- so a
// mutation that deletes the call itself is not caught by anything here. That
// was verified, not assumed: `if ref.TagName != "" && !sawNamedRef(...)`
// replaced with `if false` passes this whole package.
//
// The consequence if it regressed: a sync pinned to a tag that does not exist
// would report 202 and publish nothing, silently. Closing it properly needs a
// connector fake, which is a larger change than this feature.
func TestSawNamedRef(t *testing.T) {
	tags := []*scm.GitTag{
		{TagName: "v1.0.0", TargetCommit: "aaa"},
		nil, // a connector may yield a nil entry; this must not panic
		{TagName: "v1.2.3", TargetCommit: "bbb"},
	}
	if !sawNamedRef(tags, "v1.2.3") {
		t.Error("an existing tag was not found")
	}
	if sawNamedRef(tags, "v9.9.9") {
		t.Error("a tag that is not present was reported as found, so a sync pinned to a " +
			"nonexistent ref would report success having published nothing")
	}
	if sawNamedRef(nil, "v1.0.0") {
		t.Error("an empty tag list reported a match")
	}
}
