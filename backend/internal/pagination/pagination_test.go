package pagination

import (
	"math"
	"strconv"
	"testing"
)

func TestClampPerPage(t *testing.T) {
	tests := []struct {
		name      string
		requested int
		want      int
	}{
		// The defect this package exists for: issue #893. Before the fix every
		// one of these over-maximum cases returned the DEFAULT of 20, so a
		// caller asking for 200 got fewer rows than one asking for 50.
		{"above the maximum clamps to the maximum, not the default", 200, 100},
		{"one above the maximum clamps to the maximum", 101, 100},
		{"the maximum itself is served whole", 100, 100},
		{"an in-range size is served unchanged", 57, 57},
		{"one is a legitimate page size", 1, 1},

		// The other direction, which was always right and stays right.
		{"zero means no preference and takes the default", 0, 20},
		{"a negative size takes the default", -5, 20},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClampPerPage(tc.requested, 20, 100); got != tc.want {
				t.Errorf("ClampPerPage(%d, 20, 100) = %d, want %d", tc.requested, got, tc.want)
			}
		})
	}
}

// TestClampPerPage_AtoiFailureModes pins the two ways a query parameter reaches
// ClampPerPage without being a plain in-range integer, because every caller
// discards strconv.Atoi's error and relies on this function to absorb both.
func TestClampPerPage_AtoiFailureModes(t *testing.T) {
	t.Run("unparseable takes the default", func(t *testing.T) {
		n, err := strconv.Atoi("all-of-them")
		if err == nil {
			t.Fatal("expected a parse error for the fixture")
		}
		if got := ClampPerPage(n, 20, 100); got != 20 {
			t.Errorf("ClampPerPage(%d, 20, 100) = %d, want 20", n, got)
		}
	})

	t.Run("overflowing takes the maximum", func(t *testing.T) {
		// Atoi returns math.MaxInt *and* ErrRange here. Discarding the error
		// therefore leaves a value above every maximum in this repo, which must
		// clamp DOWN to the maximum rather than fall back to the default —
		// otherwise "?per_page=99999999999999999999" is the #893 defect again.
		n, err := strconv.Atoi("99999999999999999999")
		if err == nil {
			t.Fatal("expected a range error for the fixture")
		}
		if n != math.MaxInt {
			t.Fatalf("Atoi range failure returned %d, want math.MaxInt — this test's premise changed", n)
		}
		if got := ClampPerPage(n, 20, 100); got != 100 {
			t.Errorf("ClampPerPage(math.MaxInt, 20, 100) = %d, want 100", got)
		}
	})
}

func TestClampPage(t *testing.T) {
	for requested, want := range map[int]int{-3: 1, 0: 1, 1: 1, 9: 9} {
		if got := ClampPage(requested); got != want {
			t.Errorf("ClampPage(%d) = %d, want %d", requested, got, want)
		}
	}
}

func TestOffset(t *testing.T) {
	if got := Offset(1, 20); got != 0 {
		t.Errorf("Offset(1, 20) = %d, want 0", got)
	}
	if got := Offset(3, 100); got != 200 {
		t.Errorf("Offset(3, 100) = %d, want 200", got)
	}
}

func TestHasMore(t *testing.T) {
	tests := []struct {
		name                    string
		offset, returned, total int
		want                    bool
	}{
		{"a full first page of a longer list has more", 0, 20, 137, true},
		{"the exact last page has no more", 120, 17, 137, false},
		{"a full page that exactly exhausts the list has no more", 100, 37, 137, false},
		{"an empty list has no more", 0, 0, 0, false},
		{"a page past the end has no more", 500, 0, 137, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasMore(tc.offset, tc.returned, tc.total); got != tc.want {
				t.Errorf("HasMore(%d, %d, %d) = %v, want %v",
					tc.offset, tc.returned, tc.total, got, tc.want)
			}
		})
	}
}

func TestProbeAndTrim(t *testing.T) {
	if got := Probe(20); got != 21 {
		t.Errorf("Probe(20) = %d, want 21", got)
	}

	t.Run("a probe row present means more follow and is not served", func(t *testing.T) {
		rows := []int{1, 2, 3, 4}
		page, hasMore := Trim(rows, 3)
		if !hasMore {
			t.Error("hasMore = false, want true — the probe row was there")
		}
		if len(page) != 3 {
			t.Errorf("page has %d rows, want 3 — the probe row must not be served", len(page))
		}
	})

	t.Run("an exactly-full page with no probe row is the end", func(t *testing.T) {
		// The case a "did the page come back full?" heuristic gets wrong, and
		// the reason Probe exists at all.
		rows := []int{1, 2, 3}
		page, hasMore := Trim(rows, 3)
		if hasMore {
			t.Error("hasMore = true, want false — a full page is not evidence of more")
		}
		if len(page) != 3 {
			t.Errorf("page has %d rows, want 3", len(page))
		}
	})

	t.Run("a short page is the end", func(t *testing.T) {
		page, hasMore := Trim([]int{1}, 3)
		if hasMore || len(page) != 1 {
			t.Errorf("Trim([1], 3) = (%v, %v), want ([1], false)", page, hasMore)
		}
	})
}
