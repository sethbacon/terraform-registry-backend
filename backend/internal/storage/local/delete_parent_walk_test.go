package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Delete's "remove now-empty parent directories" walk could climb ABOVE the
// storage root (CodeQL go/path-injection, alerts 58/59).
//
// The loop terminated on `dir != s.basePath`, comparing filepath.Dir output --
// which is always clean and never has a trailing separator -- against
// cfg.BasePath stored verbatim. Configure the base path with a trailing slash,
// or as a relative path, and the comparison never matches: the walk deletes the
// storage root itself and then keeps climbing, removing every empty ancestor
// until os.Remove happens to fail on a non-empty one.
//
// Nothing about the caller's key is needed to trigger it. It is purely the
// shape of the configured base path, which is why safeJoin -- which guards the
// key -- never saw it.

// basePathSpellings are the ways an operator can write the same directory.
// Delete must behave identically for all of them.
func basePathSpellings(root string) map[string]string {
	return map[string]string{
		"plain":          root,
		"trailing slash": root + string(os.PathSeparator),
		"dot segment":    filepath.Join(root, "."),
		"redundant sep":  root + string(os.PathSeparator) + string(os.PathSeparator),
	}
}

func TestDelete_ParentWalkNeverClimbsAboveTheRoot(t *testing.T) {
	for name, spelling := range basePathSpellings(t.TempDir()) {
		t.Run(name, func(t *testing.T) {
			// An outer directory that must survive: it is the parent of the
			// storage root and is empty apart from the root itself, so a walk
			// that climbs past the root will delete it.
			outer := t.TempDir()
			root := filepath.Join(outer, "storage")
			if err := os.MkdirAll(root, 0o750); err != nil {
				t.Fatal(err)
			}
			// Re-spell the root the way the operator configured it.
			configured := root
			switch name {
			case "trailing slash":
				configured = root + string(os.PathSeparator)
			case "dot segment":
				configured = filepath.Join(root, ".")
			case "redundant sep":
				configured = root + string(os.PathSeparator) + string(os.PathSeparator)
			}
			_ = spelling

			s, err := New(&config.LocalStorageConfig{BasePath: configured}, "http://localhost")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			// One artifact, nested, so deleting it empties its parents.
			key := "modules/acme/vpc/aws/1.0.0.tar.gz"
			full := filepath.Join(root, filepath.FromSlash(key))
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := s.Delete(context.Background(), key); err != nil {
				t.Fatalf("Delete: %v", err)
			}

			// The storage root must still exist. Deleting the last artifact is
			// not a reason to remove the storage directory.
			if _, err := os.Stat(root); err != nil {
				t.Errorf("storage root was deleted by the parent walk: %v", err)
			}
			// And nothing above it may be touched.
			if _, err := os.Stat(outer); err != nil {
				t.Errorf("the walk climbed ABOVE the storage root and deleted %s: %v", outer, err)
			}
		})
	}
}

// TestDelete_StillCleansEmptyParentsInsideTheRoot is the other direction: the
// fix must not turn the cleanup into a no-op.
func TestDelete_StillCleansEmptyParentsInsideTheRoot(t *testing.T) {
	root := t.TempDir()
	s, err := New(&config.LocalStorageConfig{BasePath: root}, "http://localhost")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := "modules/acme/vpc/aws/1.0.0.tar.gz"
	full := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Every now-empty directory between the file and the root should be gone.
	if _, err := os.Stat(filepath.Join(root, "modules")); !os.IsNotExist(err) {
		t.Errorf("empty parent directories were not cleaned up (err=%v)", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("root must survive: %v", err)
	}
}

// TestDelete_StopsAtANonEmptyParent — a sibling artifact must keep its
// directories.
func TestDelete_StopsAtANonEmptyParent(t *testing.T) {
	root := t.TempDir()
	s, err := New(&config.LocalStorageConfig{BasePath: root}, "http://localhost")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	base := filepath.Join(root, "modules", "acme", "vpc", "aws")
	if err := os.MkdirAll(base, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"1.0.0.tar.gz", "2.0.0.tar.gz"} {
		if err := os.WriteFile(filepath.Join(base, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.Delete(context.Background(), "modules/acme/vpc/aws/1.0.0.tar.gz"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "2.0.0.tar.gz")); err != nil {
		t.Errorf("sibling artifact was removed: %v", err)
	}
}
