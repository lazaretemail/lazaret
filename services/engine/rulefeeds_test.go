// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// A feed is somebody else's repository, and git carries symlinks.
//
// A file named rules/creds.yml pointing at /etc/passwd or at the engine's own
// secret key would be read by the loader as though the repository contained it.
// Nothing in a rule feed has any reason to be a link, so they are removed rather
// than resolved.
func TestSymlinksInAFeedAreRemoved(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret-key")
	if err := os.WriteFile(secret, []byte("the engine's key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(root, "detection-rules"), 0o750); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "detection-rules", "ok.yml")
	if err := os.WriteFile(real, []byte("name: fine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "detection-rules", "stolen.yml")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	if err := stripSymlinks(root); err != nil {
		t.Fatalf("stripSymlinks: %v", err)
	}

	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("the symlink survived; a feed could read a file outside its clone")
	}
	if _, err := os.Stat(real); err != nil {
		t.Errorf("a real rule file was removed: %v", err)
	}
	// The link target itself must be untouched — removing a link must never remove
	// what it pointed at.
	if _, err := os.Stat(secret); err != nil {
		t.Errorf("stripping the link deleted its target: %v", err)
	}
}

// A subdir comes out of the database and is joined onto a path. It must not be
// able to climb out of the clone and point the loader at the filesystem.
func TestFeedSubdirCannotEscapeTheClone(t *testing.T) {
	f := &FeedSyncer{stateDir: "/var/lib/lazaret/state"}
	base := feedDir(f.stateDir, "feed_1")

	for _, subdir := range []string{
		"../../../../etc",
		"/etc",
		"detection-rules/../../../../etc",
		"..",
	} {
		got := f.feedContentDir(store.RuleFeed{ID: "feed_1", Subdir: subdir})
		if !strings.HasPrefix(got, base) {
			t.Errorf("subdir %q escaped the clone: %s", subdir, got)
		}
	}

	// The ordinary case still works.
	got := f.feedContentDir(store.RuleFeed{ID: "feed_1", Subdir: "detection-rules"})
	if want := filepath.Join(base, "detection-rules"); got != want {
		t.Errorf("subdir resolved to %s, want %s", got, want)
	}
}

// An id from the database is joined onto a path too.
func TestFeedDirIsConfinedToTheFeedRoot(t *testing.T) {
	root := feedRoot("/state")
	for _, id := range []string{"../../etc", "/etc/shadow", "..", "a/../../b"} {
		got := feedDir("/state", id)
		if !strings.HasPrefix(got, root) {
			t.Errorf("id %q escaped the feed root: %s", id, got)
		}
	}
}

// Feed content must be loaded at start-up, not only when a sync changes something.
//
// The bug: Dirs() correctly returns the local directory plus every cloned feed, but
// nothing called Reload until syncDue noticed a new commit. Restart an engine whose
// clone was already current and it served the local rules alone — in the deployment
// that found this, one rule instead of 1258, with every capability probe reporting
// healthy because a one-rule set is internally consistent.
func TestFeedDirsIncludeClonedContentWithoutASync(t *testing.T) {
	state := t.TempDir()
	local := t.TempDir()

	// A cloned feed already on disk, as it would be after a restart.
	feedID := "feed_1"
	content := filepath.Join(feedDir(state, feedID), "detection-rules")
	if err := os.MkdirAll(content, 0o750); err != nil {
		t.Fatal(err)
	}

	f := &FeedSyncer{stateDir: state, localDir: local}
	got := f.feedContentDir(store.RuleFeed{ID: feedID, Subdir: "detection-rules"})
	if got != content {
		t.Fatalf("content dir = %s, want %s", got, content)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("the cloned directory is not where Dirs will look: %v", err)
	}
}
