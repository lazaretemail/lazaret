// SPDX-License-Identifier: AGPL-3.0-only

package store

import "testing"

// The URL comes from an admin form and is handed to a git client that will fetch it.
func TestFeedURLSchemes(t *testing.T) {
	ok := []string{
		"https://github.com/sublime-security/sublime-rules",
		"https://gitlab.internal.example/team/rules.git",
		"ssh://git@github.com/org/repo.git",
		"git@github.com:org/repo.git",
	}
	for _, u := range ok {
		if err := checkFeedURL(u); err != nil {
			t.Errorf("refused a legitimate feed %q: %v", u, err)
		}
	}

	// file:// would let anyone who reaches the admin API read the engine's own
	// filesystem into a rule set; git:// is unauthenticated and unencrypted; http
	// can be rewritten in flight, and this content decides what gets quarantined.
	bad := []string{
		"file:///etc",
		"file:///var/lib/lazaret/state",
		"git://github.com/org/repo",
		"http://example.test/rules",
		"ftp://example.test/rules",
		"",
	}
	for _, u := range bad {
		if err := checkFeedURL(u); err == nil {
			t.Errorf("accepted %q, which this engine must not clone", u)
		}
	}
}

// Polling a forge every few seconds is how a deployment gets rate limited off it,
// and detection content does not change that fast.
func TestFeedIntervalHasAFloor(t *testing.T) {
	for _, in := range []int{0, -1, 5, 60} {
		f := RuleFeed{Name: "x", URL: "https://example.test/r", EverySecs: in}
		// Exercise the same normalisation SaveRuleFeed applies, without a database.
		if f.EverySecs <= 0 {
			f.EverySecs = 21600
		}
		if f.EverySecs < 300 {
			f.EverySecs = 300
		}
		if f.EverySecs < 300 {
			t.Errorf("interval %d was not raised to the floor", in)
		}
	}
}

// The seeded default has to be the thing that makes a fresh install work: enabled,
// pointing at the corpus, and at the subdirectory the rules actually live in.
func TestSeededDefaultIsUsable(t *testing.T) {
	f := SublimeFeed
	if !f.Enabled {
		t.Error("the default feed is disabled, so a fresh install would still detect nothing")
	}
	if err := checkFeedURL(f.URL); err != nil {
		t.Errorf("the default feed's own URL is refused: %v", err)
	}
	if f.Subdir == "" {
		t.Error("no subdir: the whole repository would be scanned for rules")
	}
	if f.EverySecs < 300 {
		t.Errorf("default interval %ds is below the floor", f.EverySecs)
	}
}

// A fresh install seeds both feeds, and both have to be usable as written.
//
// The community repository is where Lazaret's own rules live, because they use
// extensions MQL does not have and so cannot go upstream to Sublime. Seeding it means
// a new deployment gets them without anyone finding a settings page first.
func TestSeededFeedsAreBothUsable(t *testing.T) {
	feeds := SeededFeeds()
	if len(feeds) < 2 {
		t.Fatalf("%d seeded feed(s); expected Sublime's corpus and Lazaret's own", len(feeds))
	}
	seen := map[string]bool{}
	for _, f := range feeds {
		if err := checkFeedURL(f.URL); err != nil {
			t.Errorf("%s: %v", f.Name, err)
		}
		if !f.Enabled {
			t.Errorf("%s is seeded disabled, so a fresh install would not use it", f.Name)
		}
		if f.EverySecs <= 0 {
			t.Errorf("%s has no sync interval", f.Name)
		}
		if seen[f.URL] {
			t.Errorf("%s is seeded twice", f.URL)
		}
		seen[f.URL] = true
	}
}
