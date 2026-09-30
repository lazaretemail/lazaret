// SPDX-License-Identifier: AGPL-3.0-only

package main

import "testing"

// The public URL is normalised, and a malformed one is refused at startup.
//
// The failure mode this prevents is quiet: Microsoft accepts a subscription and
// then notifications simply never arrive, which looks like a mailbox that has gone
// quiet rather than like a configuration error. Finding out at startup is the
// whole point.
func TestPublicBase(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"", "", false}, // no public URL is a valid answer: poll instead
		{"https://lazaret.example.com", "https://lazaret.example.com", false},
		{"https://lazaret.example.com/", "https://lazaret.example.com", false},
		{"https://lazaret.example.com///", "https://lazaret.example.com", false},
		{"  https://lazaret.example.com  ", "https://lazaret.example.com", false},

		// A bare hostname is what people type, and https is the only scheme
		// Microsoft will accept anyway.
		{"lazaret.example.com", "https://lazaret.example.com", false},

		// A path is kept, for a deployment behind a proxy that mounts this
		// somewhere other than the root.
		{"https://example.com/security", "https://example.com/security", false},
		{"https://example.com/security/", "https://example.com/security", false},

		// Refused rather than passed to Microsoft.
		{"http://lazaret.example.com", "", true},
		{"ftp://lazaret.example.com", "", true},
		{"https://", "", true},
	}
	for _, c := range cases {
		got, err := publicBase(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("publicBase(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("publicBase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The callback path is ours and is appended, never configured.
func TestGraphNotifyURLIsDerived(t *testing.T) {
	if got := graphNotifyURL(""); got != "" {
		t.Errorf("with no public URL the callback should be empty, got %q", got)
	}
	if got := graphNotifyURL("https://lazaret.example.com"); got != "https://lazaret.example.com/graph/notify" {
		t.Errorf("callback = %q", got)
	}
	if got := graphNotifyURL("https://example.com/security"); got != "https://example.com/security/graph/notify" {
		t.Errorf("callback behind a path prefix = %q", got)
	}
}
