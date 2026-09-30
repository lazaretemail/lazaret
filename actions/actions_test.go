// SPDX-License-Identifier: AGPL-3.0-only

package actions

import "testing"

// Actions run least disruptive first, and that ordering is load-bearing rather
// than cosmetic: a rule set to flag and quarantine must flag a message that still
// exists. The other order flags nothing, having already removed it.
func TestOrderRunsLeastDisruptiveFirst(t *testing.T) {
	in := []Instance{
		{ID: "q", Type: Quarantine},
		{ID: "r", Type: Review},
		{ID: "f", Type: Flag},
		{ID: "t", Type: Trash},
	}
	got := Order(in)

	want := []Type{Review, Flag, Trash, Quarantine}
	if len(got) != len(want) {
		t.Fatalf("got %d actions, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Type != want[i] {
			t.Errorf("position %d is %s, want %s", i, got[i].Type, want[i])
		}
	}
}

// Quarantine is the only type that may remove a message outright, and it is the
// only one that must require custody. If this ever stops being true, the gate in
// the engine that refuses it without a held copy stops protecting anything.
func TestOnlyQuarantineIsDestructiveAndNeedsCustody(t *testing.T) {
	for _, d := range Types {
		if d.Destructive != (d.Type == Quarantine) {
			t.Errorf("%s: Destructive = %v", d.Type, d.Destructive)
		}
		if d.NeedsCustody && !d.Destructive {
			t.Errorf("%s needs custody but is not destructive, which cannot be right", d.Type)
		}
		if d.Destructive && !d.NeedsCustody {
			t.Errorf("%s removes the message and does not require custody", d.Type)
		}
	}
}

// Review and notify must not touch a mailbox. They are the two actions available
// on a deployment that has given no mailbox permission to be changed, and the
// whole point of offering them is that they cannot change anything.
func TestReviewAndNotifyTouchNoMailbox(t *testing.T) {
	for _, tp := range []Type{Review, Notify} {
		d, ok := Define(tp)
		if !ok {
			t.Fatalf("%s is not defined", tp)
		}
		if d.TouchesMailbox {
			t.Errorf("%s claims to touch the mailbox", tp)
		}
		if d.Destructive || d.NeedsCustody {
			t.Errorf("%s is marked destructive or custody-needing", tp)
		}
	}
}

// An instance is refused unless its type's required settings are present: a move
// with no folder would otherwise be queued and fail at the mailbox, after the
// administrator had left the page believing it was configured.
func TestInstanceValidation(t *testing.T) {
	cases := []struct {
		name string
		in   Instance
		ok   bool
	}{
		{"move with a folder", Instance{Label: "To Junk", Type: Move,
			Config: map[string]string{"folder": "Junk"}}, true},
		{"move with no folder", Instance{Label: "To nowhere", Type: Move}, false},
		{"move with a blank folder", Instance{Label: "x", Type: Move,
			Config: map[string]string{"folder": "   "}}, false},
		{"notify with a url", Instance{Label: "SOC", Type: Notify,
			Config: map[string]string{"url": "https://example.test/hook"}}, true},
		{"notify with no url", Instance{Label: "SOC", Type: Notify}, false},
		{"review needs nothing", Instance{Label: "Review", Type: Review}, true},
		{"no label", Instance{Type: Review}, false},
		{"unknown type", Instance{Label: "x", Type: Type("teleport")}, false},
	}
	for _, c := range cases {
		err := c.in.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: Validate() = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// Every type must say which connectors can carry it out, or the engine cannot
// tell an administrator that an action will not work on their mailbox.
func TestEveryTypeNamesItsProviders(t *testing.T) {
	for _, d := range Types {
		if len(d.Providers) == 0 {
			t.Errorf("%s names no providers", d.Type)
		}
		if d.TouchesMailbox && d.Supports("rspamd") {
			t.Errorf("%s touches a mailbox and claims to work inline, where there is no mailbox yet", d.Type)
		}
	}
}
