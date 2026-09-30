// SPDX-License-Identifier: AGPL-3.0-only

package main

import "testing"

// A host with no port is what a person types, and it has an unambiguous meaning.
//
// Without this the dial fails with "missing port in address" — a Go error about a
// string, not something an administrator can act on. It also looks exactly like an
// authentication problem, so the natural response is to re-enter a password that was
// correct all along. That is precisely what happened with a real mailbox: the
// credentials were fine and the host was "mail.example.com".
func TestAddressSuppliesTheStandardPort(t *testing.T) {
	cases := []struct {
		addr, tls, want string
	}{
		{"mail.example.com", "tls", "mail.example.com:993"},
		{"mail.example.com", "", "mail.example.com:993"},
		{"mail.example.com", "starttls", "mail.example.com:143"},
		{"mail.example.com", "none", "mail.example.com:143"},

		// An explicit port is always left alone, including a non-standard one.
		{"mail.example.com:1993", "tls", "mail.example.com:1993"},
		{"localhost:3993", "none", "localhost:3993"},

		// IPv4 and IPv6 literals, bracketed and not.
		{"203.0.113.9", "tls", "203.0.113.9:993"},
		{"203.0.113.9:993", "tls", "203.0.113.9:993"},
		{"[2001:db8::1]", "tls", "[2001:db8::1]:993"},
		{"[2001:db8::1]:993", "tls", "[2001:db8::1]:993"},
		{"2001:db8::1", "tls", "[2001:db8::1]:993"},

		{"", "tls", ""},
	}
	for _, c := range cases {
		s := &IMAPSource{Addr: c.addr, TLSMode: c.tls}
		if got := s.address(); got != c.want {
			t.Errorf("address(%q, tls=%q) = %q, want %q", c.addr, c.tls, got, c.want)
		}
	}
}
