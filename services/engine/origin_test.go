// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
)

// hop builds one Received header's worth of model.
func hop(index int64, from string) *mdm.Hop {
	return &mdm.Hop{Index: index, Received: &mdm.Received{
		Source: &mdm.ReceivedFrom{Raw: mdm.Ptr(from)},
	}}
}

func withSPF(h *mdm.Hop, ip, helo string) *mdm.Hop {
	h.ReceivedSPF = &mdm.SPF{ClientIP: &mdm.IP{IP: ip}}
	if helo != "" {
		h.ReceivedSPF.Helo = &mdm.Domain{Domain: helo}
	}
	return h
}

// The sending server is the last host outside the organisation, not the first line in
// the header block.
//
// Hops run sender to recipient and everything below our own boundary is whatever the
// sender chose to write. A picker that takes hops[0] reports the forged one; a picker
// that takes the last reports our own internal relay. Both are wrong on real mail, and
// both look plausible on a message with exactly two hops.
func TestOriginIsTheLastExternalHop(t *testing.T) {
	msg := &mdm.MessageDataModel{Headers: &mdm.Headers{Hops: []*mdm.Hop{
		// Invented by the sender to suggest the mail began somewhere respectable.
		hop(0, "mail.legitimate-bank.example (mail.legitimate-bank.example [198.51.100.7])"),
		// The real peer: this is the connection our boundary MTA accepted.
		hop(1, "unknown (vps-4471.cheap-hosting.example [203.0.113.99])"),
		// Our own relay handing it inward.
		hop(2, "mx01.corp.internal (mx01.corp.internal [10.0.3.11])"),
	}}}

	got := pickOrigin(msg)
	if got == nil {
		t.Fatal("no origin found, want the external hop")
	}
	if got.IP != "203.0.113.99" {
		t.Errorf("origin IP = %q, want the last external hop 203.0.113.99", got.IP)
	}
	if got.RDNS != "vps-4471.cheap-hosting.example" {
		t.Errorf("reverse name = %q, want the name the receiving server resolved", got.RDNS)
	}
	if got.Authenticated {
		t.Error("a parsed Received header is not an authenticated origin")
	}
}

// Received-SPF outranks a parsed header, because the receiving server wrote it about a
// connection it actually accepted rather than about text it was handed.
func TestReceivedSPFOutranksAParsedHeader(t *testing.T) {
	// The SPF header sits on the hop our boundary MTA wrote, above its own Received
	// line — so the hop it attaches to is not the hop that carried the connection.
	// The reverse name has to be found by matching the address.
	msg := &mdm.MessageDataModel{Headers: &mdm.Headers{Hops: []*mdm.Hop{
		hop(0, "mail.legitimate-bank.example ([198.51.100.7])"),
		hop(1, "mail.cheap-hosting.example (vps-4471.cheap-hosting.example [203.0.113.42])"),
		withSPF(hop(2, "mx01.corp.internal ([10.0.3.11])"), "203.0.113.42", "cheap-hosting.example"),
	}}}

	got := pickOrigin(msg)
	if got == nil || got.IP != "203.0.113.42" {
		t.Fatalf("origin = %+v, want the SPF client_ip 203.0.113.42", got)
	}
	if !got.Authenticated {
		t.Error("an SPF client_ip is the receiving server's own record and counts as authenticated")
	}
	if got.Helo != "cheap-hosting.example" {
		t.Errorf("helo = %q, want the name the sender gave for itself", got.Helo)
	}
	if got.RDNS != "vps-4471.cheap-hosting.example" {
		t.Errorf("reverse name = %q, want the name resolved for the authenticated "+
			"address — not whatever sits on the hop the SPF header landed on", got.RDNS)
	}
}

// With nothing but internal hops there is no origin to report, and reporting one
// anyway would name the organisation's own mail server as the sender of every message
// it relayed.
func TestInternalOnlyPathHasNoOrigin(t *testing.T) {
	for _, addr := range []string{"10.0.3.11", "192.168.1.4", "172.16.9.9", "127.0.0.1",
		"169.254.10.1", "100.100.1.1", "::1", "fe80::1"} {
		msg := &mdm.MessageDataModel{Headers: &mdm.Headers{Hops: []*mdm.Hop{
			hop(0, "relay (["+addr+"])"),
		}}}
		if got := pickOrigin(msg); got != nil {
			t.Errorf("%s: reported origin %q, want none — it is not an external address",
				addr, got.IP)
		}
	}
}

// A sender-written header is usable but must say so. It is the weakest evidence in the
// message and an analyst blocking a range on the strength of it should know that.
func TestSenderWrittenHeaderIsLabelledAsSuch(t *testing.T) {
	msg := &mdm.MessageDataModel{Headers: &mdm.Headers{
		XOriginatingIP: &mdm.IP{IP: "203.0.113.5"},
		Hops:           []*mdm.Hop{hop(0, "relay ([10.0.0.1])")},
	}}

	got := pickOrigin(msg)
	if got == nil || got.IP != "203.0.113.5" {
		t.Fatalf("origin = %+v, want the X-Originating-IP fallback", got)
	}
	if got.Authenticated {
		t.Error("a header the sender wrote must never be reported as authenticated")
	}
	if got.Basis == "" {
		t.Error("the basis must be stated, since this is the weakest evidence there is")
	}
}

// The reverse name must not be filled in with the address itself, which would read as
// a resolved hostname and imply a PTR record that does not exist.
func TestBareAddressIsNotAReverseName(t *testing.T) {
	msg := &mdm.MessageDataModel{Headers: &mdm.Headers{Hops: []*mdm.Hop{
		hop(0, "[203.0.113.99] ([203.0.113.99])"),
	}}}
	got := pickOrigin(msg)
	if got == nil {
		t.Fatal("no origin found")
	}
	if got.RDNS != "" {
		t.Errorf("reverse name = %q, want empty — that is the address, not a name", got.RDNS)
	}
}

// IPv6 is written with a prefix in Received headers and has to survive it.
func TestIPv6OriginIsExtracted(t *testing.T) {
	msg := &mdm.MessageDataModel{Headers: &mdm.Headers{Hops: []*mdm.Hop{
		hop(0, "mail.example.com (mail.example.com [IPv6:2001:db8::42])"),
	}}}
	got := pickOrigin(msg)
	if got == nil || got.IP != "2001:db8::42" {
		t.Fatalf("origin = %+v, want 2001:db8::42", got)
	}
}
