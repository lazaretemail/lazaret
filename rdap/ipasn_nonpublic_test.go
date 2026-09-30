// SPDX-License-Identifier: AGPL-3.0-only

package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// Asking a registry about an internal address cannot return anything useful, and
// it tells a third party what this organisation's addressing looks like — one
// lookup per message that crossed an internal relay, which is most of them.
func TestNonPublicAddressesNeverReachTheNetwork(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(&Options{HTTPClient: srv.Client(), BootstrapURL: srv.URL})

	for _, addr := range []string{
		"10.0.0.3", "192.168.1.1", "172.16.5.4", // RFC 1918
		"127.0.0.1", "::1", // loopback
		"169.254.169.254",           // link-local: the cloud metadata service
		"192.0.2.1", "198.51.100.7", // documentation, RFC 5737
		"2001:db8::1",          // documentation, RFC 3849
		"100.64.0.1",           // carrier NAT
		"0.0.0.0", "224.0.0.1", // unspecified, multicast
	} {
		out, err := c.LookupIP(context.Background(), addr)
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		if out == nil || out.Found == nil || *out.Found {
			t.Errorf("%s: reported as found; no registry holds it", addr)
		}
	}
	if called {
		t.Error("a non-public address was looked up over the network")
	}
}

// A genuine public address must still be looked up.
func TestPublicAddressesAreStillLookedUp(t *testing.T) {
	if nonPublic(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 was treated as non-public")
	}
	if nonPublic(netip.MustParseAddr("45.133.1.90")) {
		t.Error("a routable address was treated as non-public")
	}
	if nonPublic(netip.MustParseAddr("2606:4700::1111")) {
		t.Error("a routable IPv6 address was treated as non-public")
	}
}
