// SPDX-License-Identifier: AGPL-3.0-only

package rdap_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/rdap"
)

// A smoke test against the real IANA bootstrap and a real registry.
//
// Opt-in, because a test suite that reaches the internet is a test suite that fails when
// someone's network does, and because hammering registries from CI is exactly the
// behaviour this package is careful to avoid elsewhere. Run it deliberately:
//
//	LAZARET_LIVE_NETWORK=1 go test ./whois/ -run Live -v
func TestLiveRDAP(t *testing.T) {
	if os.Getenv("LAZARET_LIVE_NETWORK") == "" {
		t.Skip("set LAZARET_LIVE_NETWORK=1 to run against real registries")
	}

	c := rdap.New(&rdap.Options{Timeout: 20 * time.Second})
	ctx := context.Background()

	t.Run("registered domain", func(t *testing.T) {
		out, err := c.Lookup(ctx, "sublimesecurity.com")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if !mdm.Deref(out.Found) {
			t.Error("found = false for a domain that exists")
		}
		// Registered in 2016, so comfortably over a thousand days by now.
		if got := mdm.Deref(out.DaysOld); got < 1000 {
			t.Errorf("days_old = %d, want a large number", got)
		}
		if mdm.Deref(out.RegistrarName) == "" {
			t.Error("no registrar name")
		}
		if len(out.NameServers) == 0 {
			t.Error("no nameservers")
		}
		t.Logf("days_old=%d registrar=%q nameservers=%d",
			mdm.Deref(out.DaysOld), mdm.Deref(out.RegistrarName), len(out.NameServers))
	})

	t.Run("unregistered domain", func(t *testing.T) {
		out, err := c.Lookup(ctx, "this-domain-should-not-exist-lazaret-test.com")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if mdm.Deref(out.Found) {
			t.Error("found = true for a domain that should not exist")
		}
	})

	t.Run("IP address", func(t *testing.T) {
		out, err := c.LookupIP(ctx, "8.8.8.8")
		if err != nil {
			t.Fatalf("LookupIP: %v", err)
		}
		if !mdm.Deref(out.Found) {
			t.Fatal("found = false")
		}
		if got := mdm.Deref(out.Organization); got != "Google LLC" {
			t.Errorf("organization = %q, want Google LLC", got)
		}
		if len(out.CIDR) == 0 {
			t.Error("no CIDR reported")
		}
		t.Logf("org=%q name=%q cidr=%v abuse=%q",
			mdm.Deref(out.Organization), mdm.Deref(out.Name), out.CIDR, mdm.Deref(out.AbuseEmail))
	})

	t.Run("IP in another RIR", func(t *testing.T) {
		// Exercises the cross-RIR redirect and the organisation-scoring rule: RIPE's own
		// record leads with an administrative entity named "Managing Director".
		out, err := c.LookupIP(ctx, "193.0.6.139")
		if err != nil {
			t.Fatalf("LookupIP: %v", err)
		}
		if got := mdm.Deref(out.Organization); !strings.Contains(got, "RIPE") {
			t.Errorf("organization = %q, want the operator rather than a role", got)
		}
		t.Logf("org=%q country=%q", mdm.Deref(out.Organization), mdm.Deref(out.Country))
	})

	t.Run("private space needs no lookup", func(t *testing.T) {
		out, err := c.LookupIP(ctx, "10.1.2.3")
		if err != nil {
			t.Fatalf("LookupIP: %v", err)
		}
		if mdm.Deref(out.Found) {
			t.Error("found = true for private space")
		}
	})

	t.Run("ASN", func(t *testing.T) {
		out, err := c.LookupASN(ctx, 15169)
		if err != nil {
			t.Fatalf("LookupASN: %v", err)
		}
		if got := mdm.Deref(out.Name); got != "GOOGLE" {
			t.Errorf("name = %q, want GOOGLE", got)
		}
		t.Logf("org=%q name=%q days_old=%d",
			mdm.Deref(out.Organization), mdm.Deref(out.Name), mdm.Deref(out.DaysOld))
	})

	t.Run("TLD without RDAP falls back", func(t *testing.T) {
		// .de publishes no RDAP service, so this exercises the legacy path end to end.
		out, err := c.Lookup(ctx, "denic.de")
		if err != nil {
			t.Fatalf("the legacy fallback failed: %v", err)
		}
		if !mdm.Deref(out.Found) {
			t.Error("found = false")
		}
		t.Logf("via legacy WHOIS: found=%v nameservers=%d",
			mdm.Deref(out.Found), len(out.NameServers))
	})
}
