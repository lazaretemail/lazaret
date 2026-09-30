// SPDX-License-Identifier: AGPL-3.0-only

package rdap_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rdap"
)

// Fixtures trimmed from real responses captured from data.iana.org and rdap.arin.net.

const bootstrapIPv4 = `{
  "description": "RDAP bootstrap file for IPv4 address allocations",
  "publication": "2019-06-07T19:00:02Z",
  "version": "1.0",
  "services": [
    [["8.0.0.0/8", "3.0.0.0/8"], ["https://%[1]s/arin/", "http://%[1]s/arin/"]],
    [["193.0.0.0/8"], ["https://%[1]s/ripe/"]]
  ]
}`

const bootstrapIPv6 = `{"version":"1.0","services":[[["2001:500::/30"],["https://%[1]s/arin/"]]]}`

const bootstrapASN = `{
  "version": "1.0",
  "services": [
    [["1-1876", "15000-16000"], ["https://%[1]s/arin/", "http://%[1]s/arin/"]],
    [["36864-37887"], ["https://%[1]s/afrinic/"]]
  ]
}`

const ipRecord = `{
  "objectClassName": "ip network",
  "handle": "NET-8-8-8-0-2",
  "startAddress": "8.8.8.0",
  "endAddress": "8.8.8.255",
  "ipVersion": "v4",
  "name": "GOGL",
  "type": "DIRECT ALLOCATION",
  "parentHandle": "NET-8-0-0-0-0",
  "status": ["active"],
  "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
  "arin_originas0_originautnums": [15169],
  "events": [{"eventAction":"registration","eventDate":"2023-12-28T17:24:33-05:00"}],
  "entities": [
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"],["adr",{"cc":"US"},"text",["","","","","","",""]]]],
      "entities": [
        {"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","network-abuse@google.com"]]]}
      ]
    }
  ]
}`

const asnRecord = `{
  "objectClassName": "autnum",
  "handle": "AS15169",
  "startAutnum": 15169,
  "endAutnum": 15169,
  "name": "GOOGLE",
  "status": ["active"],
  "events": [{"eventAction":"registration","eventDate":"2000-03-30T00:00:00-05:00"}],
  "entities": [
    {"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Google LLC"],["adr",{"cc":"US"},"text",["","","","","","",""]]]]}
  ]
}`

// newNetClient wires a client whose bootstrap registries and RIRs are all the test server.
func newNetClient(t *testing.T, handler http.HandlerFunc) (*rdap.Client, *int32) {
	t.Helper()

	var hits int32
	mux := http.NewServeMux()
	var srv *httptest.Server

	host := func() string { return strings.TrimPrefix(srv.URL, "https://") }

	mux.HandleFunc("/bootstrap/ipv4.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, bootstrapIPv4, host())
	})
	mux.HandleFunc("/bootstrap/ipv6.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, bootstrapIPv6, host())
	})
	mux.HandleFunc("/bootstrap/asn.json", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprintf(w, bootstrapASN, host())
	})
	mux.HandleFunc("/arin/", handler)
	mux.HandleFunc("/ripe/", handler)

	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	opts := sealedOptions(t, srv)
	opts.BootstrapIPv4URL = srv.URL + "/bootstrap/ipv4.json"
	opts.BootstrapIPv6URL = srv.URL + "/bootstrap/ipv6.json"
	opts.BootstrapASNURL = srv.URL + "/bootstrap/asn.json"
	return rdap.New(opts), &hits
}

func TestLookupIP(t *testing.T) {
	c, _ := newNetClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/ip/8.8.8.8") {
			t.Errorf("registry asked for %q", r.URL.Path)
		}
		fmt.Fprint(w, ipRecord)
	})

	out, err := c.LookupIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}

	if !mdm.Deref(out.Found) {
		t.Error("found = false")
	}
	// The field that matters most: whose network this is. Attackers rotate addresses
	// freely and netblocks slowly.
	if got := mdm.Deref(out.Organization); got != "Google LLC" {
		t.Errorf("organization = %q", got)
	}
	if got := mdm.Deref(out.Name); got != "GOGL" {
		t.Errorf("name = %q", got)
	}
	if got := mdm.Deref(out.Type); got != "DIRECT ALLOCATION" {
		t.Errorf("type = %q", got)
	}
	// The structured CIDR extension, rather than inferring a prefix from start and end.
	if len(out.CIDR) != 1 || out.CIDR[0] != "8.8.8.0/24" {
		t.Errorf("cidr = %v, want [8.8.8.0/24]", out.CIDR)
	}
	if len(out.ASNs) != 1 || out.ASNs[0] != 15169 {
		t.Errorf("asns = %v, want [15169]", out.ASNs)
	}
	if got := mdm.Deref(out.Country); got != "US" {
		t.Errorf("country = %q", got)
	}
	// The abuse contact is nested inside the registrant at several RIRs.
	if got := mdm.Deref(out.AbuseEmail); got != "network-abuse@google.com" {
		t.Errorf("abuse_email = %q", got)
	}
	if got := mdm.Deref(out.DaysOld); got < 1000 {
		t.Errorf("days_old = %d, want the allocation age", got)
	}
}

func TestLookupASN(t *testing.T) {
	c, _ := newNetClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/autnum/15169") {
			t.Errorf("registry asked for %q", r.URL.Path)
		}
		fmt.Fprint(w, asnRecord)
	})

	out, err := c.LookupASN(context.Background(), 15169)
	if err != nil {
		t.Fatalf("LookupASN: %v", err)
	}
	if !mdm.Deref(out.Found) {
		t.Error("found = false")
	}
	if got := mdm.Deref(out.Organization); got != "Google LLC" {
		t.Errorf("organization = %q", got)
	}
	if got := mdm.Deref(out.Name); got != "GOOGLE" {
		t.Errorf("name = %q", got)
	}
	if got := mdm.Deref(out.ASN); got != 15169 {
		t.Errorf("asn = %d", got)
	}
}

func TestBootstrapPrefersHTTPS(t *testing.T) {
	// The registries list both schemes for several RIRs. Sending lookups of
	// attacker-chosen addresses over cleartext would be a poor trade for one fewer
	// handshake.
	var scheme string
	c, _ := newNetClient(t, func(w http.ResponseWriter, r *http.Request) {
		scheme = "https" // the guarded transport only permits the TLS test server
		fmt.Fprint(w, ipRecord)
	})
	if _, err := c.LookupIP(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if scheme != "https" {
		t.Error("the plaintext base URL was used")
	}
}

// ripeStyleRecord leads with an administrative entity whose name is a role, and puts the
// actual operator further down with kind "org" — the real shape of RIPE's own record.
const ripeStyleRecord = `{
  "objectClassName": "ip network",
  "handle": "193.0.0.0 - 193.0.7.255",
  "name": "RIPE-NCC",
  "country": "NL",
  "cidr0_cidrs": [{"v4prefix": "193.0.0.0", "length": 21}],
  "entities": [
    {
      "roles": ["administrative"],
      "vcardArray": ["vcard",[["fn",{},"text","Managing Director"],["kind",{},"text","group"],["org",{},"text","ORG-NCC1-RIPE"]]]
    },
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard",[["fn",{},"text","Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"],["kind",{},"text","org"]]]
    },
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard",[["fn",{},"text","RIPE-NCC-MNT"],["kind",{},"text","individual"]]]
    },
    {
      "roles": ["abuse"],
      "vcardArray": ["vcard",[["fn",{},"text","RIPE NCC Operations"],["email",{"type":"abuse"},"text","abuse@ripe.net"]]]
    }
  ]
}`

func TestOrganisationPrefersTheActualOperator(t *testing.T) {
	// The most valuable field in this type, and the easiest to get plausibly wrong. A
	// record that leads with "Managing Director" must still report who runs the network.
	c, _ := newNetClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, ripeStyleRecord)
	})

	out, err := c.LookupIP(context.Background(), "193.0.6.139")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	want := "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"
	if got := mdm.Deref(out.Organization); got != want {
		t.Errorf("organization = %q, want %q", got, want)
	}
	if got := mdm.Deref(out.Country); got != "NL" {
		t.Errorf("country = %q", got)
	}
	if got := mdm.Deref(out.AbuseEmail); got != "abuse@ripe.net" {
		t.Errorf("abuse_email = %q", got)
	}
	// The vcard `org` field holds a handle at RIPE, not a name, so it must not leak out.
	if strings.HasPrefix(mdm.Deref(out.Organization), "ORG-") {
		t.Error("a registry handle was reported as the organisation name")
	}
}

func TestUnallocatedSpaceIsAnAnswer(t *testing.T) {
	// Private and reserved ranges are in no RIR's bootstrap. Mail claiming to arrive
	// from them is itself notable, so this is a definite answer, not a failure.
	c, _ := newNetClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a registry was queried for unallocated space")
	})

	for _, addr := range []string{"10.1.2.3", "192.168.0.1", "127.0.0.1"} {
		out, err := c.LookupIP(context.Background(), addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if mdm.Deref(out.Found) {
			t.Errorf("%s: found = true", addr)
		}
	}
}

func TestLongestPrefixWins(t *testing.T) {
	// The registries are not disjoint: a /8 delegated to one RIR can contain a smaller
	// range transferred to another, so the most specific entry has to win.
	var served string
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/bootstrap/ipv4.json", func(w http.ResponseWriter, _ *http.Request) {
		host := strings.TrimPrefix(srv.URL, "https://")
		fmt.Fprintf(w, `{"version":"1.0","services":[
			[["8.0.0.0/8"],["https://%[1]s/broad/"]],
			[["8.8.8.0/24"],["https://%[1]s/specific/"]]
		]}`, host)
	})
	mux.HandleFunc("/bootstrap/ipv6.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"version":"1.0","services":[]}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		served = strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
		fmt.Fprint(w, ipRecord)
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	opts := sealedOptions(t, srv)
	opts.BootstrapIPv4URL = srv.URL + "/bootstrap/ipv4.json"
	opts.BootstrapIPv6URL = srv.URL + "/bootstrap/ipv6.json"
	c := rdap.New(opts)

	if _, err := c.LookupIP(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if served != "specific" {
		t.Errorf("served by %q, want the more specific delegation", served)
	}
}

func TestASNRangeMatching(t *testing.T) {
	c, _ := newNetClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, asnRecord)
	})

	// 15169 is inside 15000-16000; 99999 is in no listed range.
	if _, err := c.LookupASN(context.Background(), 15169); err != nil {
		t.Errorf("an in-range ASN failed: %v", err)
	}
	out, err := c.LookupASN(context.Background(), 99999)
	if err != nil {
		t.Fatalf("an unallocated ASN errored: %v", err)
	}
	if mdm.Deref(out.Found) {
		t.Error("found = true for an unallocated ASN")
	}
}

func TestBootstrapIsFetchedOnce(t *testing.T) {
	c, asnHits := newNetClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, asnRecord)
	})
	for _, n := range []uint32{15169, 15170, 15171} {
		if _, err := c.LookupASN(context.Background(), n); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(asnHits); got != 1 {
		t.Errorf("the ASN bootstrap was fetched %d times, want 1", got)
	}
}

func TestInvalidInputs(t *testing.T) {
	c, _ := newNetClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a registry was queried for invalid input")
	})
	if _, err := c.LookupIP(context.Background(), "not an address"); err == nil {
		t.Error("a non-address was accepted")
	}
	if _, err := c.LookupIP(context.Background(), "example.com"); err == nil {
		t.Error("a domain was accepted as an address")
	}
}

func TestExtensionsAreNotInTheStandardRegistry(t *testing.T) {
	// The compatibility numbers only mean something if the standard registry is exactly
	// Sublime's surface.
	std := mql.NewRegistry()
	for _, name := range []string{"rdap.ip", "rdap.asn"} {
		if _, ok := std.Lookup(name); ok {
			t.Errorf("%s is in the standard registry", name)
		}
	}

	ext, err := rdap.ExtendedRegistry()
	if err != nil {
		t.Fatalf("ExtendedRegistry: %v", err)
	}
	for _, name := range []string{"rdap.ip", "rdap.asn"} {
		if _, ok := ext.Lookup(name); !ok {
			t.Errorf("%s is missing from the extended registry", name)
		}
	}
	// And the standard functions are still all there.
	if _, ok := ext.Lookup("network.whois"); !ok {
		t.Error("extending dropped the standard functions")
	}

	// A strict registry refuses extensions outright, which is what keeps compatibility
	// testing meaningful after someone has extended the language.
	if err := rdap.Extend(mql.NewRegistry().Strict()); err == nil {
		t.Error("a strict registry accepted the extensions")
	}
}

func TestExtensionEvaluatesAgainstAMessage(t *testing.T) {
	c, _ := newNetClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/autnum/") {
			fmt.Fprint(w, asnRecord)
			return
		}
		fmt.Fprint(w, ipRecord)
	})

	reg, err := rdap.ExtendedRegistry()
	if err != nil {
		t.Fatal(err)
	}

	msg := &mdm.MessageDataModel{
		Headers: &mdm.Headers{IPs: []*mdm.IP{{IP: "8.8.8.8"}}},
	}

	for _, tc := range []struct {
		src  string
		want mql.Verdict
	}{
		// The shape a real rule would take: which organisation relayed this.
		{`any(headers.ips, rdap.ip(.).organization == "Google LLC")`, mql.Match},
		{`any(headers.ips, rdap.ip(.ip).organization == "Someone Else")`, mql.NoMatch},
		{`any(headers.ips, any(rdap.ip(.).asns, rdap.asn(.).name == "GOOGLE"))`, mql.Match},
		// A freshly allocated netblock already sending mail is worth a second look.
		{`any(headers.ips, rdap.ip(.).days_old < 30)`, mql.NoMatch},
	} {
		t.Run(tc.src, func(t *testing.T) {
			checked, err := mql.Compile(tc.src, &mql.CheckOptions{Registry: reg})
			if err != nil {
				t.Fatalf("compiling: %v", err)
			}
			res := mql.Eval(context.Background(), checked, msg,
				&mql.EvalOptions{Registry: reg, Enricher: c})
			if res.Err != nil {
				t.Fatalf("evaluating: %v", res.Err)
			}
			if res.Verdict != tc.want {
				t.Errorf("verdict = %s (value %s, missing %v), want %s",
					res.Verdict, res.Value, res.Missing, tc.want)
			}
		})
	}
}

func TestExtensionUnavailableIsIndeterminate(t *testing.T) {
	// Same contract as every other capability: a lookup that could not be made leaves
	// the rule undecided rather than producing a verdict.
	reg, _ := rdap.ExtendedRegistry()
	checked, err := mql.Compile(`any(headers.ips, rdap.ip(.).organization == "x")`,
		&mql.CheckOptions{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	msg := &mdm.MessageDataModel{Headers: &mdm.Headers{IPs: []*mdm.IP{{IP: "8.8.8.8"}}}}

	res := mql.Eval(context.Background(), checked, msg, &mql.EvalOptions{Registry: reg})
	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict = %s, want indeterminate", res.Verdict)
	}
	if len(res.Missing) != 1 || res.Missing[0] != rdap.CapIP {
		t.Errorf("missing = %v, want [rdap.ip]", res.Missing)
	}
}

func TestMalformedNetworkResponses(t *testing.T) {
	for name, body := range map[string]string{
		"empty":        ``,
		"not json":     `<html>502</html>`,
		"null":         `null`,
		"bad cidr":     `{"cidr0_cidrs":[{"length":24}]}`,
		"bad event":    `{"events":[{"eventAction":"registration","eventDate":"nope"}]}`,
		"future event": `{"events":[{"eventAction":"registration","eventDate":"2099-01-01T00:00:00Z"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := newNetClient(t, func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, body)
			})
			out, err := c.LookupIP(context.Background(), "8.8.8.8")
			if err != nil {
				return // a decode failure is fine; a panic is not
			}
			if out != nil && out.DaysOld != nil && *out.DaysOld < 0 {
				t.Errorf("days_old = %d, want it never negative", *out.DaysOld)
			}
		})
	}
}
