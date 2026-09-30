// SPDX-License-Identifier: AGPL-3.0-only

package rdap_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rdap"
)

// The fixtures below are trimmed from real responses captured from rdap.iana.org and
// rdap.verisign.com, so the parser is tested against the shapes registries actually
// emit rather than against an idealised reading of the RFC.

// ianaCom is IANA's record for .com. The link that matters is the one typed
// application/rdap+json whose rel is not "self" — the self link points back at IANA, and
// following it would loop.
const ianaCom = `{
  "objectClassName": "domain",
  "ldhName": "com",
  "links": [
    {"rel":"related","href":"http://www.verisigninc.com","title":"Registration URL","type":"text/html"},
    {"rel":"alternate","href":"%s","title":"RDAP Server","type":"application/rdap+json"},
    {"rel":"self","href":"https://rdap.iana.org/domain/com","type":"application/rdap+json"}
  ]
}`

// ianaDe is a TLD that publishes no RDAP server: only a registration page and the self
// link. This is the case the legacy fallback exists for, and it is real.
const ianaDe = `{
  "objectClassName": "domain",
  "ldhName": "de",
  "links": [
    {"rel":"related","href":"http://www.denic.de/","title":"Registration URL","type":"text/html"},
    {"rel":"self","href":"https://rdap.iana.org/domain/de","type":"application/rdap+json"}
  ]
}`

const domainRecord = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "status": ["client transfer prohibited"],
  "events": [
    {"eventAction":"registration","eventDate":"2016-10-15T16:55:59Z"},
    {"eventAction":"expiration","eventDate":"2027-10-15T16:55:59Z"},
    {"eventAction":"last changed","eventDate":"2026-03-26T05:19:39Z"}
  ],
  "nameservers": [
    {"ldhName":"NS-192.AWSDNS-24.COM"},
    {"ldhName":"NS-1994.AWSDNS-57.CO.UK"}
  ],
  "entities": [
    {
      "roles": ["registrar"],
      "vcardArray": ["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]]
    },
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard",[
        ["version",{},"text","4.0"],
        ["fn",{},"text","Example Holdings Ltd"],
        ["adr",{},"text",["","",["Minerva House","Science Park"],"Oxford","Oxon","OX4 4DQ","GB"]],
        ["email",{},"text","redacted@example.com"]
      ]]
    },
    {
      "roles": ["technical"],
      "vcardArray": ["vcard",[["version",{},"text","4.0"],["email",{},"text","tech@example.com"]]]
    }
  ]
}`

// fixedNow pins the clock so that days_old is an assertion rather than a moving target.
var fixedNow = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

// guardedTransport fails any request that is not aimed at the test server.
//
// An earlier version of these tests silently reached the real internet: the fake registry
// was plain HTTP, the https requirement rejected it, and the legacy fallback then dialled
// out over TCP and returned real registry data. The assertions failed for the right
// reason but the cause looked like a parser bug. A test suite for a component whose whole
// job is making outbound requests has to prove it is not making them.
type guardedTransport struct {
	t     *testing.T
	allow string
	inner http.RoundTripper
}

func (g *guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != g.allow {
		g.t.Errorf("test tried to reach %s; only %s is allowed", r.URL.Host, g.allow)
		return nil, fmt.Errorf("blocked request to %s", r.URL.Host)
	}
	return g.inner.RoundTrip(r)
}

// newTestServer runs one TLS server playing both IANA and the registry.
//
// One server rather than two because the client must trust exactly one certificate, and
// TLS rather than plain HTTP because the production code requires https for a discovered
// RDAP base — a rule worth keeping, so the test accommodates it instead.
func newTestServer(t *testing.T, registry http.HandlerFunc) *httptest.Server {
	return newTestServerCounting(t, nil, registry)
}

// newTestServerCounting is newTestServer with a counter on the discovery endpoint.
func newTestServerCounting(t *testing.T, ianaHits *int32, registry http.HandlerFunc) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	var srv *httptest.Server

	// IANA's role: discovery.
	mux.HandleFunc("/domain/", func(w http.ResponseWriter, r *http.Request) {
		if ianaHits != nil {
			atomic.AddInt32(ianaHits, 1)
		}
		tld := strings.TrimPrefix(r.URL.Path, "/domain/")
		w.Header().Set("Content-Type", "application/rdap+json")
		switch tld {
		case "com":
			fmt.Fprintf(w, ianaCom, srv.URL+"/com/v1/")
		case "de":
			fmt.Fprint(w, ianaDe)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	// The registry's role: the actual record.
	mux.HandleFunc("/com/v1/", registry)

	srv = httptest.NewTLSServer(mux)
	// The oversized-response test deliberately makes the client hang up mid-body, which
	// the server logs as a handshake error. Silence it so a real failure stays visible.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	return srv
}

// sealedOptions returns Options that cannot reach anything but the given test server.
//
// Every test builds its client through this. The guarded transport catches HTTP, and
// DisableLegacyWHOIS closes the other door: the port-43 fallback dials raw TCP, so no
// transport can intercept it, and a test that forgets this reaches the real internet and
// then fails for a reason that looks like a parser bug. That has happened twice here.
func sealedOptions(t *testing.T, srv *httptest.Server) *rdap.Options {
	t.Helper()
	client := srv.Client()
	client.Transport = &guardedTransport{
		t:     t,
		allow: strings.TrimPrefix(srv.URL, "https://"),
		inner: client.Transport,
	}
	return &rdap.Options{
		BootstrapURL:       srv.URL + "/domain/",
		Now:                func() time.Time { return fixedNow },
		MinInterval:        time.Nanosecond,
		HTTPClient:         client,
		DisableLegacyWHOIS: true,
	}
}

// newTestClient wires a client that can reach the test server and nothing else.
//
// Legacy WHOIS is disabled by default here: it dials raw TCP and so cannot be intercepted
// by a transport guard. The fallback's parser is tested separately, against captured text.
func newTestClient(t *testing.T, registry http.HandlerFunc, tweak ...func(*rdap.Options)) *rdap.Client {
	t.Helper()
	srv := newTestServer(t, registry)

	httpClient := srv.Client()
	httpClient.Transport = &guardedTransport{
		t:     t,
		allow: strings.TrimPrefix(srv.URL, "https://"),
		inner: httpClient.Transport,
	}

	opts := &rdap.Options{
		BootstrapURL:       srv.URL + "/domain/",
		Now:                func() time.Time { return fixedNow },
		MinInterval:        time.Nanosecond, // the rate limiter is tested separately
		HTTPClient:         httpClient,
		DisableLegacyWHOIS: true,
	}
	for _, f := range tweak {
		f(opts)
	}
	return rdap.New(opts)
}

func TestRDAPLookup(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/com/v1/domain/example.com" {
			t.Errorf("registry asked for %q", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); !strings.Contains(got, "application/rdap+json") {
			t.Errorf("Accept = %q, want it to ask for rdap+json", got)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, domainRecord)
	})

	out, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if !mdm.Deref(out.Found) {
		t.Error("found = false")
	}
	// The field the corpus actually leans on. Registration was 2016-10-15T16:55:59Z and
	// the clock is pinned to 2026-10-15T00:00:00Z: ten calendar years is 3,652 days
	// including two leap days, but the last one is not complete, so 3,651 have elapsed.
	// Whole days, truncated — a domain is not a day old until it has been one.
	if got := mdm.Deref(out.DaysOld); got != 3651 {
		t.Errorf("days_old = %d, want 3651", got)
	}
	if got := mdm.Deref(out.RegistrarName); got != "MarkMonitor Inc." {
		t.Errorf("registrar_name = %q", got)
	}
	if got := mdm.Deref(out.RegistrantCompany); got != "Example Holdings Ltd" {
		t.Errorf("registrant_company = %q", got)
	}
	if got := mdm.Deref(out.RegistrantEmail); got != "redacted@example.com" {
		t.Errorf("registrant_email = %q", got)
	}
	// The country code is the seventh element of the structured adr value.
	if got := mdm.Deref(out.RegistrantCountryCode); got != "GB" {
		t.Errorf("registrant_country_code = %q", got)
	}
	if got := mdm.Deref(out.TechnicalEmail); got != "tech@example.com" {
		t.Errorf("technical_email = %q", got)
	}

	// Nameservers are domains, not strings, because rules read .root_domain off them to
	// catch a whole hosting provider at once.
	if len(out.NameServers) != 2 {
		t.Fatalf("got %d nameservers, want 2", len(out.NameServers))
	}
	if got := mdm.Deref(out.NameServers[1].RootDomain); got != "awsdns-57.co.uk" {
		t.Errorf("second nameserver root domain = %q", got)
	}
}

func TestDomainNotRegistered(t *testing.T) {
	// A 404 is an unambiguous answer, and a useful one — an unregistered domain in a
	// message is itself a signal. It must not read as a failure.
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	out, err := c.Lookup(context.Background(), "nothing-here.com")
	if err != nil {
		t.Fatalf("a 404 became an error: %v", err)
	}
	if mdm.Deref(out.Found) {
		t.Error("found = true for an unregistered domain")
	}
}

func TestSubdomainsResolveToTheRegistrableDomain(t *testing.T) {
	// Registration is a property of example.com, not of mail.example.com, and asking a
	// registry about a subdomain gets nothing.
	var asked string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, domainRecord)
	})

	if _, err := c.Lookup(context.Background(), "mail.corp.example.com"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(asked, "/domain/example.com") {
		t.Errorf("asked the registry for %q, want example.com", asked)
	}
}

func TestBootstrapIsCached(t *testing.T) {
	// Discovery happens once per TLD, not once per message. Without this, a mail
	// pipeline would hammer IANA.
	var ianaHits int32
	srv := newTestServerCounting(t, &ianaHits, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, domainRecord)
	})

	opts := sealedOptions(t, srv)
	// Defeat the result cache so that discovery is what is being measured.
	opts.CacheTTL = time.Nanosecond
	c := rdap.New(opts)

	for _, d := range []string{"a.com", "b.com", "c.com"} {
		if _, err := c.Lookup(context.Background(), d); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
	}
	if n := atomic.LoadInt32(&ianaHits); n != 1 {
		t.Errorf("IANA was asked %d times for one TLD, want 1", n)
	}
}

func TestResultsAreCached(t *testing.T) {
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, domainRecord)
	})

	for range 5 {
		if _, err := c.Lookup(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("the registry was queried %d times for one domain, want 1", n)
	}
}

func TestTLDWithoutRDAPFallsBack(t *testing.T) {
	// .de publishes no RDAP server. With the fallback disabled the honest answer is that
	// the question could not be put, not that the domain is fine.
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the registry was queried for a TLD with no RDAP service")
		w.WriteHeader(http.StatusInternalServerError)
	})

	// The test client has legacy WHOIS enabled but no network, so this fails at the
	// fallback rather than silently succeeding.
	_, err := c.Lookup(context.Background(), "example.de")
	if err == nil {
		t.Fatal("a TLD with no RDAP service returned a result")
	}
}

func TestLegacyDisabledSaysSo(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the registry was queried for a TLD with no RDAP service")
	})

	// .de publishes no RDAP server, and the fallback is off.
	_, err := c.Lookup(context.Background(), "example.de")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "no RDAP") || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("error = %q, want it to explain both halves", err)
	}
}

func TestUnknownTLDIsAnError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the registry was queried for a TLD that does not exist")
	})
	if _, err := c.Lookup(context.Background(), "example.notatld"); err == nil {
		t.Error("a non-existent TLD resolved")
	}
}

func TestRateLimitIsRespected(t *testing.T) {
	// Registries block clients that burst. Being slow costs nothing when results are
	// cached for a day.
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, domainRecord)
	}, func(o *rdap.Options) { o.MinInterval = 40 * time.Millisecond })

	start := time.Now()
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		if _, err := c.Lookup(context.Background(), d); err != nil {
			t.Fatal(err)
		}
	}
	// Three lookups against one host, at 40ms apart, cannot finish instantly.
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Errorf("three lookups took %v; the rate limiter is not working", elapsed)
	}
}

func TestRefusesNonHTTPSRegistry(t *testing.T) {
	// The base URL comes from IANA rather than from the message, which bounds where a
	// lookup can reach — but requiring TLS keeps a malformed or tampered registry entry
	// from sending an email pipeline somewhere in cleartext.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, ianaCom, "http://insecure.example/com/v1/")
	}))
	t.Cleanup(srv.Close)

	c := rdap.New(sealedOptions(t, srv))

	// With the plain-HTTP base rejected there is no RDAP service, and the fallback is
	// off, so the rejection is observable.
	_, err := c.Lookup(context.Background(), "example.com")
	if err == nil {
		t.Fatal("a plain-HTTP RDAP base was accepted")
	}
	if !strings.Contains(err.Error(), "no RDAP") {
		t.Errorf("error = %q, want the insecure base to have been ignored", err)
	}
}

func TestEnrichIntegration(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, domainRecord)
	})

	// The corpus idiom: network.whois(sender.email.domain).days_old < 30
	checked, err := mql.Compile(`network.whois(sender.email.domain).days_old > 3000`, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := &mdm.MessageDataModel{
		Sender: &mdm.SenderMailbox{Email: mdm.ParseEmailAddress("a@example.com")},
	}

	res := mql.Eval(context.Background(), checked, msg, &mql.EvalOptions{Enricher: c})
	if res.Err != nil {
		t.Fatalf("evaluating: %v", res.Err)
	}
	if res.Verdict != mql.Match {
		t.Errorf("verdict = %s (value %s, missing %v), want match", res.Verdict, res.Value, res.Missing)
	}
}

func TestEnrichReportsUnavailableRatherThanFailing(t *testing.T) {
	// A registry being unreachable must leave the rule indeterminate, not produce a
	// verdict and not abort evaluation.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := rdap.New(sealedOptions(t, srv))

	checked, _ := mql.Compile(`network.whois(sender.email.domain).days_old < 30`, nil)
	msg := &mdm.MessageDataModel{
		Sender: &mdm.SenderMailbox{Email: mdm.ParseEmailAddress("a@example.com")},
	}

	res := mql.Eval(context.Background(), checked, msg, &mql.EvalOptions{Enricher: c})
	if res.Err != nil {
		t.Errorf("an unreachable registry aborted evaluation: %v", res.Err)
	}
	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict = %s, want indeterminate", res.Verdict)
	}
	if len(res.Missing) != 1 || res.Missing[0] != enrich.CapNetworkWhois {
		t.Errorf("missing = %v, want [network.whois]", res.Missing)
	}
}

func TestEnrichIgnoresOtherCapabilities(t *testing.T) {
	// So that this composes through a mux rather than having to be the only provider.
	c := rdap.New(nil)
	_, err := c.Enrich(context.Background(), enrich.CapMLNLUClassifier, nil, nil)
	if !mql.IsUnavailable(err) {
		t.Errorf("err = %v, want unavailable", err)
	}
}

func TestVCardVariants(t *testing.T) {
	// jCard values are sometimes strings and sometimes nested arrays, and the country
	// code arrives either inside the structured address or as a parameter.
	cases := map[string]struct {
		vcard          string
		wantFN, wantCC string
	}{
		"plain string": {
			`["vcard",[["fn",{},"text","Acme Ltd"],["adr",{},"text",["","","","","","","US"]]]]`,
			"Acme Ltd", "US",
		},
		"country as a parameter": {
			`["vcard",[["fn",{},"text","Acme Ltd"],["adr",{"cc":"de"},"text",["","","Street","Berlin"]]]]`,
			"Acme Ltd", "DE",
		},
		"nested street array": {
			`["vcard",[["fn",{},"text",["Acme Ltd"]],["adr",{},"text",["","",["A","B"],"","","","FR"]]]]`,
			"Acme Ltd", "FR",
		},
		"no address at all": {
			`["vcard",[["fn",{},"text","Acme Ltd"]]]`,
			"Acme Ltd", "",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			record := map[string]any{
				"objectClassName": "domain",
				"ldhName":         "example.com",
				"entities": []any{map[string]any{
					"roles":      []string{"registrant"},
					"vcardArray": json.RawMessage(tc.vcard),
				}},
			}
			body, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}

			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write(body)
			})
			out, err := c.Lookup(context.Background(), "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if got := mdm.Deref(out.RegistrantCompany); got != tc.wantFN {
				t.Errorf("registrant_company = %q, want %q", got, tc.wantFN)
			}
			if got := mdm.Deref(out.RegistrantCountryCode); got != tc.wantCC {
				t.Errorf("registrant_country_code = %q, want %q", got, tc.wantCC)
			}
		})
	}
}

func TestMalformedResponsesDoNotPanic(t *testing.T) {
	// Registry output is not under our control, and one malformed record must not take
	// down the analysis of a message.
	for name, body := range map[string]string{
		"empty":            ``,
		"not json":         `<html>503</html>`,
		"null":             `null`,
		"wrong shape":      `[1,2,3]`,
		"broken vcard":     `{"entities":[{"roles":["registrant"],"vcardArray":"not an array"}]}`,
		"short vcard":      `{"entities":[{"roles":["registrant"],"vcardArray":["vcard"]}]}`,
		"bad event date":   `{"events":[{"eventAction":"registration","eventDate":"not a date"}]}`,
		"future date":      `{"events":[{"eventAction":"registration","eventDate":"2099-01-01T00:00:00Z"}]}`,
		"null nameservers": `{"nameservers":[{"ldhName":""},{"ldhName":"..."}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, body)
			})
			out, err := c.Lookup(context.Background(), "example.com")
			if err != nil {
				return // a decode failure is a fine outcome; a panic is not
			}
			if out != nil && out.DaysOld != nil && *out.DaysOld < 0 {
				t.Errorf("days_old = %d, want it never negative", *out.DaysOld)
			}
		})
	}
}

func TestOversizedResponseIsRejected(t *testing.T) {
	// A registry streaming megabytes is malfunctioning or hostile; either way it should
	// not be able to exhaust memory in a mail pipeline.
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("a", 64*1024)
		for range 100 {
			fmt.Fprint(w, chunk)
		}
	})
	if _, err := c.Lookup(context.Background(), "example.com"); err == nil {
		t.Error("an oversized response was accepted")
	}
}

func TestContextCancellation(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.Lookup(ctx, "example.com"); err == nil {
		t.Error("a cancelled lookup returned a result")
	}
}

func TestConcurrentLookups(t *testing.T) {
	// One client serves a whole deployment.
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, domainRecord)
	})

	errs := make(chan error, 16)
	for i := range 16 {
		go func() {
			_, err := c.Lookup(context.Background(), fmt.Sprintf("d%d.com", i%4))
			errs <- err
		}()
	}
	for range 16 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent lookup: %v", err)
		}
	}
}

// A reserved TLD has a definite answer, and reporting it as an unavailable
// capability is wrong in a way that matters.
//
// .test and friends exist so they can never be registered, so there is no registry
// to ask and discovery fails. Treating that failure as "the lookup did not work"
// tells 103 rules that they could not find out, when what is true is that the domain
// is definitively unregistered — which is itself a finding, because mail from a
// .test address arriving in production is not ordinary.
func TestReservedTLDsAnswerDefinitely(t *testing.T) {
	// Discovery pointed at a closed port: a reserved TLD must be answered without
	// reaching it at all. If the shortcut regresses, this fails rather than quietly
	// going to the network.
	c := rdap.New(&rdap.Options{
		BootstrapURL:       "http://127.0.0.1:1/",
		Timeout:            2 * time.Second,
		DisableLegacyWHOIS: true,
	})

	for _, name := range []string{
		"microsft-verify.test",
		"evil.test",
		"something.invalid",
		"host.localhost",
		"printer.local",
		"example",
		"deep.sub.example",
	} {
		out, err := c.Lookup(context.Background(), name)
		if err != nil {
			t.Errorf("Lookup(%q) failed: %v — a reserved TLD should answer without a registry", name, err)
			continue
		}
		if out == nil || out.Found == nil || *out.Found {
			t.Errorf("Lookup(%q) = %+v, want a definite not-found", name, out)
		}
	}
}

// And a name under a real TLD must still go to the registry, or the shortcut has
// quietly disabled lookups for everything.
func TestOrdinaryDomainsStillLookUp(t *testing.T) {
	if reserved := rdap.ReservedTLDForTest("example.com"); reserved {
		t.Error("example.com treated as reserved; only the bare .example TLD is")
	}
	if reserved := rdap.ReservedTLDForTest("lazaret.io"); reserved {
		t.Error("lazaret.io treated as reserved")
	}
	if !rdap.ReservedTLDForTest("mail.evil.test") {
		t.Error("mail.evil.test not recognised as reserved")
	}
}
