// SPDX-License-Identifier: AGPL-3.0-only

package rdap_test

import (
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/rdap"
)

// The legacy parser is tested against captured registry output rather than over a socket.
// The socket is the uninteresting part; the parsing is where this can quietly be wrong,
// and being quietly wrong is the whole argument for preferring RDAP.

// legacyClient is only ever used to call the parser directly, so it never opens a
// socket — but it is sealed anyway, so that adding a test here later cannot quietly
// start reaching real registries.
func legacyClient() *rdap.Client {
	return rdap.New(&rdap.Options{
		Now:                func() time.Time { return fixedNow },
		DisableLegacyWHOIS: true,
	})
}

// denicResponse is DENIC's format. .de publishes no RDAP service at all, which is what
// makes this fallback necessary rather than ceremonial.
const denicResponse = `% Restricted rights.
Domain: example.de
Status: connect
Changed: 2024-03-11T09:12:44+01:00
Nserver: ns1.example.de 81.169.145.68
Nserver: ns2.example.de
`

// verisignStyle is the gTLD shape, which most registries follow loosely.
const verisignStyle = `   Domain Name: EXAMPLE.COM
   Registrar: MarkMonitor Inc.
   Creation Date: 2016-10-15T16:55:59Z
   Registry Expiry Date: 2027-10-15T16:55:59Z
   Registrant Organization: Example Holdings Ltd
   Registrant Country: GB
   Registrant Email: redacted@example.com
   Admin Email: admin@example.com
   Tech Email: tech@example.com
   Name Server: NS1.EXAMPLE.COM
   Name Server: NS2.EXAMPLE.COM
>>> Last update of whois database: 2026-09-19T00:00:00Z <<<
`

func TestLegacyParsesGTLDShape(t *testing.T) {
	out := legacyClient().ParseLegacyForTest("example.com", verisignStyle)

	if !mdm.Deref(out.Found) {
		t.Fatal("found = false")
	}
	if got := mdm.Deref(out.DaysOld); got != 3651 {
		t.Errorf("days_old = %d, want 3651", got)
	}
	if got := mdm.Deref(out.RegistrarName); got != "MarkMonitor Inc." {
		t.Errorf("registrar_name = %q", got)
	}
	if got := mdm.Deref(out.RegistrantCompany); got != "Example Holdings Ltd" {
		t.Errorf("registrant_company = %q", got)
	}
	if got := mdm.Deref(out.RegistrantCountryCode); got != "GB" {
		t.Errorf("registrant_country_code = %q", got)
	}
	if got := mdm.Deref(out.RegistrantEmail); got != "redacted@example.com" {
		t.Errorf("registrant_email = %q", got)
	}
	if got := mdm.Deref(out.TechnicalEmail); got != "tech@example.com" {
		t.Errorf("technical_email = %q", got)
	}
	if got := mdm.Deref(out.AdministrativeEmail); got != "admin@example.com" {
		t.Errorf("administrative_email = %q", got)
	}
	if len(out.NameServers) != 2 {
		t.Errorf("got %d nameservers, want 2", len(out.NameServers))
	}
}

func TestLegacyParsesDENICShape(t *testing.T) {
	// A different field vocabulary entirely: Nserver rather than Name Server, and no
	// creation date published at all. What cannot be read is absent rather than guessed.
	out := legacyClient().ParseLegacyForTest("example.de", denicResponse)

	if !mdm.Deref(out.Found) {
		t.Fatal("found = false")
	}
	if out.DaysOld != nil {
		t.Errorf("days_old = %d, but DENIC publishes no creation date", *out.DaysOld)
	}
	if len(out.NameServers) != 2 {
		t.Fatalf("got %d nameservers, want 2", len(out.NameServers))
	}
	// A nameserver line carries the glue address after the host; only the host is wanted.
	if got := out.NameServers[0].Domain; got != "ns1.example.de" {
		t.Errorf("first nameserver = %q, want the glue address stripped", got)
	}
}

func TestLegacyRecognisesUnregistered(t *testing.T) {
	// There is no status code in WHOIS, so "not registered" has to be recognised from
	// prose — and getting it wrong in either direction is worse than unhelpful. This is
	// the clearest single illustration of why RDAP, where the same question is answered
	// by an HTTP 404, is preferred.
	for name, text := range map[string]string{
		"verisign": "No match for \"NOTHING-HERE.COM\".\n",
		"nominet":  "    No such domain nothing-here.uk\n",
		"denic":    "Status: free\n",
		"generic":  "Domain not found.\n",
		"afilias":  "NOT FOUND\n",
	} {
		t.Run(name, func(t *testing.T) {
			out := legacyClient().ParseLegacyForTest("nothing-here.com", text)
			if mdm.Deref(out.Found) {
				t.Errorf("found = true for %q", text)
			}
		})
	}
}

func TestLegacyDateFormats(t *testing.T) {
	// RDAP mandates RFC 3339. WHOIS has accumulated these, and a format this parser does
	// not know means days_old is silently absent for every domain under that registry —
	// which is exactly the failure mode RDAP avoids.
	for _, line := range []string{
		"Creation Date: 2016-10-15T16:55:59Z",
		"Created On: 2016-10-15 16:55:59",
		"created: 2016-10-15",
		"Registered on: 15-Oct-2016",
		"Registration Time: 2016/10/15",
		"created: 20161015",
	} {
		t.Run(line, func(t *testing.T) {
			out := legacyClient().ParseLegacyForTest("example.com", line+"\n")
			if out.DaysOld == nil {
				t.Fatalf("no date parsed from %q", line)
			}
			// All of these are the same day, give or take the time of day.
			if got := *out.DaysOld; got < 3651 || got > 3652 {
				t.Errorf("days_old = %d, want about 3651", got)
			}
		})
	}
}

func TestLegacyIgnoresCommentsAndUnknownFields(t *testing.T) {
	out := legacyClient().ParseLegacyForTest("example.com", `% a comment
# another comment

Some Unknown Field: ignored
Registrar: Real Registrar Ltd
Registrar: A Second One That Should Not Win
`)
	if got := mdm.Deref(out.RegistrarName); got != "Real Registrar Ltd" {
		t.Errorf("registrar_name = %q, want the first occurrence", got)
	}
}

func TestLegacyNeverReportsNegativeAge(t *testing.T) {
	// A registration date in the future is a registry error, not a negative age.
	out := legacyClient().ParseLegacyForTest("example.com", "Creation Date: 2099-01-01T00:00:00Z\n")
	if got := mdm.Deref(out.DaysOld); got != 0 {
		t.Errorf("days_old = %d, want 0", got)
	}
}

func TestLegacyHandlesGarbage(t *testing.T) {
	// Registry output is not under our control and one malformed record must not take
	// down the analysis of a message.
	for name, text := range map[string]string{
		"empty":       "",
		"html":        "<html><body>503 Service Unavailable</body></html>",
		"no colons":   "just some words with no structure at all",
		"only colons": ":::::\n:\n",
		"huge line":   "Registrar: " + string(make([]byte, 100000)),
	} {
		t.Run(name, func(t *testing.T) {
			if out := legacyClient().ParseLegacyForTest("example.com", text); out == nil {
				t.Error("nil result")
			}
		})
	}
}
