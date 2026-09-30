// SPDX-License-Identifier: AGPL-3.0-only

package mdm_test

import (
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
)

func str(p *string) string { return mdm.Deref(p) }

func TestParseDomain(t *testing.T) {
	tests := []struct {
		in                          string
		domain, root, sld, sub, tld string
		valid                       bool
	}{
		{"sublimesecurity.com", "sublimesecurity.com", "sublimesecurity.com", "sublimesecurity", "", "com", true},
		{"mail.sublimesecurity.com", "mail.sublimesecurity.com", "sublimesecurity.com", "sublimesecurity", "mail", "com", true},
		{"a.b.c.example.co.uk", "a.b.c.example.co.uk", "example.co.uk", "example", "a.b.c", "co.uk", true},
		{"EXAMPLE.COM", "example.com", "example.com", "example", "", "com", true},

		// A trailing dot is a fully-qualified name, not a different domain.
		{"example.com.", "example.com", "example.com", "example", "", "com", true},

		// Free subdomain hosts are a standing abuse pattern, and the whole point of
		// tracking the registrable boundary is that evil.github.io is not github.io.
		{"evil.github.io", "evil.github.io", "evil.github.io", "evil", "", "github.io", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			d := mdm.ParseDomain(tc.in)
			if d == nil {
				t.Fatalf("ParseDomain(%q) = nil", tc.in)
			}
			if d.Domain != tc.domain {
				t.Errorf("domain = %q, want %q", d.Domain, tc.domain)
			}
			if got := str(d.RootDomain); got != tc.root {
				t.Errorf("root_domain = %q, want %q", got, tc.root)
			}
			if got := str(d.SLD); got != tc.sld {
				t.Errorf("sld = %q, want %q", got, tc.sld)
			}
			if got := str(d.Subdomain); got != tc.sub {
				t.Errorf("subdomain = %q, want %q", got, tc.sub)
			}
			if got := str(d.TLD); got != tc.tld {
				t.Errorf("tld = %q, want %q", got, tc.tld)
			}
			if mdm.Deref(d.Valid) != tc.valid {
				t.Errorf("valid = %v, want %v", mdm.Deref(d.Valid), tc.valid)
			}
		})
	}
}

func TestParseDomainPunycode(t *testing.T) {
	// Homograph attacks are a core detection target: the display form and the ASCII form
	// must both be available, or a rule comparing against the real brand misses.
	d := mdm.ParseDomain("аpple.com") // leading char is Cyrillic а, not Latin a
	if d == nil {
		t.Fatal("ParseDomain returned nil for an internationalised domain")
	}
	if d.Punycode == nil {
		t.Fatal("no punycode form recorded for a non-ASCII domain")
	}
	if got := *d.Punycode; got != "xn--pple-43d.com" {
		t.Errorf("punycode = %q, want %q", got, "xn--pple-43d.com")
	}
	if mdm.ParseDomain("apple.com").Punycode != nil {
		t.Error("an ASCII domain should not carry a punycode form")
	}
}

func TestParseDomainRejectsNonDomains(t *testing.T) {
	for _, in := range []string{"", "   ", "not a domain", "user@example.com", "http://x.com", "."} {
		if d := mdm.ParseDomain(in); d != nil {
			t.Errorf("ParseDomain(%q) = %+v, want nil", in, d)
		}
	}
}

func TestParseDomainPublicSuffixOnly(t *testing.T) {
	// "co.uk" is a suffix, not a registrable domain, so there is no root domain to report.
	d := mdm.ParseDomain("co.uk")
	if d == nil {
		t.Fatal("ParseDomain(\"co.uk\") = nil")
	}
	if d.RootDomain != nil {
		t.Errorf("root_domain = %q, want none for a bare public suffix", *d.RootDomain)
	}
}

func TestParseEmailAddress(t *testing.T) {
	addr := mdm.ParseEmailAddress("No-Reply@Mail.Sublimesecurity.com")
	if addr == nil {
		t.Fatal("ParseEmailAddress returned nil")
	}
	if got := str(addr.Email); got != "no-reply@mail.sublimesecurity.com" {
		t.Errorf("email = %q, want it normalised to lower case", got)
	}
	if got := str(addr.LocalPart); got != "no-reply" {
		t.Errorf("local_part = %q, want %q", got, "no-reply")
	}
	if addr.Domain == nil || str(addr.Domain.RootDomain) != "sublimesecurity.com" {
		t.Errorf("domain not parsed: %+v", addr.Domain)
	}

	// Angle brackets are stripped, since headers routinely carry them.
	if got := str(mdm.ParseEmailAddress("<a@b.com>").Email); got != "a@b.com" {
		t.Errorf("email = %q, want the brackets removed", got)
	}

	// A quoted local part may contain an @; the split must be on the last one.
	if got := mdm.ParseEmailAddress(`"a@b"@example.com`).Domain.Domain; got != "example.com" {
		t.Errorf("domain = %q, want example.com", got)
	}
}

func TestParseEmailAddressMalformed(t *testing.T) {
	// Rules match on malformed senders, so a missing domain yields a partial address
	// rather than nothing at all.
	addr := mdm.ParseEmailAddress("justalocalpart")
	if addr == nil {
		t.Fatal("ParseEmailAddress returned nil for an address with no domain")
	}
	if addr.Domain != nil {
		t.Errorf("domain = %+v, want nil", addr.Domain)
	}
	if got := str(addr.LocalPart); got != "justalocalpart" {
		t.Errorf("local_part = %q", got)
	}

	if mdm.ParseEmailAddress("") != nil {
		t.Error("an empty address should parse to nil")
	}
}

func TestParseURL(t *testing.T) {
	u := mdm.ParseURL("https://user:pw@sub.example.co.uk:8443/a/b?x=1&y=2#frag", true)
	if u == nil {
		t.Fatal("ParseURL returned nil")
	}
	if got := str(u.Scheme); got != "https" {
		t.Errorf("scheme = %q", got)
	}
	if u.Domain == nil || str(u.Domain.RootDomain) != "example.co.uk" {
		t.Errorf("domain = %+v", u.Domain)
	}
	if mdm.Deref(u.Port) != 8443 {
		t.Errorf("port = %d, want 8443", mdm.Deref(u.Port))
	}
	if got := str(u.Path); got != "/a/b" {
		t.Errorf("path = %q", got)
	}
	if got := str(u.Fragment); got != "frag" {
		t.Errorf("fragment = %q", got)
	}
	// Credentials embedded in a link are themselves a phishing signal.
	if got := str(u.Username); got != "user" {
		t.Errorf("username = %q", got)
	}
	if got := str(u.Password); got != "pw" {
		t.Errorf("password = %q", got)
	}
	if got := u.QueryParamsDecoded["x"]; len(got) != 1 || got[0] != "1" {
		t.Errorf("query_params_decoded[x] = %v, want [1]", got)
	}

	// The original text is preserved: rules match on the URL exactly as written.
	if u.URL != "https://user:pw@sub.example.co.uk:8443/a/b?x=1&y=2#frag" {
		t.Errorf("url = %q, want the input unchanged", u.URL)
	}
}

func TestParseURLStrictness(t *testing.T) {
	// strict requires an explicit scheme; without it a bare host is assumed to be http.
	if u := mdm.ParseURL("example.com/path", true); u != nil {
		t.Errorf("strict parse of a schemeless URL = %+v, want nil", u)
	}
	u := mdm.ParseURL("example.com/path", false)
	if u == nil {
		t.Fatal("non-strict parse of a schemeless URL returned nil")
	}
	if u.Domain == nil || u.Domain.Domain != "example.com" {
		t.Errorf("domain = %+v", u.Domain)
	}
	// Even so, the recorded URL is what the author wrote, not what we assumed.
	if u.URL != "example.com/path" {
		t.Errorf("url = %q, want the original text", u.URL)
	}

	// "host:8080" is a host and port, not a scheme, however much it looks like one.
	if u := mdm.ParseURL("example.com:8080/x", false); u == nil || u.Domain == nil {
		t.Errorf("host:port misread as a scheme: %+v", u)
	}
}

func TestParseURLWithIPHost(t *testing.T) {
	// A literal address in a link is a signal on its own, so it is recorded as an IP
	// rather than mangled into a domain.
	u := mdm.ParseURL("http://192.168.1.1/login", true)
	if u == nil {
		t.Fatal("ParseURL returned nil")
	}
	if u.Domain != nil {
		t.Errorf("domain = %+v, want nil for a literal address", u.Domain)
	}
	if u.IP == nil || u.IP.IP != "192.168.1.1" {
		t.Fatalf("ip = %+v", u.IP)
	}
	if mdm.Deref(u.IP.Version) != 4 {
		t.Errorf("version = %d, want 4", mdm.Deref(u.IP.Version))
	}

	if u := mdm.ParseURL("http://[2606:4700::1111]/x", true); u == nil || u.IP == nil || mdm.Deref(u.IP.Version) != 6 {
		t.Errorf("IPv6 host not recognised: %+v", u)
	}
}

func TestParseURLMailto(t *testing.T) {
	// mailto: links appear throughout the corpus, including in impersonation rules that
	// compare the target against the recipient.
	u := mdm.ParseURL("mailto:finance@example.com", true)
	if u == nil {
		t.Fatal("ParseURL returned nil for a mailto link")
	}
	if got := str(u.Scheme); got != "mailto" {
		t.Errorf("scheme = %q, want mailto", got)
	}
}

func TestParseURLRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if u := mdm.ParseURL(in, false); u != nil {
			t.Errorf("ParseURL(%q) = %+v, want nil", in, u)
		}
	}
}

func FuzzParsers(f *testing.F) {
	// These run over text pulled out of untrusted messages, so they must not panic on
	// anything, however malformed.
	for _, s := range []string{
		"example.com", "a@b.com", "https://x.y/z?a=1#f", "mailto:a@b",
		"", ".", "@", "://", "http://", "xn--pple-43d.com", "[::1]", "a:1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		mdm.ParseDomain(s)
		mdm.ParseEmailAddress(s)
		mdm.ParseURL(s, true)
		mdm.ParseURL(s, false)
	})
}
