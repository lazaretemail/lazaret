// SPDX-License-Identifier: AGPL-3.0-only

package mdm

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// The constructors in this file turn text into Message Data Model values.
//
// They live here rather than in the EML parser because two callers need identical
// behaviour: the parser, building the model from a message, and MQL's strings.parse_domain,
// parse_email and parse_url, which rules apply to text found inside a message. If those
// disagreed, a rule that re-parsed a value it had already been handed could reach a
// different conclusion about the same string.

// ParseDomain splits a hostname into its registrable parts.
//
// Returns nil when the input cannot be a domain at all, matching the documented behaviour
// that an unparseable domain yields null rather than an empty object.
func ParseDomain(s string) *Domain {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, ".")
	if s == "" || strings.ContainsAny(s, " \t\r\n/@") {
		return nil
	}

	// Attackers register internationalised lookalikes, so the punycode form is kept
	// alongside the display form: a rule comparing against "microsoft.com" should not be
	// defeated by an encoding choice.
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		// Not a resolvable name, but rules still match on malformed hosts, so the value is
		// returned with what could be determined rather than discarded.
		ascii = strings.ToLower(s)
	}

	d := &Domain{Domain: strings.ToLower(s)}
	if ascii != d.Domain {
		d.Punycode = &ascii
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	valid := err == nil
	d.Valid = &valid

	suffix, icann := publicsuffix.PublicSuffix(ascii)
	if suffix != "" && suffix != ascii {
		d.TLD = &suffix
	} else if suffix == ascii {
		// The whole name is a public suffix ("co.uk"), so there is no registrable domain.
		d.TLD = &suffix
		return d
	}
	_ = icann

	if !valid {
		return d
	}

	root := strings.ToLower(etld1)
	d.RootDomain = &root

	// The second-level label is the registrable name without its suffix: for
	// "mail.example.co.uk" the root is "example.co.uk" and the SLD is "example".
	if sld, _, found := strings.Cut(etld1, "."); found {
		l := strings.ToLower(sld)
		d.SLD = &l
	}

	if sub := strings.TrimSuffix(ascii, etld1); sub != "" {
		sub = strings.ToLower(strings.TrimSuffix(sub, "."))
		if sub != "" {
			d.Subdomain = &sub
		}
	}
	return d
}

// ParseEmailAddress splits an address into its local part and domain.
//
// The input is the bare addr-spec, not a full mailbox: display names and angle brackets are
// the caller's problem, because the header parser has already dealt with RFC 2047 encoding
// by the time it gets here.
func ParseEmailAddress(s string) *EmailAddress {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "<>")
	if s == "" {
		return nil
	}

	// Split on the last "@": quoted local parts may legitimately contain one.
	at := strings.LastIndex(s, "@")
	if at < 0 {
		// No domain at all. Rules do match on malformed senders, so the address is kept
		// with the local part filled in rather than thrown away.
		lower := strings.ToLower(s)
		return &EmailAddress{Email: &lower, LocalPart: &lower}
	}

	local, host := s[:at], s[at+1:]
	// Local parts are case-sensitive per RFC 5321, but every real provider folds them and
	// every rule in the corpus compares them case-insensitively, so they are normalised.
	email := strings.ToLower(s)
	lower := strings.ToLower(local)

	addr := &EmailAddress{Email: &email, LocalPart: &lower}
	addr.Domain = ParseDomain(host)
	return addr
}

// ParseURL parses a link target.
//
// With strict set, a URL must carry an explicit scheme; without it, a bare host such as
// "example.com/path" is accepted and treated as http. Returns nil when the input cannot be
// interpreted as a URL at all.
func ParseURL(s string, strict bool) *URL {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return nil
	}

	work := raw
	if !hasScheme(work) {
		if strict {
			return nil
		}
		work = "http://" + work
	}

	u, err := url.Parse(work)
	if err != nil {
		return nil
	}

	out := &URL{URL: raw}
	if u.Scheme != "" {
		scheme := strings.ToLower(u.Scheme)
		out.Scheme = &scheme
	}

	host := u.Hostname()
	if host != "" {
		// A literal IP is not a domain. Rules distinguish the two — a bare address in a
		// link is itself a signal — so the IP field is populated and Domain left nil.
		if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			version := int64(4)
			if addr.Is6() {
				version = 6
			}
			out.IP = &IP{IP: addr.String(), Version: &version}
		} else {
			out.Domain = ParseDomain(host)
		}
	}

	if p := u.Port(); p != "" {
		if n, err := strconv.ParseInt(p, 10, 64); err == nil {
			out.Port = &n
		}
	}
	if u.Path != "" {
		path := u.Path
		out.Path = &path
	}
	if u.RawQuery != "" {
		q := u.RawQuery
		out.QueryParams = &q
		if decoded, err := url.ParseQuery(q); err == nil && len(decoded) > 0 {
			out.QueryParamsDecoded = decoded
		}
	}
	if u.Fragment != "" {
		frag := u.Fragment
		out.Fragment = &frag
	}
	if u.User != nil {
		// Credentials in a link are a phishing signal in their own right.
		name := u.User.Username()
		out.Username = &name
		if pw, ok := u.User.Password(); ok {
			out.Password = &pw
		}
	}
	return out
}

// hasScheme reports whether s begins with a URI scheme. It does not use url.Parse, which
// happily reads "example.com:8080" as the scheme "example.com".
func hasScheme(s string) bool {
	colon := strings.Index(s, ":")
	if colon <= 0 {
		return false
	}
	scheme := s[:colon]
	for i, r := range scheme {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	rest := s[colon+1:]
	switch {
	case strings.HasPrefix(rest, "//"):
		// Hierarchical URL: unambiguous.
		return true
	case strings.Contains(scheme, "."):
		// Schemes never contain dots, hostnames usually do. "example.com:8080/x" is a host
		// and a port, however much the colon suggests otherwise.
		return false
	case rest != "" && rest[0] >= '0' && rest[0] <= '9':
		// "localhost:8080" — a port, not the opaque part of a scheme.
		return false
	}
	// Non-hierarchical schemes such as mailto: and tel: put the target straight after the
	// colon, so anything left here is one of those.
	return rest != ""
}

// Ptr returns a pointer to v. Optional MDM fields are pointers so that absent and empty can
// be told apart, which makes building a model by hand verbose without a helper like this.
func Ptr[T any](v T) *T { return &v }

// Deref returns the value behind p, or the zero value when p is nil.
func Deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
