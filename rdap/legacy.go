// SPDX-License-Identifier: AGPL-3.0-only

package rdap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
)

// Legacy WHOIS, reached only when a TLD publishes no RDAP service.
//
// Everything below is best-effort by nature, and that is the argument for RDAP rather
// than an apology for this file. WHOIS is free text over a cleartext socket: there is no
// schema, no content type, no status code, and no agreement between registries on what a
// field is called or how a date is written. What follows recognises the shapes that
// actually occur, and returns what it could not recognise as absent rather than guessing.
//
// Results from here carry the same type as RDAP results, so rules do not need to care —
// but a deployment that would rather have no answer than a parsed-from-prose one can set
// DisableLegacyWHOIS.

const (
	// ianaWHOIS is the root WHOIS server, which knows which server serves each TLD.
	ianaWHOIS = "whois.iana.org:43"

	// whoisPort is the standard WHOIS port. The protocol is: connect, send the query and
	// a CRLF, read until the server closes.
	whoisPort = "43"

	// maxWHOISBytes caps a response. Records are kilobytes; a server streaming more than
	// this is malfunctioning or hostile.
	maxWHOISBytes = 1 << 20
)

// legacyLookup queries the TLD's WHOIS server.
func (c *Client) legacyLookup(ctx context.Context, name string) (*mdm.WhoisOutput, error) {
	server, err := c.whoisServerFor(ctx, tldOf(name))
	if err != nil {
		return nil, err
	}
	if server == "" {
		return nil, fmt.Errorf("%w and no WHOIS server is published either", ErrNoRDAP)
	}

	text, err := c.whoisQuery(ctx, server, name)
	if err != nil {
		return nil, fmt.Errorf("whois: %s via %s: %w", name, server, err)
	}
	return c.parseLegacy(name, text), nil
}

// whoisServerFor asks IANA which WHOIS server serves a TLD, caching the answer alongside
// the RDAP bootstrap results.
func (c *Client) whoisServerFor(ctx context.Context, tld string) (string, error) {
	key := "whois:" + strings.ToLower(tld)

	c.mu.Lock()
	entry, ok := c.bootstrap[key]
	c.mu.Unlock()
	if ok && c.opts.now().Before(entry.expires) {
		return entry.base, nil
	}

	text, err := c.whoisQuery(ctx, ianaWHOIS, tld)
	if err != nil {
		return "", fmt.Errorf("whois: finding the server for .%s: %w", tld, err)
	}

	var server string
	for _, line := range strings.Split(text, "\n") {
		k, v, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "whois") {
			continue
		}
		if server = strings.TrimSpace(v); server != "" {
			break
		}
	}

	c.mu.Lock()
	c.bootstrap[key] = bootstrapEntry{base: server, expires: c.opts.now().Add(c.opts.BootstrapTTL)}
	c.mu.Unlock()
	return server, nil
}

// whoisQuery performs one port-43 exchange.
func (c *Client) whoisQuery(ctx context.Context, server, query string) (string, error) {
	host := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		host = net.JoinHostPort(server, whoisPort)
	}

	release, err := c.acquire(ctx, host)
	if err != nil {
		return "", err
	}
	defer release()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.opts.timeout()))
	}

	// The whole protocol: a query, CRLF, then read until the server hangs up.
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, maxWHOISBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// notFoundMarkers are the phrases registries use to say a domain is unregistered.
//
// There is no status code to consult, so this is the only way to tell "not registered"
// from "here is the record" — and getting it wrong in either direction is worse than
// unhelpful. It is also the clearest single illustration of why RDAP is preferred: there,
// the same question is answered by an HTTP 404.
var notFoundMarkers = []string{
	"no match", "not found", "no entries found", "no data found",
	"domain not found", "status: free", "status: available",
	"no object found", "nothing found", "not registered",
	"no such domain", "no matching record", "object does not exist",
	"domain name not known", "no information available about domain name",
}

// legacyKeys maps the field names registries use onto what the model wants. Several
// spellings per field, because there is no standard.
var legacyKeys = map[string]string{
	"creation date": "created", "created": "created", "created on": "created",
	"registered on": "created", "registration time": "created", "domain_datecreated": "created",
	"registered": "created", "create date": "created",

	"registrar": "registrar", "registrar name": "registrar", "sponsoring registrar": "registrar",

	"registrant organization": "org", "registrant organisation": "org", "org": "org",
	"registrant": "org", "registrant name": "registrant_name", "registrant contact name": "registrant_name",

	"registrant email": "registrant_email", "registrant contact email": "registrant_email",
	"admin email": "admin_email", "administrative contact email": "admin_email",
	"tech email": "tech_email", "technical contact email": "tech_email",

	"registrant country": "country", "registrant country/economy": "country",

	"name server": "ns", "nserver": "ns", "nameserver": "ns", "name servers": "ns",
}

// legacyDateLayouts are the formats that actually appear. RDAP mandates one; WHOIS has
// accumulated these.
var legacyDateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"02.01.2006",
	"2006/01/02",
	"20060102",
	"Mon Jan 2 15:04:05 2006",
	"Mon Jan  2 15:04:05 MST 2006",
}

// parseLegacy reads what it can out of a WHOIS response.
func (c *Client) parseLegacy(name, text string) *mdm.WhoisOutput {
	lower := strings.ToLower(text)
	for _, marker := range notFoundMarkers {
		if strings.Contains(lower, marker) {
			return &mdm.WhoisOutput{Found: mdm.Ptr(false), Domain: mdm.ParseDomain(name)}
		}
	}

	out := &mdm.WhoisOutput{Found: mdm.Ptr(true), Domain: mdm.ParseDomain(name)}
	seen := map[string]bool{}

	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		rawKey, rawValue, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value := strings.TrimSpace(rawValue)
		if value == "" {
			continue
		}
		field, known := legacyKeys[strings.ToLower(strings.TrimSpace(rawKey))]
		if !known {
			continue
		}

		// Records repeat fields — one line per nameserver, and sometimes a field once per
		// contact. First wins, except for nameservers where all of them are wanted.
		if field != "ns" && seen[field] {
			continue
		}
		seen[field] = true

		switch field {
		case "created":
			if t, ok := parseLegacyDate(value); ok {
				days := int64(c.opts.now().Sub(t).Hours() / 24)
				if days < 0 {
					days = 0
				}
				out.DaysOld = &days
			}
		case "registrar":
			out.RegistrarName = mdm.Ptr(value)
		case "org":
			out.RegistrantCompany = mdm.Ptr(value)
		case "registrant_name":
			out.RegistrantName = mdm.Ptr(value)
		case "registrant_email":
			out.RegistrantEmail = mdm.Ptr(value)
		case "admin_email":
			out.AdministrativeEmail = mdm.Ptr(value)
		case "tech_email":
			out.TechnicalEmail = mdm.Ptr(value)
		case "country":
			out.RegistrantCountry = mdm.Ptr(value)
			if len(value) == 2 {
				out.RegistrantCountryCode = mdm.Ptr(strings.ToUpper(value))
			}
		case "ns":
			// A nameserver line often carries the glue address after the host.
			host := strings.Fields(value)[0]
			if d := mdm.ParseDomain(strings.ToLower(strings.TrimSuffix(host, "."))); d != nil {
				out.NameServers = append(out.NameServers, d)
			}
		}
	}
	return out
}

func parseLegacyDate(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	// Some registries append a note after the timestamp.
	if i := strings.Index(v, " ("); i > 0 {
		v = strings.TrimSpace(v[:i])
	}
	for _, layout := range legacyDateLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
