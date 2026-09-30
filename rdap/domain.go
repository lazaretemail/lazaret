// SPDX-License-Identifier: AGPL-3.0-only

package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
)

// rdapResponse is the part of RFC 9083 this package reads.
//
// Deliberately partial: RDAP responses carry a great deal that no rule has ever asked
// for, and decoding into a narrow struct means a registry adding a field cannot break
// parsing.
type rdapResponse struct {
	ObjectClassName string       `json:"objectClassName"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Status          []string     `json:"status"`
	Events          []rdapEvent  `json:"events"`
	Entities        []rdapEntity `json:"entities"`
	Nameservers     []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Links []rdapLink `json:"links"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapLink struct {
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type"`
	Title string `json:"title"`
}

// rdapEntity is a party associated with a domain: registrar, registrant, technical or
// administrative contact.
type rdapEntity struct {
	Roles      []string        `json:"roles"`
	Handle     string          `json:"handle"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

// rdapBase resolves a TLD to its RDAP service, caching the answer.
//
// An empty base with a nil error means the TLD has no RDAP service — a real, stable fact
// about .de among others, and the reason the legacy fallback exists.
func (c *Client) rdapBase(ctx context.Context, tld string) (string, error) {
	tld = strings.ToLower(tld)

	c.mu.Lock()
	entry, ok := c.bootstrap[tld]
	c.mu.Unlock()
	if ok && c.opts.now().Before(entry.expires) {
		return entry.base, nil
	}

	base, err := c.discover(ctx, tld)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.bootstrap[tld] = bootstrapEntry{base: base, expires: c.opts.now().Add(c.opts.BootstrapTTL)}
	c.mu.Unlock()
	return base, nil
}

// discover asks IANA which RDAP server serves a TLD.
//
// IANA's own RDAP record for the TLD carries the answer as a link of type
// "application/rdap+json" — the entry titled "RDAP Server". The self link has the same
// type and points back at IANA, so it has to be excluded or discovery loops.
func (c *Client) discover(ctx context.Context, tld string) (string, error) {
	body, status, err := c.get(ctx, c.opts.bootstrapURL()+url.PathEscape(tld))
	if err != nil {
		return "", fmt.Errorf("whois: discovering RDAP for .%s: %w", tld, err)
	}
	if status == http.StatusNotFound {
		// Not a TLD at all. Nothing to fall back to either.
		return "", fmt.Errorf("whois: .%s is not a delegated TLD", tld)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("whois: discovering RDAP for .%s: HTTP %d", tld, status)
	}

	var doc rdapResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("whois: discovering RDAP for .%s: %w", tld, err)
	}

	for _, l := range doc.Links {
		if !strings.EqualFold(l.Type, "application/rdap+json") {
			continue
		}
		if strings.EqualFold(l.Rel, "self") {
			continue
		}
		base, err := validRDAPBase(l.Href)
		if err != nil {
			continue
		}
		return base, nil
	}
	// No RDAP service for this TLD, which is a fact rather than a failure.
	return "", nil
}

// validRDAPBase checks a discovered URL before anything is sent to it.
//
// The URL comes from IANA rather than from the message, which already bounds where a
// lookup can reach, but requiring HTTPS and a real host keeps a compromised or malformed
// registry entry from redirecting an email pipeline somewhere unexpected.
func validRDAPBase(href string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("RDAP base %q is not https", href)
	}
	if u.Host == "" {
		return "", fmt.Errorf("RDAP base %q has no host", href)
	}
	return strings.TrimSuffix(u.String(), "/") + "/", nil
}

// rdapLookup fetches and converts one domain record.
func (c *Client) rdapLookup(ctx context.Context, base, name string) (*mdm.WhoisOutput, error) {
	body, status, err := c.get(ctx, base+"domain/"+url.PathEscape(name))
	if err != nil {
		return nil, fmt.Errorf("whois: %s: %w", name, err)
	}

	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		// An unambiguous answer, and a useful one: a domain in a message that is not
		// registered at all is itself worth knowing.
		return &mdm.WhoisOutput{
			Found:  mdm.Ptr(false),
			Domain: mdm.ParseDomain(name),
		}, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("whois: %s: rate limited by the registry", name)
	default:
		return nil, fmt.Errorf("whois: %s: HTTP %d", name, status)
	}

	var doc rdapResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("whois: %s: %w", name, err)
	}
	return c.convert(name, &doc), nil
}

// convert maps an RDAP record onto the model.
func (c *Client) convert(name string, doc *rdapResponse) *mdm.WhoisOutput {
	out := &mdm.WhoisOutput{Found: mdm.Ptr(true)}

	reported := doc.LDHName
	if reported == "" {
		reported = name
	}
	out.Domain = mdm.ParseDomain(strings.ToLower(reported))

	// days_old is the field the corpus actually leans on — 116 references — because a
	// domain registered last week is the cheapest reliable phishing signal there is.
	if t, ok := eventDate(doc.Events, "registration"); ok {
		days := int64(c.opts.now().Sub(t).Hours() / 24)
		if days < 0 {
			// A registration date in the future is a registry error, not a negative age.
			days = 0
		}
		out.DaysOld = &days
	}

	for _, ns := range doc.Nameservers {
		if d := mdm.ParseDomain(strings.ToLower(ns.LDHName)); d != nil {
			out.NameServers = append(out.NameServers, d)
		}
	}

	for _, e := range doc.Entities {
		card := parseVCard(e.VCardArray)
		for _, role := range e.Roles {
			switch strings.ToLower(role) {
			case "registrar":
				if card.fn != "" {
					out.RegistrarName = mdm.Ptr(card.fn)
				}
			case "registrant":
				// RDAP does not separate a person from an organisation, so `org` is
				// taken as the company and `fn` as the name, which is how registries
				// populate them in practice.
				if card.org != "" {
					out.RegistrantCompany = mdm.Ptr(card.org)
				}
				if card.fn != "" {
					out.RegistrantName = mdm.Ptr(card.fn)
					if card.org == "" {
						out.RegistrantCompany = mdm.Ptr(card.fn)
					}
				}
				if card.email != "" {
					out.RegistrantEmail = mdm.Ptr(card.email)
				}
				if card.country != "" {
					out.RegistrantCountryCode = mdm.Ptr(strings.ToUpper(card.country))
					out.RegistrantCountry = mdm.Ptr(card.country)
				}
			case "technical":
				if card.email != "" {
					out.TechnicalEmail = mdm.Ptr(card.email)
				}
			case "administrative":
				if card.email != "" {
					out.AdministrativeEmail = mdm.Ptr(card.email)
				}
			}
		}
	}
	return out
}

// eventDate finds an RDAP event by action.
func eventDate(events []rdapEvent, action string) (time.Time, bool) {
	for _, e := range events {
		if !strings.EqualFold(e.Action, action) {
			continue
		}
		// RFC 9083 specifies RFC 3339, and registries do comply — one of the reasons to
		// prefer RDAP over guessing at WHOIS date formats.
		if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// vcard is the handful of jCard fields worth reading.
type vcard struct {
	fn    string
	org   string
	email string

	// kind is "org", "group" or "individual". It is what distinguishes the entity that
	// actually holds a resource from the person or role listed alongside it, and
	// ignoring it is how a lookup ends up reporting "Managing Director" as the operator
	// of a network.
	kind string

	country string
}

// parseVCard reads the jCard structure RDAP embeds for each entity.
//
// The shape is ["vcard", [[name, params, type, value], ...]] — an array of arrays, with
// values that may themselves be arrays. It is decoded dynamically rather than into a
// struct because the element types genuinely vary by field.
func parseVCard(raw json.RawMessage) vcard {
	var out vcard
	if len(raw) == 0 {
		return out
	}

	var outer []json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer) < 2 {
		return out
	}
	var props [][]any
	if err := json.Unmarshal(outer[1], &props); err != nil {
		return out
	}

	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		name, _ := p[0].(string)
		switch strings.ToLower(name) {
		case "fn":
			out.fn = firstString(p[3])
		case "kind":
			out.kind = strings.ToLower(firstString(p[3]))
		case "org":
			out.org = firstString(p[3])
		case "email":
			if out.email == "" {
				out.email = firstString(p[3])
			}
		case "adr":
			// The structured form is
			// [pobox, ext, street, locality, region, postcode, country]; the country
			// code can also arrive as a "cc" parameter.
			if params, ok := p[1].(map[string]any); ok {
				if cc := firstString(params["cc"]); cc != "" {
					out.country = cc
				}
			}
			if out.country == "" {
				if parts, ok := p[3].([]any); ok && len(parts) >= 7 {
					out.country = firstString(parts[6])
				}
			}
		}
	}
	return out
}

// firstString flattens a jCard value, which may be a string or a nested array of them.
func firstString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		for _, e := range t {
			if s := firstString(e); s != "" {
				return s
			}
		}
	}
	return ""
}

// get performs one rate-limited, size-capped HTTP request.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}

	release, err := c.acquire(ctx, u.Host)
	if err != nil {
		return nil, 0, err
	}
	defer release()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9")
	req.Header.Set("User-Agent", c.opts.userAgent())

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	// Capped, and one byte over the cap is read so that truncation is detectable rather
	// than silently producing a half-record.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > maxResponseBytes {
		return nil, resp.StatusCode, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	return body, resp.StatusCode, nil
}

// reservedTLDs are the top-level domains that exist precisely so they cannot be
// registered.
//
// RFC 2606 sets aside .test, .example, .invalid and .localhost; RFC 6761 restates
// them as special-use and adds .local for mDNS; RFC 7686 adds .onion. None has a
// registry, so RDAP discovery for them does not fail by accident — there is nothing
// there to discover, by design and permanently.
var reservedTLDs = map[string]bool{
	"test":      true,
	"example":   true,
	"invalid":   true,
	"localhost": true,
	"local":     true,
	"onion":     true,
	// Not a TLD but reserved the same way, and it turns up in home-router mail.
	"home.arpa": true,
}

// reservedTLD reports whether a name sits under one of them.
func reservedTLD(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if reservedTLDs[name] {
		return true
	}
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return false
	}
	if reservedTLDs[name[i+1:]] {
		return true
	}
	// home.arpa is two labels deep.
	return strings.HasSuffix(name, ".home.arpa")
}
