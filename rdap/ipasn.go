// SPDX-License-Identifier: AGPL-3.0-only

package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
)

// IP and ASN lookups.
//
// # Why these are worth having in an email engine
//
// A message's Received chain is a list of addresses, and the interesting question about
// each one is rarely "which address is it" but "whose network is it". A relay in a range
// allocated last month, or held by a hosting provider that exists to be abused, is a far
// more durable signal than any individual address: attackers rotate addresses freely and
// netblocks slowly.
//
// The corpus already reaches for this indirectly. Its largest single rule is a 242 KB
// list of Spamhaus CIDR ranges compiled into one beta.ip_in call — a snapshot of exactly
// the attribution these lookups provide directly, frozen at the moment the rule was
// generated.
//
// # Discovery is different from domains
//
// IANA's RDAP server answers for the root zone only; asking it about an address returns
// 501. Addresses and AS numbers use the RFC 9224 bootstrap registries instead — three
// published JSON files mapping ranges to the RIR that serves them. Those are fetched once
// and cached, which is both simpler and cheaper than per-object discovery.
//
// # Not part of Sublime's language
//
// MQL has no IP or ASN function, so these are registered as extensions under the `rdap`
// namespace and never appear in the standard registry. See Extend.

// Bootstrap registry locations, per RFC 9224.
const (
	BootstrapIPv4URL = "https://data.iana.org/rdap/ipv4.json"
	BootstrapIPv6URL = "https://data.iana.org/rdap/ipv6.json"
	BootstrapASNURL  = "https://data.iana.org/rdap/asn.json"
)

// bootstrapFile is the published format: a list of services, each pairing a set of keys
// with the URLs that serve them.
type bootstrapFile struct {
	Description string       `json:"description"`
	Publication string       `json:"publication"`
	Version     string       `json:"version"`
	Services    [][][]string `json:"services"`
}

// ipService is one parsed IP bootstrap entry.
type ipService struct {
	prefix netip.Prefix
	base   string
}

// asnService is one parsed ASN bootstrap entry.
type asnService struct {
	start, end uint32
	base       string
}

// registryCache holds the parsed bootstrap files.
type registryCache struct {
	mu      sync.Mutex
	ips     []ipService
	asns    []asnService
	ipsAt   time.Time
	asnsAt  time.Time
	ipsErr  error
	asnsErr error
}

// LookupIP returns registration data for an address.
//
// A range that is unallocated yields Found false with no error — that is an answer, and
// mail arriving from unallocated space is itself notable.
func (c *Client) LookupIP(ctx context.Context, addr string) (*mdm.IPInfo, error) {
	ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(addr), "[]"))
	if err != nil {
		return nil, fmt.Errorf("rdap: %q is not an IP address", addr)
	}
	ip = ip.Unmap()

	// Addresses no registry has anything to say about are answered here.
	//
	// Two reasons, and the second is the one that matters. Asking ARIN about
	// 10.0.0.3 cannot return anything useful, so the round trip is wasted on every
	// message that crossed an internal relay — which is most of them. And it tells
	// a third party what this organisation's internal addressing looks like, one
	// lookup at a time, which is not a thing to leak in exchange for nothing.
	if nonPublic(ip) {
		return &mdm.IPInfo{IP: mdm.Ptr(ip.String()), Found: mdm.Ptr(false)}, nil
	}

	key := "ip:" + ip.String()
	if v, err, ok := c.cachedAny(key); ok {
		out, _ := v.(*mdm.IPInfo)
		return out, err
	}

	out, err := c.lookupIPUncached(ctx, ip)
	c.storeAny(key, out, err)
	return out, err
}

func (c *Client) lookupIPUncached(ctx context.Context, ip netip.Addr) (*mdm.IPInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.timeout())
	defer cancel()

	base, err := c.ipBase(ctx, ip)
	if err != nil {
		return nil, err
	}
	if base == "" {
		// Not in any RIR's space: unallocated, reserved, or private. Worth reporting as
		// a definite answer rather than as a failure.
		return &mdm.IPInfo{Found: mdm.Ptr(false), IP: mdm.Ptr(ip.String())}, nil
	}

	body, status, err := c.get(ctx, base+"ip/"+ip.String())
	if err != nil {
		return nil, fmt.Errorf("rdap: %s: %w", ip, err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return &mdm.IPInfo{Found: mdm.Ptr(false), IP: mdm.Ptr(ip.String())}, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rdap: %s: rate limited by the registry", ip)
	default:
		return nil, fmt.Errorf("rdap: %s: HTTP %d", ip, status)
	}

	var doc ipResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("rdap: %s: %w", ip, err)
	}
	return c.convertIP(ip, &doc), nil
}

// LookupASN returns registration data for an autonomous system number.
func (c *Client) LookupASN(ctx context.Context, asn uint32) (*mdm.ASNInfo, error) {
	key := "asn:" + strconv.FormatUint(uint64(asn), 10)
	if v, err, ok := c.cachedAny(key); ok {
		out, _ := v.(*mdm.ASNInfo)
		return out, err
	}

	out, err := c.lookupASNUncached(ctx, asn)
	c.storeAny(key, out, err)
	return out, err
}

func (c *Client) lookupASNUncached(ctx context.Context, asn uint32) (*mdm.ASNInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.timeout())
	defer cancel()

	base, err := c.asnBase(ctx, asn)
	if err != nil {
		return nil, err
	}
	if base == "" {
		return &mdm.ASNInfo{Found: mdm.Ptr(false), ASN: mdm.Ptr(int64(asn))}, nil
	}

	body, status, err := c.get(ctx, base+"autnum/"+strconv.FormatUint(uint64(asn), 10))
	if err != nil {
		return nil, fmt.Errorf("rdap: AS%d: %w", asn, err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return &mdm.ASNInfo{Found: mdm.Ptr(false), ASN: mdm.Ptr(int64(asn))}, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rdap: AS%d: rate limited by the registry", asn)
	default:
		return nil, fmt.Errorf("rdap: AS%d: HTTP %d", asn, status)
	}

	var doc autnumResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("rdap: AS%d: %w", asn, err)
	}
	return c.convertASN(asn, &doc), nil
}

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

// ipBase finds the RIR serving an address, preferring the most specific prefix.
//
// The registries are not disjoint in practice — a /8 delegated to one RIR can contain a
// smaller range transferred to another — so the longest match wins.
func (c *Client) ipBase(ctx context.Context, ip netip.Addr) (string, error) {
	services, err := c.ipServices(ctx, ip.Is4())
	if err != nil {
		return "", err
	}
	best, bestBits := "", -1
	for _, s := range services {
		if s.prefix.Contains(ip) && s.prefix.Bits() > bestBits {
			best, bestBits = s.base, s.prefix.Bits()
		}
	}
	return best, nil
}

func (c *Client) asnBase(ctx context.Context, asn uint32) (string, error) {
	services, err := c.asnServices(ctx)
	if err != nil {
		return "", err
	}
	// Narrowest containing range wins, for the same reason.
	best, bestWidth := "", ^uint64(0)
	for _, s := range services {
		if asn < s.start || asn > s.end {
			continue
		}
		if width := uint64(s.end) - uint64(s.start); width < bestWidth {
			best, bestWidth = s.base, width
		}
	}
	return best, nil
}

func (c *Client) ipServices(ctx context.Context, v4 bool) ([]ipService, error) {
	c.registries.mu.Lock()
	fresh := c.registries.ips != nil && c.opts.now().Sub(c.registries.ipsAt) < c.opts.BootstrapTTL
	if fresh {
		defer c.registries.mu.Unlock()
		return c.registries.ips, c.registries.ipsErr
	}
	c.registries.mu.Unlock()

	// Both families are fetched together: a deployment analysing mail will see each
	// within moments of the other, and two files is one fewer decision.
	var all []ipService
	var firstErr error
	for _, src := range []struct {
		url string
		v4  bool
	}{{c.opts.bootstrapIPv4URL(), true}, {c.opts.bootstrapIPv6URL(), false}} {
		file, err := c.fetchBootstrap(ctx, src.url)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, svc := range file.Services {
			if len(svc) < 2 {
				continue
			}
			base := preferHTTPS(svc[1])
			if base == "" {
				continue
			}
			for _, key := range svc[0] {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(key))
				if err != nil {
					continue
				}
				all = append(all, ipService{prefix: prefix, base: base})
			}
		}
	}
	if len(all) == 0 && firstErr != nil {
		return nil, firstErr
	}

	c.registries.mu.Lock()
	c.registries.ips, c.registries.ipsAt, c.registries.ipsErr = all, c.opts.now(), nil
	c.registries.mu.Unlock()
	return all, nil
}

func (c *Client) asnServices(ctx context.Context) ([]asnService, error) {
	c.registries.mu.Lock()
	if c.registries.asns != nil && c.opts.now().Sub(c.registries.asnsAt) < c.opts.BootstrapTTL {
		defer c.registries.mu.Unlock()
		return c.registries.asns, c.registries.asnsErr
	}
	c.registries.mu.Unlock()

	file, err := c.fetchBootstrap(ctx, c.opts.bootstrapASNURL())
	if err != nil {
		return nil, err
	}

	var all []asnService
	for _, svc := range file.Services {
		if len(svc) < 2 {
			continue
		}
		base := preferHTTPS(svc[1])
		if base == "" {
			continue
		}
		for _, key := range svc[0] {
			start, end, ok := parseASNRange(key)
			if !ok {
				continue
			}
			all = append(all, asnService{start: start, end: end, base: base})
		}
	}

	c.registries.mu.Lock()
	c.registries.asns, c.registries.asnsAt, c.registries.asnsErr = all, c.opts.now(), nil
	c.registries.mu.Unlock()
	return all, nil
}

func (c *Client) fetchBootstrap(ctx context.Context, url string) (*bootstrapFile, error) {
	body, status, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("rdap: fetching %s: %w", url, err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("rdap: fetching %s: HTTP %d", url, status)
	}
	var file bootstrapFile
	if err := json.Unmarshal(body, &file); err != nil {
		return nil, fmt.Errorf("rdap: parsing %s: %w", url, err)
	}
	return &file, nil
}

// preferHTTPS picks a base URL, insisting on TLS.
//
// The registries list both schemes for several RIRs, and the plaintext one would send
// lookups of attacker-chosen addresses over the wire in clear.
func preferHTTPS(urls []string) string {
	for _, u := range urls {
		if base, err := validRDAPBase(u); err == nil {
			return base
		}
	}
	return ""
}

// parseASNRange reads a bootstrap key, which is either "15169" or "36864-37887".
func parseASNRange(key string) (start, end uint32, ok bool) {
	key = strings.TrimSpace(key)
	lo, hi, found := strings.Cut(key, "-")

	s, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if !found {
		return uint32(s), uint32(s), true
	}
	e, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if e < s {
		return 0, 0, false
	}
	return uint32(s), uint32(e), true
}

// ---------------------------------------------------------------------------
// response shapes and conversion
// ---------------------------------------------------------------------------

type ipResponse struct {
	Handle       string       `json:"handle"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	IPVersion    string       `json:"ipVersion"`
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	Country      string       `json:"country"`
	ParentHandle string       `json:"parentHandle"`
	Status       []string     `json:"status"`
	Events       []rdapEvent  `json:"events"`
	Entities     []rdapEntity `json:"entities"`
	Port43       string       `json:"port43"`

	// cidr0_cidrs is the structured-CIDR extension. Far better than inferring a prefix
	// from the start and end addresses, which is only unambiguous when the range happens
	// to be aligned.
	CIDRs []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`

	// ARIN publishes the originating AS numbers as an extension. Not every RIR does, so
	// it is read when present and never depended on.
	OriginAutnums []int64 `json:"arin_originas0_originautnums"`
}

type autnumResponse struct {
	Handle      string       `json:"handle"`
	StartAutnum int64        `json:"startAutnum"`
	EndAutnum   int64        `json:"endAutnum"`
	Name        string       `json:"name"`
	Type        string       `json:"type"`
	Country     string       `json:"country"`
	Status      []string     `json:"status"`
	Events      []rdapEvent  `json:"events"`
	Entities    []rdapEntity `json:"entities"`
}

func (c *Client) convertIP(ip netip.Addr, doc *ipResponse) *mdm.IPInfo {
	out := &mdm.IPInfo{
		Found: mdm.Ptr(true),
		IP:    mdm.Ptr(ip.String()),
	}
	setIfNotEmpty(&out.Handle, doc.Handle)
	setIfNotEmpty(&out.Name, doc.Name)
	setIfNotEmpty(&out.Type, doc.Type)
	setIfNotEmpty(&out.ParentHandle, doc.ParentHandle)
	setIfNotEmpty(&out.StartAddress, doc.StartAddress)
	setIfNotEmpty(&out.EndAddress, doc.EndAddress)
	setIfNotEmpty(&out.Country, strings.ToUpper(doc.Country))
	out.Status = doc.Status

	for _, cidr := range doc.CIDRs {
		prefix := cidr.V4Prefix
		if prefix == "" {
			prefix = cidr.V6Prefix
		}
		if prefix == "" {
			continue
		}
		out.CIDR = append(out.CIDR, fmt.Sprintf("%s/%d", prefix, cidr.Length))
	}

	for _, n := range doc.OriginAutnums {
		out.ASNs = append(out.ASNs, n)
	}

	if t, ok := eventDate(doc.Events, "registration"); ok {
		out.DaysOld = mdm.Ptr(c.daysSince(t))
	}

	// The organisation holding the range is the field worth having: attackers rotate
	// addresses constantly and netblocks slowly, so "who owns this space" outlives any
	// individual address.
	applyEntities(doc.Entities, &out.Organization, &out.AbuseEmail, &out.Country)
	return out
}

func (c *Client) convertASN(asn uint32, doc *autnumResponse) *mdm.ASNInfo {
	out := &mdm.ASNInfo{
		Found: mdm.Ptr(true),
		ASN:   mdm.Ptr(int64(asn)),
	}
	setIfNotEmpty(&out.Handle, doc.Handle)
	setIfNotEmpty(&out.Name, doc.Name)
	setIfNotEmpty(&out.Type, doc.Type)
	setIfNotEmpty(&out.Country, strings.ToUpper(doc.Country))
	out.Status = doc.Status
	if doc.StartAutnum > 0 {
		out.StartASN = mdm.Ptr(doc.StartAutnum)
	}
	if doc.EndAutnum > 0 {
		out.EndASN = mdm.Ptr(doc.EndAutnum)
	}
	if t, ok := eventDate(doc.Events, "registration"); ok {
		out.DaysOld = mdm.Ptr(c.daysSince(t))
	}

	applyEntities(doc.Entities, &out.Organization, &out.AbuseEmail, &out.Country)
	return out
}

// applyEntities pulls the organisation and abuse contact out of an entity list.
//
// Picking the organisation needs care. A record lists several entities and the first one
// is frequently a person or a role rather than the operator: RIPE's record for its own
// range leads with an administrative entity whose name is "Managing Director", while the
// entity that actually holds the allocation is further down with kind "org". Reporting
// the former would make the most valuable field in this whole type wrong in a way that
// looks plausible.
//
// So candidates are scored, and the best wins:
//
//	registrant with kind "org"   the operator, stated unambiguously
//	any entity with kind "org"   an organisation, if not the registrant
//	registrant of any kind       probably right
//	administrative               last resort
//
// The vcard `org` field is deliberately not used: at RIPE it holds a handle such as
// "ORG-NCC1-RIPE" rather than a name.
func applyEntities(entities []rdapEntity, org, abuse, country **string) {
	bestScore := 0

	consider := func(e rdapEntity, card vcard) {
		for _, role := range e.Roles {
			score := 0
			switch strings.ToLower(role) {
			case "registrant":
				score = 2
				if card.kind == "org" {
					score = 4
				}
			case "administrative":
				score = 1
			default:
				if card.kind == "org" {
					score = 3
				}
			}
			if score > bestScore && card.fn != "" {
				bestScore = score
				*org = mdm.Ptr(card.fn)
			}
			if *country == nil && card.country != "" {
				*country = mdm.Ptr(strings.ToUpper(card.country))
			}
			if strings.EqualFold(role, "abuse") && *abuse == nil && card.email != "" {
				*abuse = mdm.Ptr(card.email)
			}
		}
	}

	for _, e := range entities {
		card := parseVCard(e.VCardArray)
		consider(e, card)
		// The abuse contact is nested one level down at several RIRs — an abuse entity
		// inside the registrant — so the search descends rather than only reading the top.
		for _, sub := range e.Entities {
			subCard := parseVCard(sub.VCardArray)
			for _, role := range sub.Roles {
				if strings.EqualFold(role, "abuse") && *abuse == nil && subCard.email != "" {
					*abuse = mdm.Ptr(subCard.email)
				}
			}
		}
	}
}

// daysSince returns whole days elapsed, never negative: a registration date in the future
// is a registry error rather than a negative age.
func (c *Client) daysSince(t time.Time) int64 {
	days := int64(c.opts.now().Sub(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

func setIfNotEmpty(dst **string, v string) {
	if v = strings.TrimSpace(v); v != "" {
		*dst = mdm.Ptr(v)
	}
}

// documentationRanges are the address blocks IANA reserved for examples and
// benchmarking. No RIR holds registration data for them, and they never appear as
// a genuine sending address.
var documentationRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1, RFC 5737
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking, RFC 2544
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier NAT, RFC 6598
	netip.MustParsePrefix("2001:db8::/32"),   // documentation, RFC 3849
}

// nonPublic reports whether an address is one the global registries do not cover.
func nonPublic(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range documentationRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
