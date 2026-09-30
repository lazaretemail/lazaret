// SPDX-License-Identifier: AGPL-3.0-only

package eml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"net/netip"
	"regexp"
	"strings"

	"github.com/emersion/go-message"

	"github.com/lazaretemail/lazaret/mdm"
)

// parseHeaders fills in everything derived from the top-level header block.
func (p *parser) parseHeaders(m *mdm.MessageDataModel, h message.Header) {
	hdr := &mdm.Headers{}
	m.Headers = hdr

	if v := headerText(h, "Message-Id"); v != "" {
		hdr.MessageID = mdm.Ptr(strings.Trim(v, "<>"))
	}
	if v := headerText(h, "In-Reply-To"); v != "" {
		hdr.InReplyTo = mdm.Ptr(strings.Trim(v, "<>"))
	}
	if v := headerText(h, "References"); v != "" {
		hdr.References = splitReferences(v)
	}
	if v := headerText(h, "X-Mailer"); v != "" {
		hdr.Mailer = mdm.Ptr(v)
	} else if v := headerText(h, "User-Agent"); v != "" {
		hdr.Mailer = mdm.Ptr(v)
	}

	if v := h.Get("Date"); v != "" {
		if t, err := mail.ParseDate(v); err == nil {
			utc := t.UTC()
			hdr.Date = &utc
			if _, offset := t.Zone(); true {
				// The original offset is retained separately: a message claiming a
				// timezone inconsistent with its routing is a signal, and converting to
				// UTC would erase it.
				hdr.DateOriginalOffset = mdm.Ptr(formatOffset(offset))
			}
		} else {
			p.recordf("header", "date %q: %v", v, err)
		}
	}

	// Sender identity. From is what the recipient sees, and is what impersonation rules
	// work against; Return-Path is where bounces go and is frequently different.
	if from := p.mailboxes(h, "From"); len(from) > 0 {
		hdr.From = from[0]
		m.Sender = &mdm.SenderMailbox{
			DisplayName: from[0].DisplayName,
			Email:       from[0].Email,
		}
		if len(from) > 1 {
			p.recordf("header", "From has %d addresses; using the first", len(from))
		}
	} else {
		m.Sender = &mdm.SenderMailbox{}
	}

	hdr.ReplyTo = p.mailboxes(h, "Reply-To")
	if rp := headerText(h, "Return-Path"); rp != "" {
		hdr.ReturnPath = mdm.ParseEmailAddress(rp)
	}
	if dt := headerText(h, "Delivered-To"); dt != "" {
		hdr.DeliveredTo = mdm.ParseEmailAddress(dt)
	}
	if xs := headerText(h, "X-Sender"); xs != "" {
		hdr.XSender = mdm.ParseEmailAddress(xs)
	}
	if xs := headerText(h, "X-Authenticated-Sender"); xs != "" {
		hdr.XAuthenticatedSender = mdm.ParseEmailAddress(xs)
	}
	if xd := headerText(h, "X-Authenticated-Domain"); xd != "" {
		hdr.XAuthenticatedDomain = mdm.ParseDomain(xd)
	}
	if ip := firstIP(headerText(h, "X-Originating-IP")); ip != nil {
		hdr.XOriginatingIP = ip
	}
	if ip := firstIP(headerText(h, "X-Client-IP")); ip != nil {
		hdr.XClientIP = ip
	}

	m.Recipients = &mdm.Recipients{
		To:  p.mailboxes(h, "To"),
		CC:  p.mailboxes(h, "Cc"),
		BCC: p.mailboxes(h, "Bcc"),
	}
	m.Mailbox = &mdm.MailboxExtended{}

	m.Subject = parseSubject(headerText(h, "Subject"))

	p.parseHops(hdr, h)
	p.summariseAuth(hdr)
	hdr.Domains = collectHeaderDomains(m, hdr)
	hdr.IPs = collectHeaderIPs(hdr)
}

// headerText reads a header and decodes any RFC 2047 encoded-words in it. Falling back to
// the raw value matters: a malformed encoded-word is common in phishing and the undecoded
// text is still worth matching on.
func headerText(h message.Header, key string) string {
	if v, err := h.Text(key); err == nil {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(h.Get(key))
}

// mailboxes parses an address-list header.
func (p *parser) mailboxes(h message.Header, key string) []*mdm.Mailbox {
	raw := h.Get(key)
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	addrs, err := (&mail.AddressParser{WordDecoder: &wordDecoder}).ParseList(raw)
	if err != nil {
		// Address lists in real mail are frequently malformed, and the addresses in them
		// are exactly what rules need. Fall back to splitting by hand rather than
		// discarding the header.
		if boxes := looseAddressList(raw); len(boxes) > 0 {
			p.recordf("header", "%s: %v (recovered %d addresses)", key, err, len(boxes))
			return boxes
		}
		p.recordf("header", "%s: %v", key, err)
		return nil
	}

	out := make([]*mdm.Mailbox, 0, len(addrs))
	for _, a := range addrs {
		mb := &mdm.Mailbox{Email: mdm.ParseEmailAddress(a.Address)}
		if a.Name != "" {
			mb.DisplayName = mdm.Ptr(a.Name)
		}
		out = append(out, mb)
	}
	return out
}

// wordDecoder decodes RFC 2047 encoded-words, tolerating charsets Go does not know.
var wordDecoder = mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		// Unknown charset: hand back the bytes unchanged rather than failing the whole
		// address list. Mojibake is more useful to a rule than a missing sender.
		return input, nil
	},
}

// looseAddressList salvages addresses from a header net/mail refused.
func looseAddressList(raw string) []*mdm.Mailbox {
	var out []*mdm.Mailbox
	for _, piece := range splitOutsideQuotes(raw, ',') {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		display, addr := piece, piece
		if lt := strings.LastIndex(piece, "<"); lt >= 0 {
			if gt := strings.Index(piece[lt:], ">"); gt >= 0 {
				addr = piece[lt+1 : lt+gt]
				display = strings.TrimSpace(piece[:lt])
			}
		} else {
			display = ""
		}
		parsed := mdm.ParseEmailAddress(addr)
		// ParseEmailAddress tolerates a missing domain, which is right when a header
		// genuinely holds a malformed address but wrong here: this is a salvage path over
		// text that may not be an address list at all, and without the check every comma-
		// separated fragment of an attribution line becomes a "sender".
		if parsed == nil || parsed.Domain == nil {
			continue
		}
		mb := &mdm.Mailbox{Email: parsed}
		if display = strings.Trim(strings.TrimSpace(display), `"`); display != "" {
			if decoded, err := wordDecoder.DecodeHeader(display); err == nil {
				display = decoded
			}
			mb.DisplayName = mdm.Ptr(display)
		}
		out = append(out, mb)
	}
	return out
}

// splitOutsideQuotes splits on sep, ignoring separators inside double quotes. Display names
// legitimately contain commas: `"Surname, Forename" <a@b.com>`.
func splitOutsideQuotes(s string, sep byte) []string {
	var out []string
	var start int
	var inQuotes bool
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			inQuotes = !inQuotes
		case sep:
			if !inQuotes {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// subjectPrefix matches the reply and forward markers mail clients prepend, in the
// languages that appear in real traffic. Stripping them is what gives subject.base, which
// rules use to compare a reply against the thread it claims to belong to.
var subjectPrefix = regexp.MustCompile(`(?i)^\s*((re|aw|sv|vs|antw|odp|ref|fwd?|tr|wg|enc|rv|vs|res)\s*(\[\d+\])?\s*:\s*)+`)

var forwardPrefix = regexp.MustCompile(`(?i)\b(fwd?|tr|wg|enc|rv)\s*(\[\d+\])?\s*:`)
var replyPrefix = regexp.MustCompile(`(?i)\b(re|aw|sv|antw|odp|ref|res)\s*(\[\d+\])?\s*:`)

// subjectTag matches the bracketed tags mailing lists and scanners prepend, as in
// "[EXTERNAL]" or "[SPAM]".
var subjectTag = regexp.MustCompile(`^\s*\[([^\]]{1,64})\]\s*`)

func parseSubject(raw string) *mdm.Subject {
	s := &mdm.Subject{Subject: mdm.Ptr(raw)}

	rest := raw
	for {
		loc := subjectTag.FindStringSubmatch(rest)
		if loc == nil {
			break
		}
		s.Tags = append(s.Tags, loc[1])
		rest = rest[len(loc[0]):]
	}

	prefixes := subjectPrefix.FindString(rest)
	s.IsReply = mdm.Ptr(prefixes != "" && replyPrefix.MatchString(prefixes))
	s.IsForward = mdm.Ptr(prefixes != "" && forwardPrefix.MatchString(prefixes))
	s.Base = mdm.Ptr(strings.TrimSpace(rest[len(prefixes):]))

	// Auto-replies announce themselves in the subject often enough to be worth a flag, and
	// the header that should carry it (Auto-Submitted) is frequently missing.
	s.IsAutoReply = mdm.Ptr(regexp.MustCompile(`(?i)\b(out of (the )?office|automatic reply|auto(matic)?[ -]?respon[sd])`).MatchString(raw))

	for _, u := range extractURLsFromText(raw) {
		s.URLs = append(s.URLs, u)
	}
	return s
}

func splitReferences(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ','
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.Trim(f, "<>"); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ipPattern finds addresses in free-form header text. Headers wrap them in brackets,
// parentheses, or nothing at all depending on the MTA.
var ipPattern = regexp.MustCompile(`\[?([0-9a-fA-F:]*:[0-9a-fA-F:.]+|\d{1,3}(?:\.\d{1,3}){3})\]?`)

func firstIP(s string) *mdm.IP {
	for _, m := range ipPattern.FindAllStringSubmatch(s, -1) {
		if ip := parseIP(m[1]); ip != nil {
			return ip
		}
	}
	return nil
}

func parseIP(s string) *mdm.IP {
	addr, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return nil
	}
	version := int64(4)
	if addr.Is6() && !addr.Is4In6() {
		version = 6
	}
	out := &mdm.IP{IP: addr.String(), Version: &version}
	if addr.Is4In6() {
		// An IPv4 address written in IPv6 form is a mild obfuscation, and rules that match
		// on address ranges need to see through it.
		out.Translation = &mdm.IPTranslation{
			Original: mdm.Ptr(s),
			V4ToV6:   mdm.Ptr(true),
		}
		out.IP = addr.Unmap().String()
	}
	return out
}

// collectHeaderDomains gathers every domain named anywhere in the headers, which is what
// `headers.domains` exposes for rules that want to check the whole routing path at once.
func collectHeaderDomains(m *mdm.MessageDataModel, hdr *mdm.Headers) []*mdm.Domain {
	seen := map[string]bool{}
	var out []*mdm.Domain

	add := func(d *mdm.Domain) {
		if d == nil || seen[d.Domain] {
			return
		}
		seen[d.Domain] = true
		out = append(out, d)
	}
	addAddr := func(a *mdm.EmailAddress) {
		if a != nil {
			add(a.Domain)
		}
	}

	if m.Sender != nil {
		addAddr(m.Sender.Email)
	}
	for _, mb := range allRecipients(m) {
		addAddr(mb.Email)
	}
	for _, mb := range hdr.ReplyTo {
		addAddr(mb.Email)
	}
	addAddr(hdr.ReturnPath)
	addAddr(hdr.DeliveredTo)
	addAddr(hdr.XSender)
	add(hdr.XAuthenticatedDomain)

	for _, hop := range hdr.Hops {
		if hop.Signature != nil && hop.Signature.Domain != nil {
			add(mdm.ParseDomain(*hop.Signature.Domain))
		}
		if hop.AuthenticationResults != nil {
			add(hop.AuthenticationResults.Server)
		}
	}
	return out
}

// collectHeaderIPs gathers the addresses the message was relayed through.
func collectHeaderIPs(hdr *mdm.Headers) []*mdm.IP {
	seen := map[string]bool{}
	var out []*mdm.IP
	add := func(ip *mdm.IP) {
		if ip == nil || seen[ip.IP] {
			return
		}
		seen[ip.IP] = true
		out = append(out, ip)
	}
	add(hdr.XOriginatingIP)
	add(hdr.XClientIP)
	for _, hop := range hdr.Hops {
		if hop.Received != nil && hop.Received.Source != nil && hop.Received.Source.Raw != nil {
			add(firstIP(*hop.Received.Source.Raw))
		}
		if hop.ReceivedSPF != nil {
			add(hop.ReceivedSPF.ClientIP)
		}
	}
	return out
}

func formatOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign, seconds = "-", -seconds
	}
	return fmt.Sprintf("%s%02d%02d", sign, seconds/3600, (seconds%3600)/60)
}

// canonicalID identifies a message by its content. Two copies of the same message
// delivered to different mailboxes share one canonical identity, which is what lets the
// platform group them later.
func canonicalID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
