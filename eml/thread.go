// SPDX-License-Identifier: AGPL-3.0-only

package eml

import (
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
)

// Thread splitting separates what the sender just wrote from the conversation they quoted.
//
// This is the most-used field in the whole model — body.current_thread.text appears 2,409
// times in the public rule corpus — and it is also the least specified. Sublime publishes
// the shape of the output but nothing at all about how to produce it. The heuristic below
// is therefore an explicit compatibility risk, documented as such in docs/SEMANTICS.md, and
// deliberately kept in one place so it can be replaced wholesale.
//
// Why it matters that this is right: a rule looking for "please update your bank details"
// in the current thread means the sender said it. If quoted history leaks into the current
// thread, every reply to a legitimate conversation inherits the words of that conversation,
// and rules start firing on the wrong half of the message.

// quoteHeader matches the line a mail client writes above quoted text. The forms below
// cover the clients that actually appear in traffic; each is anchored to the start of a
// line so that prose merely mentioning "wrote:" does not split a message.
var quoteHeaders = []*regexp.Regexp{
	// "On Mon, 1 Jan 2024 at 09:00, Alice <a@b.com> wrote:" — Gmail, Apple Mail, and most
	// clients that follow them. The date and address are both optional in practice.
	regexp.MustCompile(`(?im)^[ \t>]*On\s+.{0,200}?\s+wrote:\s*$`),
	// The same, but with the colon and the quoted block on the following line.
	regexp.MustCompile(`(?im)^[ \t>]*On\s+.{0,200}?\s+wrote:`),
	// Outlook's separator, in several localisations, together with the header block that
	// follows it. The block has to be part of the boundary rather than part of the quoted
	// text, because it is where the quoted message's own headers are recovered from.
	regexp.MustCompile(`(?im)^[ \t>]*-{2,}\s*(Original Message|Forwarded message|Ursprüngliche Nachricht|Message d'origine|Mensaje original)\s*-{2,}\s*$(?:\n[ \t>]*(?:From|Sent|Date|To|Cc|Bcc|Subject|Reply-To|Importance):[^\n]*)*`),
	// Outlook's header block on its own: many versions emit no separator line at all.
	regexp.MustCompile(`(?im)^[ \t>]*From:[^\n]*$\n(?:[ \t>]*(?:Sent|Date|To|Cc|Bcc|Subject|Reply-To|Importance):[^\n]*\n?)+`),
	// Gmail's forward marker, likewise with the header block it introduces.
	regexp.MustCompile(`(?im)^[ \t>]*-{2,}\s*Forwarded message\s*-{2,}\s*$(?:\n[ \t>]*(?:From|Sent|Date|To|Cc|Bcc|Subject|Reply-To):[^\n]*)*`),
	// "Le 1 janvier 2024 à 09:00, Alice a écrit :" and the German equivalent.
	regexp.MustCompile(`(?im)^[ \t>]*(Le|Am)\s+.{0,200}?\s+(a écrit|schrieb)\s*:\s*$`),
	// "Alice <a@b.com> wrote:" with no date.
	regexp.MustCompile(`(?im)^[ \t>]*\S.{0,120}<[^>]+@[^>]+>\s+wrote:\s*$`),
}

// buildThreads splits the body into the current message and the conversation below it.
func (p *parser) buildThreads(m *mdm.MessageDataModel, body *mdm.Body) {
	text := bodyText(body)

	segments := splitThreads(text)

	current := &mdm.Thread{Text: mdm.Ptr(segments[0].text)}
	if segments[0].preamble != "" {
		current.Preamble = mdm.Ptr(segments[0].preamble)
	}
	current.Links = linksInText(body.Links, segments[0].text)
	current.Banners = bannersIn(segments[0].text, body.Links)
	body.CurrentThread = current

	for i, seg := range segments[1:] {
		prev := &mdm.PreviousThread{
			Index: mdm.Ptr(int64(i)),
			Text:  mdm.Ptr(seg.text),
			Links: linksInText(body.Links, seg.text),
		}
		if seg.preamble != "" {
			prev.Preamble = mdm.Ptr(seg.preamble)
			p.fillFromPreamble(prev, seg.preamble)
		}
		body.PreviousThreads = append(body.PreviousThreads, prev)
	}
}

// segment is one slice of a quoted conversation.
type segment struct {
	// preamble is the attribution line or header block that introduced this segment. It is
	// what the quoted headers can be recovered from.
	preamble string
	text     string
}

// splitThreads divides body text at quote boundaries. The first segment is always the
// current message, even when it is empty — a reply with nothing above the quote is a real
// thing and the model still needs a current thread.
func splitThreads(text string) []segment {
	if strings.TrimSpace(text) == "" {
		return []segment{{}}
	}

	type boundary struct{ start, end int }
	var bounds []boundary
	for _, re := range quoteHeaders {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			bounds = append(bounds, boundary{loc[0], loc[1]})
		}
	}
	if len(bounds) == 0 {
		// No attribution lines. A block of >-quoted lines is still quoted history, and is
		// the only marker some clients leave.
		if idx := firstQuotedBlock(text); idx > 0 {
			return []segment{
				{text: strings.TrimSpace(text[:idx])},
				{text: strings.TrimSpace(stripQuoteMarkers(text[idx:]))},
			}
		}
		return []segment{{text: strings.TrimSpace(text)}}
	}

	// Sort and drop overlaps: several patterns match the same Outlook header block, and
	// counting it twice would invent an empty thread between them.
	for i := 1; i < len(bounds); i++ {
		for j := i; j > 0 && bounds[j].start < bounds[j-1].start; j-- {
			bounds[j], bounds[j-1] = bounds[j-1], bounds[j]
		}
	}
	deduped := bounds[:0]
	for _, b := range bounds {
		if n := len(deduped); n > 0 {
			prev := deduped[n-1]
			if b.start < prev.end {
				// Overlapping: several patterns match the same header block.
				if b.end > prev.end {
					deduped[n-1].end = b.end
				}
				continue
			}
			if strings.TrimSpace(text[prev.end:b.start]) == "" {
				// Adjacent with only whitespace between. A separator line immediately
				// followed by a header block is one boundary, not two with an empty
				// thread wedged between them.
				deduped[n-1].end = b.end
				continue
			}
		}
		deduped = append(deduped, b)
	}

	segs := []segment{{text: strings.TrimSpace(text[:deduped[0].start])}}
	for i, b := range deduped {
		end := len(text)
		if i+1 < len(deduped) {
			end = deduped[i+1].start
		}
		segs = append(segs, segment{
			preamble: strings.TrimSpace(stripQuoteMarkers(text[b.start:b.end])),
			text:     strings.TrimSpace(stripQuoteMarkers(text[b.end:end])),
		})
	}
	return segs
}

// quotedLine matches a line prefixed with the ">" marker.
var quotedLine = regexp.MustCompile(`(?m)^[ \t]*>`)

// firstQuotedBlock returns the offset of the first run of quoted lines, or -1.
//
// A single quoted line is not enough: people quote one line inline while still writing new
// text around it, and treating that as the end of the message would truncate what the
// sender said.
func firstQuotedBlock(text string) int {
	lines := strings.SplitAfter(text, "\n")
	offset, runStart, run := 0, -1, 0
	for _, line := range lines {
		if quotedLine.MatchString(line) {
			if run == 0 {
				runStart = offset
			}
			run++
			if run >= 2 {
				return runStart
			}
		} else if strings.TrimSpace(line) != "" {
			run = 0
		}
		offset += len(line)
	}
	return -1
}

func stripQuoteMarkers(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		for strings.HasPrefix(trimmed, ">") {
			trimmed = strings.TrimPrefix(trimmed, ">")
			trimmed = strings.TrimPrefix(trimmed, " ")
		}
		lines[i] = trimmed
	}
	return strings.Join(lines, "\n")
}

// preambleField reads one header out of a quoted Outlook-style block.
func preambleField(preamble, name string) string {
	re := regexp.MustCompile(`(?im)^[ \t>]*` + name + `:\s*(.+)$`)
	if m := re.FindStringSubmatch(preamble); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// attributionLine pulls the sender out of "On <date>, <person> wrote:".
var attributionLine = regexp.MustCompile(`(?is)^[\s>]*(?:On|Le|Am)\s+(.{0,200}?),?\s*(?:wrote|a écrit|schrieb)\s*:`)

// fillFromPreamble recovers the quoted message's headers.
//
// The schema asks for a sender, recipients, subject and date on each previous thread, which
// means the attribution line has to be read back into structure. What can be recovered
// varies by client: Outlook quotes a full header block, Gmail quotes one sentence.
func (p *parser) fillFromPreamble(prev *mdm.PreviousThread, preamble string) {
	if v := preambleField(preamble, "Subject"); v != "" {
		prev.Subject = parseSubject(v)
	}
	if v := preambleField(preamble, "From"); v != "" {
		prev.Sender = mailboxFromText(v)
	}
	for _, field := range []string{"Sent", "Date"} {
		if v := preambleField(preamble, field); v != "" {
			if t, ok := parsePreambleDate(v); ok {
				utc := t.UTC()
				prev.Date = &utc
			}
			break
		}
	}

	rcpt := &mdm.ThreadRecipients{
		To:  mailboxesFromText(preambleField(preamble, "To")),
		CC:  mailboxesFromText(preambleField(preamble, "Cc")),
		BCC: mailboxesFromText(preambleField(preamble, "Bcc")),
	}
	if len(rcpt.To)+len(rcpt.CC)+len(rcpt.BCC) > 0 {
		prev.Recipients = rcpt
	}

	if prev.Sender != nil {
		return
	}
	// No header block, so fall back to the attribution sentence.
	if m := attributionLine.FindStringSubmatch(preamble); m != nil {
		if mb := mailboxFromText(m[1]); mb != nil {
			prev.Sender = mb
		}
	}
}

// preambleDateLayouts covers the forms mail clients write into a quoted header block.
//
// These are display dates, not RFC 5322 timestamps: Outlook writes what the sender's
// machine would show a human, in that machine's locale and timezone. So this is best-effort
// by nature — a non-English month name will not parse, and the result carries no real
// timezone. It is still worth attempting, because rules compare the quoted date against the
// message's own to spot fabricated history.
var preambleDateLayouts = []string{
	"Monday, January 2, 2006 3:04 PM",
	"Monday, January 2, 2006 3:04:05 PM",
	"Monday, 2 January 2006 15:04",
	"Monday, 2 January 2006 15:04:05",
	"January 2, 2006 3:04 PM",
	"2 January 2006 15:04",
	"02/01/2006 15:04",
	"1/2/2006 3:04 PM",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	time.RFC1123Z,
	time.RFC1123,
	time.RFC822Z,
	time.RFC822,
}

func parsePreambleDate(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	// RFC 5322 first: some clients do quote a real timestamp.
	if t, err := mail.ParseDate(v); err == nil {
		return t, true
	}
	// Non-breaking spaces are common in HTML-derived preambles and defeat every layout.
	v = strings.ReplaceAll(v, "\u00a0", " ")
	v = strings.Join(strings.Fields(v), " ")
	for _, layout := range preambleDateLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// bracketedAddress finds an address inside a fragment of prose.
var bracketedAddress = regexp.MustCompile(`<([^<>@\s]+@[^<>@\s]+)>|\b([^\s<>,;:"]+@[^\s<>,;:"]+\.[A-Za-z]{2,})\b`)

// mailboxFromText recovers a mailbox from free text such as an attribution line.
func mailboxFromText(s string) *mdm.Mailbox {
	boxes := mailboxesFromText(s)
	if len(boxes) == 0 {
		return nil
	}
	return boxes[0]
}

func mailboxesFromText(s string) []*mdm.Mailbox {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if boxes := looseAddressList(s); len(boxes) > 0 {
		return boxes
	}

	var out []*mdm.Mailbox
	for _, m := range bracketedAddress.FindAllStringSubmatch(s, -1) {
		raw := firstNonEmpty(m[1], m[2])
		addr := mdm.ParseEmailAddress(raw)
		if addr == nil {
			continue
		}
		mb := &mdm.Mailbox{Email: addr}
		// Whatever precedes the address on the line is the display name.
		if idx := strings.Index(s, raw); idx > 0 {
			name := strings.TrimSpace(strings.Trim(strings.TrimSpace(s[:idx]), `"<`))
			if name != "" && !strings.Contains(name, "@") {
				mb.DisplayName = mdm.Ptr(name)
			}
		}
		out = append(out, mb)
	}
	if len(out) > 0 {
		return out
	}

	// No address at all. A bare display name still identifies the quoted sender, which is
	// what impersonation rules compare against.
	if name := strings.TrimSpace(s); name != "" && len(name) < 200 {
		return []*mdm.Mailbox{{DisplayName: mdm.Ptr(name)}}
	}
	return nil
}

// linksInText selects the links whose target appears in a given slice of the body, so each
// thread carries the links that belong to it.
func linksInText(all []*mdm.Link, text string) []*mdm.Link {
	if text == "" || len(all) == 0 {
		return nil
	}
	var out []*mdm.Link
	for _, l := range all {
		if l.HrefURL == nil {
			continue
		}
		if strings.Contains(text, l.HrefURL.URL) || (l.DisplayText != nil && strings.Contains(text, *l.DisplayText)) {
			out = append(out, l)
		}
	}
	return out
}

// bannerPattern matches the warning banners mail gateways inject. Recognising them matters
// in both directions: they are not content the sender wrote, and attackers forge them to
// make a message look as though it has already been screened.
var bannerPattern = regexp.MustCompile(`(?im)^.{0,200}\b(CAUTION|EXTERNAL|WARNING|This (e-?mail|message) (originated|came) from outside|Be careful with this message|You don't often get email from)\b.{0,300}$`)

func bannersIn(text string, all []*mdm.Link) []*mdm.Banner {
	if text == "" {
		return nil
	}
	var out []*mdm.Banner
	for _, line := range bannerPattern.FindAllString(text, -1) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, &mdm.Banner{
			Text:  mdm.Ptr(line),
			Links: linksInText(all, line),
		})
	}
	return out
}
