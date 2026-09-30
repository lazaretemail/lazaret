// SPDX-License-Identifier: AGPL-3.0-only

package eml_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/eml"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/orgconfig"
)

// crlf converts the readable test fixtures below into the line endings a real message uses.
// Writing "\r\n" inline would make every fixture unreadable, and a parser that only worked
// on LF would pass tests and fail on all real mail.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

func testOrg() *orgconfig.Config {
	c := &orgconfig.Config{
		Domains: []string{"example.com"},
		VIPs:    []orgconfig.VIP{{Email: "ceo@example.com", DisplayName: "Dana Reed"}},
	}
	c.Normalize()
	return c
}

func parse(t *testing.T, raw string) *mdm.MessageDataModel {
	t.Helper()
	m, err := eml.ParseString(crlf(raw), &eml.Options{Org: testOrg()})
	if err != nil {
		t.Fatalf("parsing message: %v", err)
	}
	return m
}

func str(p *string) string { return mdm.Deref(p) }

const simpleMessage = `From: "Alice Smith" <alice@sender.test>
To: Bob <bob@example.com>, carol@example.com
Cc: dave@partner.test
Subject: Re: Quarterly report
Message-Id: <abc123@sender.test>
In-Reply-To: <prev@example.com>
References: <one@x.test> <two@x.test>
Date: Mon, 02 Jan 2023 15:04:05 -0700
Content-Type: text/plain; charset=utf-8

Please see the attached figures.
`

func TestBasicHeaders(t *testing.T) {
	m := parse(t, simpleMessage)

	if got := str(m.Sender.Email.Email); got != "alice@sender.test" {
		t.Errorf("sender = %q", got)
	}
	if got := str(m.Sender.DisplayName); got != "Alice Smith" {
		t.Errorf("display_name = %q", got)
	}
	if got := str(m.Sender.Email.Domain.RootDomain); got != "sender.test" {
		t.Errorf("sender root domain = %q", got)
	}

	if n := len(m.Recipients.To); n != 2 {
		t.Fatalf("To has %d recipients, want 2", n)
	}
	if got := str(m.Recipients.To[1].Email.Email); got != "carol@example.com" {
		t.Errorf("second recipient = %q", got)
	}
	if n := len(m.Recipients.CC); n != 1 {
		t.Errorf("Cc has %d recipients, want 1", n)
	}

	if got := str(m.Headers.MessageID); got != "abc123@sender.test" {
		t.Errorf("message_id = %q, want the angle brackets stripped", got)
	}
	if got := str(m.Headers.InReplyTo); got != "prev@example.com" {
		t.Errorf("in_reply_to = %q", got)
	}
	if n := len(m.Headers.References); n != 2 {
		t.Errorf("references = %v, want 2 entries", m.Headers.References)
	}

	if m.Headers.Date == nil {
		t.Fatal("no date parsed")
	}
	if got := m.Headers.Date.UTC().Format("2006-01-02T15:04:05Z"); got != "2023-01-02T22:04:05Z" {
		t.Errorf("date = %s, want it normalised to UTC", got)
	}
	// The original offset is kept: a timezone inconsistent with the routing is a signal.
	if got := str(m.Headers.DateOriginalOffset); got != "-0700" {
		t.Errorf("date_original_offset = %q", got)
	}
}

func TestSubjectParsing(t *testing.T) {
	tests := []struct {
		subject            string
		base               string
		isReply, isForward bool
		tags               []string
	}{
		{"Quarterly report", "Quarterly report", false, false, nil},
		{"Re: Quarterly report", "Quarterly report", true, false, nil},
		{"RE: RE: Quarterly report", "Quarterly report", true, false, nil},
		{"Fwd: Quarterly report", "Quarterly report", false, true, nil},
		{"FW: Quarterly report", "Quarterly report", false, true, nil},
		{"Re: Fwd: Quarterly report", "Quarterly report", true, true, nil},
		{"[EXTERNAL] Quarterly report", "Quarterly report", false, false, []string{"EXTERNAL"}},
		{"[EXTERNAL][SPAM] Re: Report", "Report", true, false, []string{"EXTERNAL", "SPAM"}},
		// Non-English prefixes: mail is not all in English and rules compare on base.
		{"AW: Quarterly report", "Quarterly report", true, false, nil},
		{"WG: Quarterly report", "Quarterly report", false, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.subject, func(t *testing.T) {
			m := parse(t, "From: a@b.test\nSubject: "+tc.subject+"\n\nbody\n")
			s := m.Subject
			if got := str(s.Subject); got != tc.subject {
				t.Errorf("subject = %q, want the header verbatim", got)
			}
			if got := str(s.Base); got != tc.base {
				t.Errorf("base = %q, want %q", got, tc.base)
			}
			if mdm.Deref(s.IsReply) != tc.isReply {
				t.Errorf("is_reply = %v, want %v", mdm.Deref(s.IsReply), tc.isReply)
			}
			if mdm.Deref(s.IsForward) != tc.isForward {
				t.Errorf("is_forward = %v, want %v", mdm.Deref(s.IsForward), tc.isForward)
			}
			if len(s.Tags) != len(tc.tags) {
				t.Errorf("tags = %v, want %v", s.Tags, tc.tags)
			}
		})
	}
}

func TestMessageDirection(t *testing.T) {
	// type.inbound gates most of the public rule corpus, and it is defined relative to the
	// organisation rather than being a property of the message.
	tests := []struct {
		name                        string
		from, to                    string
		inbound, outbound, internal bool
	}{
		{"external sender", "a@other.test", "bob@example.com", true, false, false},
		{"internal to internal", "alice@example.com", "bob@example.com", false, false, true},
		{"internal to external", "alice@example.com", "b@other.test", false, true, false},
		// Not exclusive: a message to both a colleague and an outsider is both outbound
		// and internal, which is why the schema has three booleans and not one enum.
		{"internal to both", "alice@example.com", "bob@example.com, b@other.test", false, true, true},
		// A subdomain of a verified domain is still us.
		{"subdomain sender", "alice@mail.example.com", "bob@example.com", false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := parse(t, "From: "+tc.from+"\nTo: "+tc.to+"\nSubject: s\n\nbody\n")
			if got := mdm.Deref(m.Type.Inbound); got != tc.inbound {
				t.Errorf("inbound = %v, want %v", got, tc.inbound)
			}
			if got := mdm.Deref(m.Type.Outbound); got != tc.outbound {
				t.Errorf("outbound = %v, want %v", got, tc.outbound)
			}
			if got := mdm.Deref(m.Type.Internal); got != tc.internal {
				t.Errorf("internal = %v, want %v", got, tc.internal)
			}
		})
	}
}

func TestDirectionUnknownWithoutOrgConfig(t *testing.T) {
	// Without a configured organisation the direction is genuinely unknowable. Guessing
	// would silently change the verdict of most of the corpus, so the fields stay null and
	// the reason is recorded.
	m, err := eml.ParseString(crlf("From: a@b.test\nTo: c@d.test\n\nbody\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != nil {
		t.Errorf("type = %+v, want nil when no organisation is configured", m.Type)
	}
	if len(m.Errors) == 0 {
		t.Error("no note recorded explaining why direction is unknown")
	}
}

const htmlMessage = `From: a@sender.test
To: bob@example.com
Subject: Account notice
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="B"

--B
Content-Type: text/plain; charset=utf-8

Visit https://plain.example.test/path to continue.
--B
Content-Type: text/html; charset=utf-8

<html><body>
<p>Hello there</p>
<a href="https://evil.test/login">https://accounts.google.com</a>
<a href="https://good.test/x">Click here</a>
<span style="display:none">hidden keyword stuffing</span>
<script>var x = "not content";</script>
</body></html>
--B--
`

func TestHTMLBodyAndLinks(t *testing.T) {
	m := parse(t, htmlMessage)

	if m.Body.Plain == nil || !strings.Contains(str(m.Body.Plain.Raw), "plain.example.test") {
		t.Errorf("plain part missing: %+v", m.Body.Plain)
	}
	if m.Body.HTML == nil {
		t.Fatal("html part missing")
	}

	// inner_text includes hidden content; display_text does not. Attackers rely on the
	// gap, so both are kept and rules can compare them.
	inner := str(m.Body.HTML.InnerText)
	display := str(m.Body.HTML.DisplayText)
	if !strings.Contains(inner, "hidden keyword stuffing") {
		t.Errorf("inner_text should include hidden text, got %q", inner)
	}
	if strings.Contains(display, "hidden keyword stuffing") {
		t.Errorf("display_text should exclude hidden text, got %q", display)
	}
	// Script contents are never readable content in either form.
	if strings.Contains(inner, "not content") {
		t.Errorf("script contents leaked into inner_text: %q", inner)
	}

	var deceptive, honest *mdm.Link
	for _, l := range m.Body.Links {
		switch str(l.HrefURL.Domain.RootDomain) {
		case "evil.test":
			deceptive = l
		case "good.test":
			honest = l
		}
	}
	if deceptive == nil {
		t.Fatalf("deceptive link not found in %d links", len(m.Body.Links))
	}
	if !mdm.Deref(deceptive.Mismatched) {
		t.Error("a link whose text claims google.com but points at evil.test is not marked mismatched")
	}
	if honest == nil {
		t.Fatal("ordinary link not found")
	}
	// The text is prose, so there is nothing to compare and no finding to report. Saying
	// "not mismatched" would claim a check we did not make.
	if honest.Mismatched != nil {
		t.Errorf("mismatched = %v for a link with prose text, want null", *honest.Mismatched)
	}
}

func TestHiddenLinkVisibility(t *testing.T) {
	m := parse(t, `From: a@b.test
Content-Type: text/html

<html><body>
<div style="display:none"><a href="https://hidden.test/x">h</a></div>
<a href="https://shown.test/y">s</a>
</body></html>
`)
	found := map[string]bool{}
	for _, l := range m.Body.Links {
		if l.HrefURL.Domain != nil {
			found[l.HrefURL.Domain.Domain] = mdm.Deref(l.Visible)
		}
	}
	if visible, ok := found["hidden.test"]; !ok || visible {
		t.Errorf("hidden link visibility = %v (present=%v), want false", visible, ok)
	}
	if visible, ok := found["shown.test"]; !ok || !visible {
		t.Errorf("shown link visibility = %v (present=%v), want true", visible, ok)
	}
}

func TestAttachments(t *testing.T) {
	// A PDF magic number under a .txt name and a text/plain content type: all three
	// answers to "what is this file" disagree, which is the point of keeping all three.
	payload := base64.StdEncoding.EncodeToString([]byte("%PDF-1.7\nfake pdf body\n"))
	m := parse(t, `From: a@b.test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain

see attached
--B
Content-Type: text/plain; name="invoice.txt"
Content-Disposition: attachment; filename="invoice.txt"
Content-Transfer-Encoding: base64

`+payload+`
--B--
`)

	if n := len(m.Attachments); n != 1 {
		t.Fatalf("got %d attachments, want 1", n)
	}
	a := m.Attachments[0]
	if got := str(a.FileName); got != "invoice.txt" {
		t.Errorf("file_name = %q", got)
	}
	if got := str(a.FileExtension); got != "txt" {
		t.Errorf("file_extension = %q", got)
	}
	if got := str(a.ContentType); got != "text/plain" {
		t.Errorf("content_type = %q, want the declared type verbatim", got)
	}
	// The declared type and the extension both say text; the bytes say PDF.
	if a.FileType == nil || *a.FileType != mdm.AttachmentFileTypePdf {
		t.Errorf("file_type = %v, want pdf from content sniffing", a.FileType)
	}
	if mdm.Deref(a.Size) == 0 || a.SHA256 == nil || a.MD5 == nil {
		t.Errorf("hashes or size missing: size=%d sha256=%v", mdm.Deref(a.Size), a.SHA256)
	}

	// The body part must not have been swallowed as an attachment.
	if !strings.Contains(str(m.Body.Plain.Raw), "see attached") {
		t.Errorf("body text lost: %q", str(m.Body.Plain.Raw))
	}
}

func TestAttachmentFilenameSanitisation(t *testing.T) {
	// Filenames are attacker-controlled and end up in logs and UIs.
	m := parse(t, `From: a@b.test
Content-Type: application/octet-stream; name="../../etc/passwd"
Content-Disposition: attachment; filename="../../etc/passwd"

data
`)
	if len(m.Attachments) != 1 {
		t.Fatalf("got %d attachments, want 1", len(m.Attachments))
	}
	if got := str(m.Attachments[0].FileName); got != "passwd" {
		t.Errorf("file_name = %q, want the traversal stripped", got)
	}
}

func TestAuthenticationSummary(t *testing.T) {
	// The summary must come from the most recent hop — the one written by infrastructure
	// the organisation controls. An attacker can forge Authentication-Results further down
	// the path, so believing the earliest hop would be believing the attacker.
	m := parse(t, `From: a@sender.test
Received: by mx.example.com; Mon, 02 Jan 2023 15:04:05 -0000
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=sender.test; dmarc=fail header.from=sender.test
Received: by relay.attacker.test; Mon, 02 Jan 2023 15:03:05 -0000
Authentication-Results: relay.attacker.test; spf=pass smtp.mailfrom=sender.test; dmarc=pass header.from=sender.test
Subject: s

body
`)
	as := m.Headers.AuthSummary
	if as == nil || as.DMARC == nil || as.SPF == nil {
		t.Fatalf("auth summary incomplete: %+v", as)
	}
	if mdm.Deref(as.DMARC.Pass) {
		t.Error("dmarc.pass is true; the forged lower hop was believed over our own MTA")
	}
	if mdm.Deref(as.SPF.Pass) {
		t.Error("spf.pass is true; the forged lower hop was believed over our own MTA")
	}
	if got := mdm.Deref(as.DMARC.ReceivedHop); got != 0 {
		t.Errorf("dmarc verdict taken from hop %d, want hop 0", got)
	}
}

func TestBestGuessPassIsNotAPass(t *testing.T) {
	// "bestguesspass" is what an MTA reports when the domain publishes no DMARC record.
	// Treating it as a pass would let any domain without a policy inherit the trust of one
	// that has it.
	m := parse(t, `From: a@sender.test
Received: by mx.example.com; Mon, 02 Jan 2023 15:04:05 -0000
Authentication-Results: mx.example.com; dmarc=bestguesspass header.from=sender.test
Subject: s

body
`)
	if mdm.Deref(m.Headers.AuthSummary.DMARC.Pass) {
		t.Error("dmarc=bestguesspass was treated as a pass")
	}
}

func TestHopsAreNewestFirst(t *testing.T) {
	m := parse(t, `From: a@b.test
Received: from c.test by mx.example.com with ESMTPS id AAA for <bob@example.com>; Mon, 02 Jan 2023 15:04:05 -0000
Received: from d.test by c.test with SMTP id BBB; Mon, 02 Jan 2023 15:03:05 -0000
Received: from e.test by d.test with SMTP id CCC; Mon, 02 Jan 2023 15:02:05 -0000
Subject: s

body
`)
	hops := m.Headers.Hops
	if len(hops) != 3 {
		t.Fatalf("got %d hops, want 3", len(hops))
	}
	for i, h := range hops {
		if h.Index != int64(i) {
			t.Errorf("hop %d has index %d", i, h.Index)
		}
	}
	// Hop 0 is the MTA closest to the recipient, which is the one whose word is worth
	// most: everything below it was written by servers we do not control.
	if got := str(hops[0].Received.Server.Raw); got != "mx.example.com" {
		t.Errorf("hop 0 server = %q, want our own MTA", got)
	}
	if got := str(hops[0].Received.Source.Raw); got != "c.test" {
		t.Errorf("hop 0 source = %q", got)
	}
	if got := str(hops[0].Received.ID.Raw); got != "AAA" {
		t.Errorf("hop 0 id = %q", got)
	}
	if got := str(hops[0].Received.Mailbox.Raw); got != "<bob@example.com>" {
		t.Errorf("hop 0 for = %q", got)
	}
	if hops[0].Received.Time == nil {
		t.Error("hop 0 has no timestamp")
	}
	if len(hops[0].Fields) == 0 {
		t.Error("hop 0 carries no raw fields")
	}
}

func TestDKIMSignature(t *testing.T) {
	m := parse(t, `From: a@b.test
Received: by mx.example.com; Mon, 02 Jan 2023 15:04:05 -0000
DKIM-Signature: v=1; a=rsa-sha256; d=sender.test; s=sel1; h=from:to:subject; bh=abc=; b=sig==
Subject: s

body
`)
	if len(m.Headers.Hops) == 0 {
		t.Fatal("no hops")
	}
	sig := m.Headers.Hops[0].Signature
	if sig == nil {
		t.Fatal("no signature recorded on the hop")
	}
	if got := str(sig.Domain); got != "sender.test" {
		t.Errorf("signature domain = %q", got)
	}
	if got := str(sig.Selector); got != "sel1" {
		t.Errorf("selector = %q", got)
	}
	// Rules match on the signed-header list to spot a signature that does not cover
	// Reply-To, so it is kept as written.
	if got := str(sig.Headers); got != "from:to:subject" {
		t.Errorf("signed headers = %q", got)
	}
}

func TestEncodedHeaders(t *testing.T) {
	// RFC 2047 encoded-words are routine, and a display name is what impersonation rules
	// compare against.
	m := parse(t, "From: =?utf-8?B?RGFuYSBSZWVk?= <attacker@evil.test>\nSubject: =?utf-8?q?Urgent=20payment?=\n\nbody\n")
	if got := str(m.Sender.DisplayName); got != "Dana Reed" {
		t.Errorf("display_name = %q, want the encoded-word decoded", got)
	}
	if got := str(m.Subject.Subject); got != "Urgent payment" {
		t.Errorf("subject = %q", got)
	}
}

func TestMalformedMessagesStillParse(t *testing.T) {
	// A message that fails to parse is a message no rule gets to inspect, so malformed
	// input must degrade rather than abort. Each of these is a real shape seen in the wild.
	cases := map[string]string{
		"no headers at all":      "just a body with no headers\n",
		"header with no body":    "From: a@b.test\nSubject: s\n",
		"bare LF line endings":   "From: a@b.test\nSubject: s\n\nbody\n",
		"missing boundary":       "From: a@b.test\nContent-Type: multipart/mixed; boundary=\"B\"\n\nno parts here\n",
		"unterminated boundary":  "From: a@b.test\nContent-Type: multipart/mixed; boundary=\"B\"\n\n--B\nContent-Type: text/plain\n\norphan\n",
		"unknown charset":        "From: a@b.test\nContent-Type: text/plain; charset=x-not-a-charset\n\nbody\n",
		"unknown encoding":       "From: a@b.test\nContent-Transfer-Encoding: x-nonsense\n\nbody\n",
		"malformed address list": "From: a@b.test\nTo: <<broken>>, alice@example.com\n\nbody\n",
		"malformed date":         "From: a@b.test\nDate: not a date at all\n\nbody\n",
		"empty subject":          "From: a@b.test\nSubject:\n\nbody\n",
		"8-bit in headers":       "From: \xc3\xa9@b.test\nSubject: caf\xc3\xa9\n\nbody\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := eml.ParseString(crlf(raw), &eml.Options{Org: testOrg()})
			if err != nil {
				t.Fatalf("returned an error instead of a partial model: %v", err)
			}
			if m == nil || m.Headers == nil {
				t.Fatal("no model produced")
			}
			// Whatever went wrong must be visible rather than silently swallowed.
			t.Logf("errors: %v", m.Errors)
		})
	}
}

func TestRecoversAddressesFromBrokenList(t *testing.T) {
	m := parse(t, "From: a@b.test\nTo: <<broken>>, Alice <alice@example.com>\n\nbody\n")
	var found bool
	for _, r := range m.Recipients.To {
		if r.Email != nil && str(r.Email.Email) == "alice@example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("the valid address was discarded along with the broken one: %+v", m.Recipients.To)
	}
	if len(m.Errors) == 0 {
		t.Error("recovery happened silently; it should be recorded")
	}
}

func TestEmptyInputIsAnError(t *testing.T) {
	if _, err := eml.Parse(nil, nil); err == nil {
		t.Error("parsing nothing succeeded")
	}
}

func TestCanonicalIDIsContentAddressed(t *testing.T) {
	// Two copies of the same message delivered to different mailboxes are one message;
	// grouping them later depends on this being stable.
	a := parse(t, simpleMessage)
	b := parse(t, simpleMessage)
	if a.Meta.CanonicalID != b.Meta.CanonicalID {
		t.Error("canonical id is not stable across parses")
	}
	c := parse(t, strings.Replace(simpleMessage, "Quarterly", "Annual", 1))
	if a.Meta.CanonicalID == c.Meta.CanonicalID {
		t.Error("different messages share a canonical id")
	}
}

func FuzzParse(f *testing.F) {
	// The EML parser reads fully untrusted input — this is the most attacker-exposed code
	// in the platform. It must never panic, however malformed the message.
	f.Add(simpleMessage)
	f.Add(htmlMessage)
	for _, s := range []string{
		"", "\n", "From:", "Content-Type: multipart/mixed; boundary=x\n\n--x\n--x--\n",
		"Content-Type: text/html\n\n<a href=\"\">", "From: <>\n\n", ":\n\n",
	} {
		f.Add(s)
	}
	org := testOrg()
	f.Fuzz(func(t *testing.T, raw string) {
		m, err := eml.ParseString(raw, &eml.Options{Org: org})
		if err != nil {
			return
		}
		if m == nil {
			t.Fatal("nil model with no error")
		}
		// Anything a rule can reach must be safe to reach on a hostile message.
		_ = m.Body
		_ = m.Headers.Hops
		for _, l := range m.Body.Links {
			_ = l.HrefURL
		}
	})
}
