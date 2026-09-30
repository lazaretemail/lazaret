// SPDX-License-Identifier: AGPL-3.0-only

package eml_test

import (
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
)

// Thread splitting is the largest single compatibility risk in the parser.
//
// body.current_thread.text is the most-used field in the public rule corpus — 2,409
// references — and no published document says how to produce it. If quoted history leaks
// into the current thread, every reply to a legitimate conversation inherits that
// conversation's words, and rules start firing on the wrong half of the message. If the
// split is too eager, the sender's own text goes missing and rules stop firing at all.
//
// So these tests are written from the client's point of view: each fixture is the shape a
// real mail client actually produces.

func threadOf(t *testing.T, body string) *mdm.Body {
	t.Helper()
	m := parse(t, "From: alice@sender.test\nTo: bob@example.com\nSubject: Re: Invoice\n\n"+body)
	return m.Body
}

func currentText(t *testing.T, body string) string {
	t.Helper()
	b := threadOf(t, body)
	if b.CurrentThread == nil {
		t.Fatal("no current thread")
	}
	return mdm.Deref(b.CurrentThread.Text)
}

func TestNoQuotedHistory(t *testing.T) {
	// A message with nothing quoted is entirely the current thread.
	got := currentText(t, "Hello Bob,\n\nHere is the invoice you asked for.\n\nAlice\n")
	if !strings.Contains(got, "Here is the invoice") {
		t.Errorf("current thread = %q, want the whole message", got)
	}
	b := threadOf(t, "Hello Bob,\n\nHere is the invoice.\n")
	if n := len(b.PreviousThreads); n != 0 {
		t.Errorf("got %d previous threads, want none", n)
	}
}

func TestGmailStyleReply(t *testing.T) {
	body := `Thanks, that works for me.

On Mon, 2 Jan 2023 at 15:04, Bob Jones <bob@example.com> wrote:
> Can we move the meeting to Tuesday?
>
> Bob
`
	b := threadOf(t, body)

	current := mdm.Deref(b.CurrentThread.Text)
	if !strings.Contains(current, "Thanks, that works for me.") {
		t.Errorf("current thread lost the reply: %q", current)
	}
	if strings.Contains(current, "move the meeting") {
		t.Errorf("quoted history leaked into the current thread: %q", current)
	}

	if len(b.PreviousThreads) != 1 {
		t.Fatalf("got %d previous threads, want 1", len(b.PreviousThreads))
	}
	prev := b.PreviousThreads[0]
	if got := mdm.Deref(prev.Text); !strings.Contains(got, "move the meeting") {
		t.Errorf("previous thread = %q", got)
	}
	// The ">" markers are the client's quoting, not the author's text.
	if strings.Contains(mdm.Deref(prev.Text), ">") {
		t.Errorf("quote markers left in the previous thread: %q", mdm.Deref(prev.Text))
	}
	// The attribution line has to be read back into structure: the schema asks each
	// previous thread for a sender.
	if prev.Sender == nil || prev.Sender.Email == nil {
		t.Fatalf("no sender recovered from the attribution line: %+v", prev.Sender)
	}
	if got := str(prev.Sender.Email.Email); got != "bob@example.com" {
		t.Errorf("previous sender = %q", got)
	}
}

func TestOutlookStyleReply(t *testing.T) {
	// Outlook quotes a full header block and, in many versions, no separator line at all.
	body := `I've approved it.

From: Bob Jones <bob@example.com>
Sent: Monday, January 2, 2023 3:04 PM
To: Alice Smith <alice@sender.test>
Cc: Carol <carol@example.com>
Subject: Invoice approval

Please approve the attached invoice.
`
	b := threadOf(t, body)

	if got := mdm.Deref(b.CurrentThread.Text); !strings.Contains(got, "I've approved it.") {
		t.Errorf("current thread = %q", got)
	}
	if got := mdm.Deref(b.CurrentThread.Text); strings.Contains(got, "Please approve") {
		t.Errorf("quoted history leaked into the current thread: %q", got)
	}

	if len(b.PreviousThreads) != 1 {
		t.Fatalf("got %d previous threads, want 1", len(b.PreviousThreads))
	}
	prev := b.PreviousThreads[0]
	if prev.Sender == nil || prev.Sender.Email == nil || str(prev.Sender.Email.Email) != "bob@example.com" {
		t.Errorf("previous sender = %+v", prev.Sender)
	}
	if prev.Subject == nil || str(prev.Subject.Subject) != "Invoice approval" {
		t.Errorf("previous subject = %+v", prev.Subject)
	}
	if prev.Recipients == nil || len(prev.Recipients.To) != 1 {
		t.Fatalf("previous recipients = %+v", prev.Recipients)
	}
	if got := str(prev.Recipients.To[0].Email.Email); got != "alice@sender.test" {
		t.Errorf("previous To = %q", got)
	}
	if len(prev.Recipients.CC) != 1 {
		t.Errorf("previous Cc = %+v", prev.Recipients.CC)
	}
	if prev.Date == nil {
		t.Error("no date recovered from the Sent: line")
	}
}

func TestOriginalMessageSeparator(t *testing.T) {
	body := `See below.

-----Original Message-----
From: Bob <bob@example.com>
Sent: Monday, January 2, 2023 3:04 PM
Subject: Payment details

Our bank details have changed.
`
	b := threadOf(t, body)
	if got := mdm.Deref(b.CurrentThread.Text); !strings.Contains(got, "See below.") {
		t.Errorf("current thread = %q", got)
	}
	if got := mdm.Deref(b.CurrentThread.Text); strings.Contains(got, "bank details") {
		t.Errorf("quoted history leaked: %q", got)
	}
	if len(b.PreviousThreads) == 0 {
		t.Fatal("no previous thread found")
	}
	if got := mdm.Deref(b.PreviousThreads[0].Text); !strings.Contains(got, "bank details") {
		t.Errorf("previous thread = %q", got)
	}
}

func TestMultiHopThread(t *testing.T) {
	// Three messages deep, which is where indexing matters: rules reach for
	// body.previous_threads[length(...) - 1] to get the oldest message in a chain.
	body := `Latest reply from Alice.

On Wed, 4 Jan 2023 at 10:00, Bob <bob@example.com> wrote:
> Second message from Bob.
>
> On Tue, 3 Jan 2023 at 09:00, Carol <carol@partner.test> wrote:
> > First message from Carol.
`
	b := threadOf(t, body)

	if got := mdm.Deref(b.CurrentThread.Text); !strings.Contains(got, "Latest reply from Alice") {
		t.Errorf("current thread = %q", got)
	}
	if len(b.PreviousThreads) != 2 {
		t.Fatalf("got %d previous threads, want 2", len(b.PreviousThreads))
	}

	// Index 0 is the most recent quoted message, counting backwards in time.
	if got := mdm.Deref(b.PreviousThreads[0].Text); !strings.Contains(got, "Second message from Bob") {
		t.Errorf("previous_threads[0] = %q", got)
	}
	if got := mdm.Deref(b.PreviousThreads[1].Text); !strings.Contains(got, "First message from Carol") {
		t.Errorf("previous_threads[1] = %q", got)
	}
	for i, prev := range b.PreviousThreads {
		if got := mdm.Deref(prev.Index); got != int64(i) {
			t.Errorf("previous_threads[%d].index = %d", i, got)
		}
	}
	if b.PreviousThreads[1].Sender == nil || str(b.PreviousThreads[1].Sender.Email.Email) != "carol@partner.test" {
		t.Errorf("oldest sender = %+v", b.PreviousThreads[1].Sender)
	}
}

func TestQuotedBlockWithoutAttribution(t *testing.T) {
	// Some clients leave only the ">" markers, with no attribution line at all.
	body := `Agreed.

> The contract is attached.
> Let me know.
`
	b := threadOf(t, body)
	if got := mdm.Deref(b.CurrentThread.Text); got != "Agreed." {
		t.Errorf("current thread = %q, want just the reply", got)
	}
	if len(b.PreviousThreads) != 1 {
		t.Fatalf("got %d previous threads, want 1", len(b.PreviousThreads))
	}
	if got := mdm.Deref(b.PreviousThreads[0].Text); !strings.Contains(got, "The contract is attached") {
		t.Errorf("previous thread = %q", got)
	}
}

func TestSingleQuotedLineIsNotASplit(t *testing.T) {
	// People quote one line inline while still writing around it. Treating that as the end
	// of the message would truncate what the sender actually said — and what the sender
	// said is what most rules are looking for.
	body := `You wrote:

> the invoice

and I agree, please send it to the new account.
`
	got := currentText(t, body)
	if !strings.Contains(got, "please send it to the new account") {
		t.Errorf("text after an inline quote was lost: %q", got)
	}
}

func TestProseMentioningWroteIsNotASplit(t *testing.T) {
	// "wrote:" only ends the message when a client put it there. An anchored pattern is
	// what keeps ordinary prose from truncating the body.
	body := "As I wrote: the deadline is Friday, and we should confirm it today.\n"
	got := currentText(t, body)
	if !strings.Contains(got, "deadline is Friday") {
		t.Errorf("prose containing \"wrote:\" split the message: %q", got)
	}
}

func TestReplyWithNothingAboveTheQuote(t *testing.T) {
	// A forward with no added comment is real, and the model still needs a current thread
	// rather than a nil one.
	body := `---------- Forwarded message ---------
From: Bob <bob@example.com>
Subject: Invoice

Please pay this.
`
	b := threadOf(t, body)
	if b.CurrentThread == nil {
		t.Fatal("no current thread for a bare forward")
	}
	if got := mdm.Deref(b.CurrentThread.Text); strings.TrimSpace(got) != "" {
		t.Errorf("current thread = %q, want empty", got)
	}
	if len(b.PreviousThreads) == 0 {
		t.Fatal("the forwarded message was not captured")
	}
}

func TestWarningBannerIsRecognised(t *testing.T) {
	// Gateways inject these, so they are not content the sender wrote — and attackers
	// forge them to make a message look as though it has already been screened.
	body := `CAUTION: This email originated from outside of the organization.

Please review the attached invoice.
`
	b := threadOf(t, body)
	if len(b.CurrentThread.Banners) == 0 {
		t.Fatalf("no banner recognised in %q", mdm.Deref(b.CurrentThread.Text))
	}
	if got := mdm.Deref(b.CurrentThread.Banners[0].Text); !strings.Contains(got, "CAUTION") {
		t.Errorf("banner text = %q", got)
	}
}

func TestThreadLinksAreAttributedToTheRightThread(t *testing.T) {
	// A link in quoted history is not a link the sender just sent you, and rules that
	// check body.current_thread.links depend on the distinction.
	body := `Here is the new one: https://current.test/a

On Mon, 2 Jan 2023 at 15:04, Bob <bob@example.com> wrote:
> The old link was https://previous.test/b
`
	b := threadOf(t, body)

	var currentHosts, prevHosts []string
	for _, l := range b.CurrentThread.Links {
		currentHosts = append(currentHosts, l.HrefURL.Domain.Domain)
	}
	if len(b.PreviousThreads) > 0 {
		for _, l := range b.PreviousThreads[0].Links {
			prevHosts = append(prevHosts, l.HrefURL.Domain.Domain)
		}
	}

	if !contains(currentHosts, "current.test") {
		t.Errorf("current thread links = %v, want current.test", currentHosts)
	}
	if contains(currentHosts, "previous.test") {
		t.Errorf("a quoted link was attributed to the current thread: %v", currentHosts)
	}
	if !contains(prevHosts, "previous.test") {
		t.Errorf("previous thread links = %v, want previous.test", prevHosts)
	}
}

func TestHTMLBlockquoteReply(t *testing.T) {
	// The HTML path goes through rendered text, so the same attribution lines have to be
	// found after the markup is stripped.
	m := parse(t, `From: alice@sender.test
To: bob@example.com
Subject: Re: Invoice
Content-Type: text/html; charset=utf-8

<html><body>
<div>Approved, thanks.</div>
<div class="gmail_quote">
<div>On Mon, 2 Jan 2023 at 15:04, Bob &lt;bob@example.com&gt; wrote:</div>
<blockquote><div>Please approve the invoice.</div></blockquote>
</div>
</body></html>
`)
	current := mdm.Deref(m.Body.CurrentThread.Text)
	if !strings.Contains(current, "Approved, thanks.") {
		t.Errorf("current thread = %q", current)
	}
	if strings.Contains(current, "Please approve the invoice") {
		t.Errorf("quoted HTML leaked into the current thread: %q", current)
	}
	if len(m.Body.PreviousThreads) == 0 {
		t.Fatal("no previous thread found in the HTML reply")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
