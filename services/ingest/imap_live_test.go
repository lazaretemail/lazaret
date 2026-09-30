// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Live IMAP tests against a real server.
//
// Opt-in. Run against GreenMail, which speaks enough IMAP to exercise the paths that
// matter — IDLE, SEARCH UNSEEN, FETCH, and the COPY/STORE/EXPUNGE quarantine fallback
// for servers without MOVE:
//
//	docker run -d --name lazaret-greenmail -p 3143:3143 -p 3993:3993 -p 3025:3025 \
//	  -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 \
//	     -Dgreenmail.users=watch:watchpw@lazaret.test' greenmail/standalone:2.1.0
//
//	LAZARET_TEST_IMAP=localhost:3993 LAZARET_TEST_SMTP=localhost:3025 go test . -run Live -v
//
// A fake IMAP server would prove nothing here. The interesting behaviour is all in how
// a real server answers: whether it advertises IDLE, whether MOVE exists, what a UID
// search returns after a message is copied away.
func liveIMAP(t *testing.T) *IMAPSource {
	t.Helper()
	addr := os.Getenv("LAZARET_TEST_IMAP")
	if addr == "" {
		t.Skip("set LAZARET_TEST_IMAP to a test IMAP server to run this")
	}
	return &IMAPSource{
		Addr: addr, Username: "watch", Password: "watchpw",
		Mailbox: "INBOX", TLSMode: "tls", Insecure: true,
		PollInterval: time.Second,
	}
}

// send injects a message over SMTP, the way a real one would arrive.
func send(t *testing.T, subject, body string) {
	t.Helper()
	addr := os.Getenv("LAZARET_TEST_SMTP")
	if addr == "" {
		t.Skip("set LAZARET_TEST_SMTP as well")
	}
	msg := fmt.Sprintf("From: Sender <sender@example.com>\r\n"+
		"To: watch@lazaret.test\r\n"+
		"Subject: %s\r\n"+
		"Date: Mon, 02 Mar 2026 10:00:00 +0000\r\n"+
		"Message-ID: <%s@example.com>\r\n\r\n%s\r\n", subject, subject, body)
	if err := smtp.SendMail(addr, nil, "sender@example.com", []string{"watch@lazaret.test"}, []byte(msg)); err != nil {
		t.Fatalf("sending: %v", err)
	}
}

func TestLiveIMAPDeliversNewMail(t *testing.T) {
	src := liveIMAP(t)
	send(t, "LiveDeliver", "hello from the test")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got := make(chan RawMessage, 4)
	go src.Run(ctx, func(_ context.Context, m RawMessage) (*Verdict, error) {
		got <- m
		return &Verdict{Verdict: "clean", MessageID: "LiveDeliver@example.com"}, nil
	})

	select {
	case m := <-got:
		if m.Source != "imap" {
			t.Errorf("source = %q", m.Source)
		}
		if m.ProviderID == "" {
			t.Error("no provider id; without a UID the message cannot be acted on later")
		}
		if len(m.Raw) == 0 {
			t.Error("empty body")
		}
		if m.ReceivedAt.IsZero() {
			t.Error("no received time")
		}
	case <-ctx.Done():
		t.Fatal("no message delivered within the timeout")
	}
}

// The remediation path: a flagged message must leave the inbox entirely.
//
// Entirely, not into a folder. Quarantine here means the engine holds the only copy;
// a Quarantine folder would leave the message in the recipient's mailbox, one click
// from being read, which is the model this deliberately does not use.
func TestLiveIMAPQuarantinesFlaggedMail(t *testing.T) {
	src := liveIMAP(t)
	src.Remediate = true
	src.Engine = &Engine{Address: "http://127.0.0.1:1", Tenant: "t", Client: shortClient()}

	subject := fmt.Sprintf("LiveQuarantine-%d", time.Now().UnixNano())
	send(t, subject, "please wire the funds")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var once sync.Once
	done := make(chan struct{})
	go src.Run(ctx, func(_ context.Context, m RawMessage) (*Verdict, error) {
		if !contains(m.Raw, subject) {
			return &Verdict{Verdict: "clean"}, nil
		}
		once.Do(func() { close(done) })
		return &Verdict{
			Verdict:   "malicious",
			MessageID: subject + "@example.com",
			Matched:   []Rule{{Name: "Test rule", Severity: "high"}},
		}, nil
	})

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("the message was never analysed")
	}

	// Give the delete a moment, then check the inbox directly.
	time.Sleep(2 * time.Second)
	if inMailbox(t, src, "INBOX", subject) {
		t.Error("the flagged message is still in INBOX")
	}
}

// Removing and restoring: the two halves of custody.
//
// The point of deleting rather than filing is that releasing has to put the message
// back, so this checks the round trip rather than just the delete.
func TestLiveIMAPRemoveAndRestore(t *testing.T) {
	src := liveIMAP(t)
	src.Engine = &Engine{Address: "http://127.0.0.1:1", Tenant: "t", Client: shortClient()}

	subject := fmt.Sprintf("LiveRestore-%d", time.Now().UnixNano())
	messageID := fmt.Sprintf("<restore-%d@example.com>", time.Now().UnixNano())
	raw := []byte("Message-ID: " + messageID + "\r\n" +
		"From: sender@example.com\r\n" +
		"To: watch@lazaret.test\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\nthe body\r\n")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Put it there, take it away, put it back.
	if err := src.Restore(ctx, messageID, raw); err != nil {
		t.Fatalf("appending: %v", err)
	}
	if !inMailbox(t, src, "INBOX", subject) {
		t.Fatal("the appended message is not in INBOX")
	}

	if err := src.Remove(ctx, messageID); err != nil {
		t.Fatalf("removing: %v", err)
	}
	if inMailbox(t, src, "INBOX", subject) {
		t.Error("the message is still in INBOX after Remove")
	}

	if err := src.Restore(ctx, messageID, raw); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	if !inMailbox(t, src, "INBOX", subject) {
		t.Error("the message did not come back after Restore")
	}

	// Releasing twice must not produce two copies.
	if err := src.Restore(ctx, messageID, raw); err != nil {
		t.Fatalf("restoring again: %v", err)
	}
	if n := countInMailbox(t, src, "INBOX", subject); n != 1 {
		t.Errorf("restoring twice left %d copies, want 1", n)
	}

	// Removing something that is not there is success, not an error: the recipient
	// may have deleted it, or it may have been in the other watched mailbox.
	if err := src.Remove(ctx, "<never-existed@example.com>"); err != nil {
		t.Errorf("removing an absent message: %v", err)
	}
}

// A clean message must be left alone. A connector that moves everything is not a
// detection system.
func TestLiveIMAPLeavesCleanMailAlone(t *testing.T) {
	src := liveIMAP(t)
	src.Remediate = true
	src.Engine = &Engine{Address: "http://127.0.0.1:1", Tenant: "t", Client: shortClient()}

	subject := fmt.Sprintf("LiveClean-%d", time.Now().UnixNano())
	send(t, subject, "an ordinary message")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	seen := make(chan struct{})
	var once sync.Once
	go src.Run(ctx, func(_ context.Context, m RawMessage) (*Verdict, error) {
		if contains(m.Raw, subject) {
			once.Do(func() { close(seen) })
		}
		return &Verdict{Verdict: "clean"}, nil
	})

	select {
	case <-seen:
	case <-ctx.Done():
		t.Fatal("the message was never analysed")
	}
	time.Sleep(time.Second)
	if !inMailbox(t, src, "INBOX", subject) {
		t.Error("a clean message was moved out of INBOX")
	}
}

func ensureMailbox(t *testing.T, src *IMAPSource, name string) {
	t.Helper()
	c := connect(t, src)
	defer c.Close()
	// Already existing is fine; anything else is not.
	if err := c.Create(name, nil).Wait(); err != nil {
		list, lerr := c.List("", "*", nil).Collect()
		if lerr != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		for _, m := range list {
			if m.Mailbox == name {
				return
			}
		}
		t.Fatalf("creating %s: %v", name, err)
	}
}

func inMailbox(t *testing.T, src *IMAPSource, mailbox, subject string) bool {
	t.Helper()
	c := connect(t, src)
	defer c.Close()

	if _, err := c.Select(mailbox, nil).Wait(); err != nil {
		t.Fatalf("selecting %s: %v", mailbox, err)
	}
	found, err := c.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: subject}},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("searching %s: %v", mailbox, err)
	}
	return len(found.AllUIDs()) > 0
}

func countInMailbox(t *testing.T, src *IMAPSource, mailbox, subject string) int {
	t.Helper()
	c := connect(t, src)
	defer c.Close()

	if _, err := c.Select(mailbox, nil).Wait(); err != nil {
		t.Fatalf("selecting %s: %v", mailbox, err)
	}
	found, err := c.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: subject}},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("searching %s: %v", mailbox, err)
	}
	return len(found.AllUIDs())
}

func connect(t *testing.T, src *IMAPSource) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialTLS(src.Addr, &imapclient.Options{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	if err := c.Login(src.Username, src.Password).Wait(); err != nil {
		t.Fatalf("logging in: %v", err)
	}
	return c
}

func contains(haystack []byte, needle string) bool {
	return len(needle) > 0 && bytesIndex(haystack, needle) >= 0
}

func bytesIndex(h []byte, n string) int {
outer:
	for i := 0; i+len(n) <= len(h); i++ {
		for j := range n {
			if h[i+j] != n[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
