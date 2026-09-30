// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// The IMAP source: after delivery, and it works against anything.
//
// No cooperation from the mail provider beyond an account, which is what makes it the
// universal fallback — a self-hosted Dovecot, a hosted mailbox, a shared abuse@ inbox
// people forward suspicious mail to. It is also the only source here that can act on
// mail it did not itself ingest, because IMAP is a protocol for managing a mailbox
// rather than a notification feed.
//
// IDLE is used when the server offers it, so a new message is noticed in seconds
// rather than at the next poll. Servers that do not, or that drop the connection, fall
// back to polling on an interval — the same failover shape the Graph source uses, for
// the same reason: the cheaper mechanism is preferred and the reliable one is always
// there underneath.

// IMAPSource watches a mailbox.
type IMAPSource struct {
	Engine   *Engine
	Addr     string
	Username string
	Password string
	// Mailbox to watch. INBOX unless a deployment routes suspicious mail elsewhere.
	Mailbox string
	// MailboxID is the engine's identifier for this mailbox, set when the engine
	// configured this connector. It travels with every message so remediation can
	// be aimed at one mailbox rather than fanned out across all of them.
	MailboxID string
	// TLSMode is "tls" (implicit, port 993), "starttls" (required), or "none".
	//
	// "none" exists because Dovecot on localhost is a real deployment and refusing it
	// outright would be posturing rather than security. It is spelled out rather than
	// implied, and logged at startup, because this connection carries a password and
	// every message in the mailbox — nobody should arrive at plaintext by leaving a
	// field blank.
	TLSMode string
	// PollInterval is how often to check when IDLE is unavailable.
	PollInterval time.Duration
	// Remediate allows this connector to remove mail from the mailbox.
	//
	// Off by default, which leaves it a read-only observer — a reasonable way to run
	// it first. Turning it on is the decision to let an automated verdict take a
	// message away from its recipient, and since quarantine deletes rather than
	// files, that is not a decision to arrive at by leaving a field blank.
	Remediate bool
	// Insecure skips certificate verification. For a self-signed Dovecot on a lab
	// network, and named so nobody sets it by accident.
	Insecure bool
}

// reportHealth tells the engine how the last connection attempt went, when this
// connector is one the engine configured.
func (s *IMAPSource) reportHealth(ctx context.Context, seen int64, err error) {
	if s.Engine != nil {
		s.Engine.ReportHealth(ctx, s.MailboxID, seen, err)
	}
}

func (s *IMAPSource) Name() string { return "imap" }

func (s *IMAPSource) mailbox() string {
	if s.Mailbox != "" {
		return s.Mailbox
	}
	return "INBOX"
}

func (s *IMAPSource) interval() time.Duration {
	if s.PollInterval > 0 {
		return s.PollInterval
	}
	return 60 * time.Second
}

// Run watches the mailbox until the context is cancelled.
//
// Reconnects on failure with a backoff. A mail connector that exits when the server
// restarts is a connector that silently stops protecting a mailbox, and the operator
// finds out weeks later.
func (s *IMAPSource) Run(ctx context.Context, deliver Deliver) error {
	backoff := time.Second
	for ctx.Err() == nil {
		err := s.session(ctx, deliver)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Printf("imap: %v; reconnecting in %s", err, backoff)
			// Said out loud rather than only logged. A wrong password, a
			// provider that wants an app password, TLS on the wrong setting —
			// all of them look identical from the settings page unless the
			// connector reports what it actually got.
			s.reportHealth(context.WithoutCancel(ctx), 0, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}
	return nil
}

func (s *IMAPSource) session(ctx context.Context, deliver Deliver) error {
	// Buffered by one, and written to without blocking. The library calls the
	// handler on its own goroutine and documents that it blocks the client while it
	// runs, so this must not do anything but set a flag. One slot is enough: the
	// signal means "something changed, go and look", and two changes before the
	// looker wakes still only need one look.
	notify := make(chan struct{}, 1)

	c, err := s.dialNotifying(notify)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer c.Close()

	if err := c.Login(s.Username, s.Password).Wait(); err != nil {
		return fmt.Errorf("logging in: %w", err)
	}

	mbox, err := c.Select(s.mailbox(), nil).Wait()
	if err != nil {
		return fmt.Errorf("selecting %s: %w", s.mailbox(), err)
	}
	log.Printf("imap: watching %s (%d messages)", s.mailbox(), mbox.NumMessages)
	// Connected, authenticated, and the folder exists. That is the whole of what a
	// credential check can establish, and it is established here by doing the real
	// thing rather than by a separate code path that might succeed where the real
	// one fails.
	s.reportHealth(ctx, 0, nil)

	// Only unseen mail. A connector that re-analyses an entire mailbox on every restart
	// would re-ingest years of history, and — because ingest is keyed on message id —
	// mostly discover it already had it, slowly.
	if err := s.processUnseen(ctx, c, deliver); err != nil {
		return err
	}

	idle := supportsIDLE(c)
	if !idle {
		log.Printf("imap: server does not advertise IDLE; polling every %s", s.interval())
	}

	for ctx.Err() == nil {
		if idle {
			if err := s.waitIdle(ctx, c, notify); err != nil {
				return err
			}
		} else {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(s.interval()):
			}
		}
		if err := s.processUnseen(ctx, c, deliver); err != nil {
			return err
		}
	}
	return nil
}

func (s *IMAPSource) dial() (*imapclient.Client, error) { return s.dialNotifying(nil) }

// dialNotifying connects, and arranges for the server's unsolicited mailbox updates
// to be delivered to notify.
//
// Without this, IDLE was pointless. The first version issued IDLE and then waited on
// nothing but its own 20-minute refresh timer, so a message arriving a minute after
// the last check sat unread for nineteen more — while the log said the server
// supported IDLE and the documentation said new mail was noticed in seconds. It is a
// hard failure to see from the outside: nothing errors, mail is collected eventually,
// and the only symptom is latency nobody is measuring.
func (s *IMAPSource) dialNotifying(notify chan<- struct{}) (*imapclient.Client, error) {
	opts := &imapclient.Options{}
	if notify != nil {
		opts.UnilateralDataHandler = &imapclient.UnilateralDataHandler{
			Mailbox: func(data *imapclient.UnilateralDataMailbox) {
				if data.NumMessages == nil {
					return
				}
				select {
				case notify <- struct{}{}:
				default:
				}
			},
		}
	}
	if s.Insecure {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
	addr := s.address()
	switch s.TLSMode {
	case "none":
		log.Printf("imap: connecting to %s WITHOUT TLS; the password and every message cross the wire in the clear", addr)
		return imapclient.DialInsecure(addr, opts)
	case "starttls":
		// Fails rather than continuing in the clear if the server will not upgrade.
		return imapclient.DialStartTLS(addr, opts)
	default:
		return imapclient.DialTLS(addr, opts)
	}
}

// address is the host to dial, with the standard port supplied when none was given.
//
// Because "mail.example.com" is what a person types, and what they mean is
// unambiguous: 993 for implicit TLS, 143 otherwise. Without this the dial fails with
// "missing port in address", which is a Go error message about a string rather than
// anything an administrator can act on — and it looks exactly like a credential
// problem, so the natural response is to go and re-enter a password that was right
// all along.
func (s *IMAPSource) address() string {
	addr := strings.TrimSpace(s.Addr)
	if addr == "" {
		return addr
	}
	// An IPv6 literal must already be bracketed to be distinguishable from a
	// host:port, and if it is bracketed without a port SplitHostPort still fails,
	// so the bracket check comes first.
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return net.JoinHostPort(strings.Trim(addr, "[]"), s.defaultPort())
	}
	if strings.Contains(addr, ":") && !strings.Contains(addr, "]") {
		// More than one colon and no brackets: a bare IPv6 literal. Bracket it.
		if strings.Count(addr, ":") > 1 {
			return net.JoinHostPort(addr, s.defaultPort())
		}
	}
	return net.JoinHostPort(addr, s.defaultPort())
}

// defaultPort is the port for the transport in use: 993 is implicit TLS, 143 is the
// plaintext port that STARTTLS upgrades from.
func (s *IMAPSource) defaultPort() string {
	switch s.TLSMode {
	case "none", "starttls":
		return "143"
	default:
		return "993"
	}
}

func supportsIDLE(c *imapclient.Client) bool {
	return c.Caps().Has(imap.CapIdle)
}

// waitIdle blocks until the server reports a change, the context ends, or the IDLE
// times out.
//
// The timeout matters: RFC 2177 says a client must re-issue IDLE at least every 29
// minutes, and middleboxes drop idle connections long before that. 20 minutes keeps
// the connection alive without polling.
//
// The notify channel is the part that makes this IDLE rather than a long sleep: the
// server announces a new message as unsolicited EXISTS data, the handler set up in
// dialNotifying converts that to a signal, and this returns immediately so the caller
// goes and fetches it.
func (s *IMAPSource) waitIdle(ctx context.Context, c *imapclient.Client, notify <-chan struct{}) error {
	// Drain a signal that arrived while the last batch was being processed, so the
	// wait below does not return immediately for a message already collected. Doing
	// it before IDLE starts rather than after means a genuine arrival in between is
	// still seen, because the handler refills the slot.
	select {
	case <-notify:
	default:
	}

	idle, err := c.Idle()
	if err != nil {
		return fmt.Errorf("starting IDLE: %w", err)
	}

	timer := time.NewTimer(20 * time.Minute)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	case <-notify:
	}
	return idle.Close()
}

// processUnseen fetches and delivers every unseen message.
func (s *IMAPSource) processUnseen(ctx context.Context, c *imapclient.Client, deliver Deliver) error {
	criteria := &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}
	found, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return fmt.Errorf("searching: %w", err)
	}
	uids := found.AllUIDs()
	if len(uids) == 0 {
		return nil
	}

	var handled int64
	for start := 0; start < len(uids); start += deliverWindow {
		if ctx.Err() != nil {
			return nil
		}
		end := min(start+deliverWindow, len(uids))
		handled += int64(s.processWindow(ctx, c, uids[start:end], deliver))
	}
	// Once per batch rather than once per message: the count is for the settings
	// page, and a database write per delivered message to maintain it would cost
	// more than the thing it measures.
	if handled > 0 {
		s.reportHealth(ctx, handled, nil)
	}
	return nil
}

// fetchOne reads one message off the connection.
//
// Split out from delivery so the slow part — analysis — can overlap while the
// connection, which is a single conversation and cannot be shared, stays serial.
func (s *IMAPSource) fetchOne(c *imapclient.Client, uid imap.UID) (RawMessage, error) {
	set := imap.UIDSetNum(uid)
	opts := &imap.FetchOptions{
		Envelope:     true,
		InternalDate: true,
		BodySection:  []*imap.FetchItemBodySection{{Peek: true}},
	}

	buf, err := c.Fetch(set, opts).Collect()
	if err != nil {
		return RawMessage{}, fmt.Errorf("fetching: %w", err)
	}
	if len(buf) == 0 {
		return RawMessage{}, errSkipMessage
	}

	var raw []byte
	for _, b := range buf[0].BodySection {
		raw = b.Bytes
		break
	}
	if len(raw) == 0 {
		return RawMessage{}, fmt.Errorf("empty body")
	}

	received := buf[0].InternalDate
	if received.IsZero() {
		received = time.Now().UTC()
	}

	return RawMessage{
		Raw:        raw,
		Source:     "imap",
		Mailbox:    s.mailbox(),
		MailboxID:  s.MailboxID,
		ProviderID: fmt.Sprintf("%v", uid),
		ReceivedAt: received,
	}, nil
}

// errSkipMessage marks a UID that vanished between the search and the fetch,
// which is ordinary: somebody deleted it, or another client moved it.
var errSkipMessage = errors.New("message is no longer there")

// quarantine takes a message out of the mailbox.
//
// # Not a folder move
//
// An earlier version moved the message to a Quarantine folder. That is the wrong
// model: a folder is still the recipient's mailbox, the message is still one click
// away, and "quarantined" then means "filed somewhere else". Here the message is
// removed outright and the engine keeps the only copy, so releasing it is putting it
// back and agreeing with the verdict is simply not doing so.
//
// The order is what matters. The engine already holds the bytes — it stored them
// when it ingested the message, and its action endpoint refuses to queue a removal
// for a message it cannot reproduce — so by the time this runs, deleting is safe.
// This function never deletes a message the engine has not confirmed it holds.
func (s *IMAPSource) quarantine(ctx context.Context, c *imapclient.Client, uid imap.UID, v *Verdict) error {
	if err := s.expunge(c, imap.UIDSetNum(uid)); err != nil {
		return err
	}
	log.Printf("imap: removed %s from %s (%s)", v.MessageID, s.mailbox(), describe(v))
	return s.Engine.RecordAction(ctx, v.MessageID, "quarantine", describe(v), "lazaret-ingest/imap")
}

// expunge deletes a set of messages outright.
func (s *IMAPSource) expunge(c *imapclient.Client, set imap.UIDSet) error {
	flags := &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}}
	if err := c.Store(set, flags, nil).Close(); err != nil {
		return fmt.Errorf("flagging deleted: %w", err)
	}
	// UID EXPUNGE where the server has it, so a concurrent client that deleted
	// something else does not have its message expunged by this call as well.
	if c.Caps().Has(imap.CapUIDPlus) {
		if err := c.UIDExpunge(set).Close(); err != nil {
			return fmt.Errorf("expunging: %w", err)
		}
		return nil
	}
	if err := c.Expunge().Close(); err != nil {
		return fmt.Errorf("expunging: %w", err)
	}
	return nil
}

// Remove finds a message by its Message-ID and deletes it.
//
// By header rather than by UID, because the UID is not recorded anywhere: it is
// meaningful only within one mailbox and one uidvalidity, and a connector that stored
// one would be wrong after any server-side move. The Message-ID is what the engine
// knows the message by, and it is what a person reading an audit log sees.
//
// Not finding it is success. The message may have been deleted by the recipient, or
// filed by a rule, or this may be the second mailbox of two and it was only ever in
// the other one. None of those is a failure to report.
func (s *IMAPSource) Remove(ctx context.Context, messageID string) error {
	return s.withMailbox(ctx, func(c *imapclient.Client) error {
		uids, err := s.findByMessageID(c, messageID)
		if err != nil {
			return err
		}
		if len(uids) == 0 {
			return nil
		}
		set := imap.UIDSet{}
		for _, u := range uids {
			set.AddNum(u)
		}
		if err := s.expunge(c, set); err != nil {
			return err
		}
		log.Printf("imap: removed %s from %s", messageID, s.mailbox())
		return nil
	})
}

// Restore appends a held message back into the mailbox.
//
// Marked unseen and recent, so it arrives looking like mail rather than like
// something that has been read. It cannot be put back in its original position —
// IMAP has no such notion — so it appears as newly delivered, which is the honest
// representation of what happened.
func (s *IMAPSource) Restore(ctx context.Context, messageID string, raw []byte) error {
	if len(raw) == 0 {
		return errors.New("nothing to restore: no message bytes")
	}
	return s.withMailbox(ctx, func(c *imapclient.Client) error {
		// Already there: releasing twice should not produce two copies.
		uids, err := s.findByMessageID(c, messageID)
		if err != nil {
			return err
		}
		if len(uids) > 0 {
			log.Printf("imap: %s is already in %s", messageID, s.mailbox())
			return nil
		}

		opts := &imap.AppendOptions{Time: time.Now()}
		cmd := c.Append(s.mailbox(), int64(len(raw)), opts)
		if _, err := cmd.Write(raw); err != nil {
			return fmt.Errorf("appending: %w", err)
		}
		if err := cmd.Close(); err != nil {
			return fmt.Errorf("appending: %w", err)
		}
		if _, err := cmd.Wait(); err != nil {
			return fmt.Errorf("appending: %w", err)
		}
		log.Printf("imap: restored %s to %s", messageID, s.mailbox())
		return nil
	})
}

func (s *IMAPSource) findByMessageID(c *imapclient.Client, messageID string) ([]imap.UID, error) {
	criteria := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-Id", Value: messageID}},
	}
	data, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("searching for %s: %w", messageID, err)
	}
	return data.AllUIDs(), nil
}

// withMailbox runs fn against a freshly selected mailbox.
//
// A separate connection from the watching session, because that one is usually
// parked in IDLE and issuing a command on it would mean interrupting and restarting
// the wait. Remediation is rare and a connection is cheap.
func (s *IMAPSource) withMailbox(ctx context.Context, fn func(*imapclient.Client) error) error {
	c, err := s.dial()
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer c.Close()
	if err := c.Login(s.Username, s.Password).Wait(); err != nil {
		return fmt.Errorf("logging in: %w", err)
	}
	if _, err := c.Select(s.mailbox(), nil).Wait(); err != nil {
		return fmt.Errorf("selecting %s: %w", s.mailbox(), err)
	}
	return fn(c)
}

// itoa avoids importing strconv for one call site in the shared helpers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// deliverWindow is how many messages are analysed at once within one mailbox.
//
// Live delivery was strictly serial per mailbox: one message finished before the
// next was looked at. Across mailboxes that is fine, because each has its own
// goroutine — but a single busy mailbox, a shared or catch-all address, could not
// keep up. At roughly fourteen seconds a message one stream manages four a minute,
// and a box taking eight falls permanently behind however many other mailboxes are
// idle.
//
// Small on purpose. Sender profiles answer from events strictly before the message
// being judged, so processing order is belief order, and analysing a window
// concurrently makes the order within that window arbitrary. Messages in one poll
// batch arrived within seconds of each other, so the cost is bounded to a handful
// of near-simultaneous messages — but it is a real cost, and four is chosen to keep
// it small rather than to maximise throughput.
const deliverWindow = 4

// fetched is a message read off the connection, waiting to be analysed.
type fetched struct {
	uid      imap.UID
	msg      RawMessage
	fetchErr error
}

// processWindow reads a run of messages, analyses them together, and applies any
// remediation afterwards.
//
// Three phases, because an IMAP connection is a single conversation and cannot be
// used concurrently. Fetching and remediating are cheap and stay on the connection
// in order; the analysis in the middle is the part that takes seconds, and it is
// the only part that overlaps.
func (s *IMAPSource) processWindow(ctx context.Context, c *imapclient.Client, uids []imap.UID, deliver Deliver) int {
	batch := make([]fetched, 0, len(uids))
	for _, uid := range uids {
		if ctx.Err() != nil {
			return len(batch)
		}
		msg, err := s.fetchOne(c, uid)
		batch = append(batch, fetched{uid: uid, msg: msg, fetchErr: err})
	}

	verdicts := make([]*Verdict, len(batch))
	errs := make([]error, len(batch))
	var wg sync.WaitGroup
	for i := range batch {
		if batch[i].fetchErr != nil {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			verdicts[i], errs[i] = deliver(ctx, batch[i].msg)
		}(i)
	}
	wg.Wait()

	for i, f := range batch {
		switch {
		case errors.Is(f.fetchErr, errSkipMessage):
			// Ordinary: somebody deleted it or another client moved it between
			// the search and the fetch. Not worth a line in the log.
		case f.fetchErr != nil:
			// One bad message does not stop the mailbox. A malformed message is
			// exactly what this system exists to look at, and refusing to move
			// past it would let one attacker stall every subsequent delivery.
			log.Printf("imap: uid %v: %v", f.uid, f.fetchErr)
		case errs[i] != nil:
			log.Printf("imap: uid %v: %v", f.uid, errs[i])
		case verdicts[i] != nil && verdicts[i].Actionable() && s.Remediate:
			// Back on the connection, in order, one at a time.
			if err := s.quarantine(ctx, c, f.uid, verdicts[i]); err != nil {
				log.Printf("imap: uid %v: quarantining: %v", f.uid, err)
			}
		}
	}
	return len(batch)
}
