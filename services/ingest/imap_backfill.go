// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Walking an IMAP mailbox's existing mail.
//
// IMAP makes this nearly pleasant: SINCE and BEFORE are server-side date searches,
// so the server does the selection and hands back the UIDs that fall in the window.
//
// Two things it does not give, and both are handled here.
//
// A UID is only approximately chronological. It is assigned on arrival in a folder,
// so a message filed later, or moved between folders, gets a UID that says nothing
// about when it was received — and ordering by UID would therefore process some mail
// out of order, which is the one thing a history rebuild must not do. So every batch
// is sorted by its real INTERNALDATE before anything is delivered.
//
// And SINCE and BEFORE work in whole days, in the server's timezone. The window is
// therefore widened to whole days at the search and narrowed back to the exact
// instants here, so resuming mid-day neither skips mail nor reprocesses a day's
// worth of it.

// imapBackfillBatch is how many messages are fetched at once. Each is a full body,
// so this is a memory budget as much as a round-trip one.
const imapBackfillBatch = 50

// Walk implements HistoricalSource.
func (s *IMAPSource) Walk(ctx context.Context, from, until time.Time, visit func(context.Context, RawMessage) error) error {
	return s.withMailbox(ctx, func(c *imapclient.Client) error {
		// Whole days, widened outward: SINCE is inclusive of its day and BEFORE
		// exclusive, both at day granularity, so asking for the exact instants
		// would drop the mail on the boundary days.
		criteria := &imap.SearchCriteria{
			Since:  from.UTC().AddDate(0, 0, -1),
			Before: until.UTC().AddDate(0, 0, 1),
		}
		found, err := c.UIDSearch(criteria, nil).Wait()
		if err != nil {
			return fmt.Errorf("searching the window: %w", err)
		}
		uids := found.AllUIDs()
		if len(uids) == 0 {
			return nil
		}
		log.Printf("imap: %d message(s) in the window for %s", len(uids), s.mailbox())

		for start := 0; start < len(uids); start += imapBackfillBatch {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			end := min(start+imapBackfillBatch, len(uids))

			batch, err := s.fetchBatch(c, uids[start:end], from, until)
			if err != nil {
				// One bad batch does not end the scan: a malformed message is
				// exactly what this exists to look at, and stopping would let
				// one of them hide everything after it.
				log.Printf("imap: fetching uids %v-%v: %v", uids[start], uids[end-1], err)
				continue
			}

			// The sort is the load-bearing line. See the file comment: UID order
			// is not receipt order, and processing out of order rebuilds the
			// sender history in an order that never happened.
			sortByTime(batch)

			for _, msg := range batch {
				if err := visit(ctx, msg); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// fetchBatch reads a run of UIDs and keeps the ones genuinely inside the window.
func (s *IMAPSource) fetchBatch(c *imapclient.Client, uids []imap.UID, from, until time.Time) ([]RawMessage, error) {
	set := imap.UIDSetNum(uids...)
	opts := &imap.FetchOptions{
		Envelope:     true,
		InternalDate: true,
		UID:          true,
		BodySection:  []*imap.FetchItemBodySection{{Peek: true}},
	}
	buf, err := c.Fetch(set, opts).Collect()
	if err != nil {
		return nil, err
	}

	out := make([]RawMessage, 0, len(buf))
	for _, m := range buf {
		if m == nil {
			continue
		}
		at := m.InternalDate
		// The day-granularity search returns the boundary days whole; this is
		// where the window becomes exact again.
		if at.Before(from) || !at.Before(until) {
			continue
		}
		var raw []byte
		for _, b := range m.BodySection {
			if len(b.Bytes) > 0 {
				raw = b.Bytes
				break
			}
		}
		if len(raw) == 0 {
			continue
		}
		out = append(out, RawMessage{
			Raw:        raw,
			Source:     s.Name(),
			Mailbox:    s.Username,
			MailboxID:  s.MailboxID,
			ProviderID: fmt.Sprintf("%v", m.UID),
			ReceivedAt: at,
		})
	}
	return out, nil
}

// Peek is not optional above. A backfill that marked ninety days of mail as read
// would be a visible, irreversible change to someone's mailbox made by a tool that
// was only supposed to be looking — and the complaint would arrive long before
// anyone read the findings.
