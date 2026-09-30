// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

// Walking a Microsoft 365 mailbox's existing mail.
//
// Graph is better suited to this than IMAP: receivedDateTime is a real timestamp, it
// can be filtered and ordered server-side, and paging is a URL the server hands back.
// So the query asks for exactly the window, in ascending order, and follows
// @odata.nextLink until it runs out.
//
// The ordering is asked for rather than imposed afterwards, which is worth being
// careful about: $orderby and $filter on the same property is one of the few
// combinations Graph accepts without a ConsistencyLevel header, and reordering on
// this side would only work within a page anyway.
//
// Each message still costs a second request for its MIME, because Graph's JSON is
// Microsoft's parse of the headers rather than what arrived, and the engine's input
// has to be the original bytes.

// graphPageSize is how many message references are listed per request. The bodies
// are fetched one at a time regardless, so this only bounds the listing.
const graphPageSize = 100

// Walk implements HistoricalSource for one mailbox.
func (g *GraphSource) Walk(ctx context.Context, from, until time.Time, visit func(context.Context, RawMessage) error) error {
	mailbox := g.walkMailbox()
	if mailbox == "" {
		return fmt.Errorf("graph: no mailbox configured to scan")
	}

	next := fmt.Sprintf(
		"%s/v1.0/users/%s/mailFolders/inbox/messages"+
			"?$select=id,receivedDateTime"+
			"&$filter=receivedDateTime ge %s and receivedDateTime lt %s"+
			"&$orderby=receivedDateTime asc"+
			"&$top=%d",
		g.graphBase(), url.PathEscape(mailbox),
		from.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339),
		graphPageSize)

	for next != "" {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		body, err := g.call(ctx, http.MethodGet, next, nil)
		if err != nil {
			return fmt.Errorf("graph: listing the window: %w", err)
		}

		var page struct {
			Value []struct {
				ID       string    `json:"id"`
				Received time.Time `json:"receivedDateTime"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("graph: decoding the listing: %w", err)
		}

		for _, m := range page.Value {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			raw, err := g.call(ctx, http.MethodGet, fmt.Sprintf("%s/v1.0/users/%s/messages/%s/$value",
				g.graphBase(), url.PathEscape(mailbox), url.PathEscape(m.ID)), nil)
			if err != nil {
				// One unreadable message does not end a ninety-day scan.
				log.Printf("graph: fetching %s: %v", m.ID, err)
				continue
			}
			err = visit(ctx, RawMessage{
				Raw:        raw,
				Source:     "graph",
				Mailbox:    mailbox,
				MailboxID:  g.MailboxID,
				ProviderID: m.ID,
				ReceivedAt: m.Received,
			})
			if err != nil {
				return err
			}
		}

		next = page.Next
	}
	return nil
}

// walkMailbox is which mailbox this connector scans.
//
// A Graph connector can watch several, but a scan is created against one mailbox
// row, so the connector that claims it is the one configured for that mailbox.
func (g *GraphSource) walkMailbox() string {
	if len(g.Mailboxes) > 0 {
		return g.Mailboxes[0]
	}
	return ""
}
