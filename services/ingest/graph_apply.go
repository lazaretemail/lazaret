// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Carrying out a rule's action on a Microsoft 365 mailbox.
//
// Graph names the well-known folders, so junk and deleted items are asked for by
// name rather than guessed at — `deleteditems` and `junkemail` are the same
// wherever the mailbox is and whatever language it is in, which is more than can
// be said for IMAP.
//
// Flagging is a category rather than a flag: Graph's followup flag is the
// recipient's own to-do marker and taking it over would be rude and confusing.
// A category is what a system is supposed to add.

// graphCategory is what a flag action adds. Named so a recipient seeing it in
// Outlook has some idea where it came from.
const graphCategory = "Lazaret"

// Apply implements Filer.
func (g *GraphSource) Apply(ctx context.Context, op, messageID string, config map[string]string) error {
	mailbox := g.walkMailbox()
	if mailbox == "" {
		return fmt.Errorf("graph: no mailbox configured")
	}
	// By Message-ID, not by a stored provider id: the provider id changes when a
	// message moves between folders, so one captured at delivery is no use by the
	// time an action runs.
	ids, err := g.findByMessageID(ctx, mailbox, messageID)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		// Already gone: filed by a rule in Outlook, deleted by the recipient,
		// moved by an earlier action. Not an error — the desired state is that
		// it is not in the inbox, and it is not.
		return nil
	}
	id := ids[0]

	switch op {
	case "trash":
		return g.moveToFolder(ctx, mailbox, id, "deleteditems")
	case "spam":
		return g.moveToFolder(ctx, mailbox, id, "junkemail")
	case "move":
		folder := strings.TrimSpace(config["folder"])
		if folder == "" {
			return fmt.Errorf("move: no folder configured")
		}
		target, err := g.findFolder(ctx, mailbox, folder)
		if err != nil {
			return err
		}
		return g.moveToFolder(ctx, mailbox, id, target)
	case "flag":
		return g.patch(ctx, mailbox, id, map[string]any{"categories": []string{graphCategory}})
	case "mark_read":
		return g.patch(ctx, mailbox, id, map[string]any{"isRead": true})
	default:
		return fmt.Errorf("graph: unknown action %q", op)
	}
}

// moveToFolder moves a message. The destination is a folder id or one of Graph's
// well-known names.
func (g *GraphSource) moveToFolder(ctx context.Context, mailbox, id, folder string) error {
	body, err := json.Marshal(map[string]string{"destinationId": folder})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s/move",
		g.graphBase(), url.PathEscape(mailbox), url.PathEscape(id))
	if _, err := g.call(ctx, http.MethodPost, endpoint, body); err != nil {
		return fmt.Errorf("moving to %s: %w", folder, err)
	}
	return nil
}

// patch changes properties on a message in place.
func (g *GraphSource) patch(ctx context.Context, mailbox, id string, fields map[string]any) error {
	body, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s",
		g.graphBase(), url.PathEscape(mailbox), url.PathEscape(id))
	_, err = g.call(ctx, http.MethodPatch, endpoint, body)
	return err
}

// findFolder resolves a folder name to its id, refusing rather than creating.
//
// Creating a folder in somebody's mailbox is not a detection rule's business, and
// a typo would otherwise file mail into a directory nobody knows exists.
func (g *GraphSource) findFolder(ctx context.Context, mailbox, name string) (string, error) {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/mailFolders?$top=200&$select=id,displayName",
		g.graphBase(), url.PathEscape(mailbox))
	raw, err := g.call(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	var page struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return "", err
	}
	for _, f := range page.Value {
		if strings.EqualFold(f.Name, name) {
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("no folder named %q in %s; create it first — a rule will not", name, mailbox)
}
