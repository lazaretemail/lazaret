// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Carrying out a rule's action on an IMAP mailbox.
//
// The gentler half of remediation: move it, flag it, mark it read. Quarantine and
// its reversal live in imap.go, because those are about custody — the platform
// holding the only copy — and these leave the message with its recipient.
//
// Every one of them finds the message by Message-ID rather than by a stored UID.
// A UID is only meaningful within one folder and changes when a message is moved,
// so a UID captured at delivery is no use by the time an action runs; the
// Message-ID is what survives.

// Apply implements Filer.
func (s *IMAPSource) Apply(ctx context.Context, op, messageID string, config map[string]string) error {
	return s.withMailbox(ctx, func(c *imapclient.Client) error {
		uids, err := s.findByMessageID(c, messageID)
		if err != nil {
			return err
		}
		if len(uids) == 0 {
			// Already gone: filed by a rule in the mail client, deleted by the
			// recipient, moved by another action. Not an error — the desired
			// state is that it is not in the inbox, and it is not.
			return nil
		}
		set := imap.UIDSetNum(uids...)

		switch op {
		case "trash":
			return s.moveTo(c, set, s.specialFolder(c, `\Trash`, "Trash"))
		case "spam":
			return s.moveTo(c, set, s.specialFolder(c, `\Junk`, "Junk"))
		case "move":
			folder := strings.TrimSpace(config["folder"])
			if folder == "" {
				return fmt.Errorf("move: no folder configured")
			}
			return s.moveTo(c, set, folder)
		case "flag":
			return s.store(c, set, imap.StoreFlagsAdd, imap.FlagFlagged)
		case "mark_read":
			return s.store(c, set, imap.StoreFlagsAdd, imap.FlagSeen)
		default:
			return fmt.Errorf("imap: unknown action %q", op)
		}
	})
}

// moveTo moves messages into a folder, refusing rather than creating one.
//
// Creating folders in somebody's mailbox is not something a detection rule should
// do. A typo in a folder name would otherwise scatter mail into a directory nobody
// knows exists, and the first sign of it would be mail that had silently stopped
// arriving.
func (s *IMAPSource) moveTo(c *imapclient.Client, set imap.UIDSet, folder string) error {
	if folder == "" {
		return fmt.Errorf("imap: no destination folder")
	}
	if _, err := c.Move(set, folder).Wait(); err != nil {
		return fmt.Errorf("moving to %q: %w", folder, err)
	}
	return nil
}

// store adds a flag.
func (s *IMAPSource) store(c *imapclient.Client, set imap.UIDSet, op imap.StoreFlagsOp, flag imap.Flag) error {
	cmd := c.Store(set, &imap.StoreFlags{Op: op, Flags: []imap.Flag{flag}}, nil)
	if err := cmd.Close(); err != nil {
		return fmt.Errorf("setting %v: %w", flag, err)
	}
	return nil
}

// specialFolder finds the folder a server has marked for a purpose, falling back
// to a conventional name.
//
// Servers disagree about what the junk folder is called — Junk, Spam, Junk E-mail,
// and translated versions of each — so the SPECIAL-USE attribute is asked for
// first. The fallback is a guess and is only reached on servers that do not
// publish one; a wrong guess surfaces as a failed move rather than as mail filed
// somewhere unexpected, because moveTo will not create what is not there.
func (s *IMAPSource) specialFolder(c *imapclient.Client, attr, fallback string) string {
	boxes, err := c.List("", "*", &imap.ListOptions{ReturnSpecialUse: true}).Collect()
	if err != nil {
		return fallback
	}
	for _, b := range boxes {
		for _, a := range b.Attrs {
			if string(a) == attr {
				return b.Mailbox
			}
		}
	}
	// A case-insensitive name match, for servers with the folder but no
	// SPECIAL-USE capability.
	for _, b := range boxes {
		if strings.EqualFold(b.Mailbox, fallback) {
			return b.Mailbox
		}
	}
	return fallback
}
