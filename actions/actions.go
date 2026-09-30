// SPDX-License-Identifier: AGPL-3.0-only

// Package actions is what a detection may do about a message.
//
// Until now a verdict produced a report and, if an operator had turned remediation
// on for a mailbox, a quarantine. One answer to every question, and the wrong
// granularity: "this is a credential phish" and "this is a newsletter the finance
// team finds annoying" both deserve a response and they are not the same response.
//
// # Types and instances
//
// A *type* is something this platform knows how to do — move a message, flag it,
// queue it for review. An *instance* is a configured, named one: "Move to Spam" and
// "Move to Promotions" are two instances of the same type differing only in the
// folder. Rules are attached to instances, not to types, which is what lets one
// deployment have three different move actions and another have none.
//
// That indirection earns its keep in the interface as well: an administrator picks
// "Auto-trash" from a list of things their organisation has decided on, rather than
// re-deciding what trashing means on every one of a thousand rules.
//
// # Everything is off until somebody turns it on
//
// A rule with no actions reports and does nothing, which is every rule on a fresh
// deployment. This package automates changes to other people's mailboxes because a
// rule fired, and the failure mode of getting it wrong is not a missed detection —
// it is a deleted message.
//
// # Three properties that are not negotiable
//
//   - Destructive actions need custody. Quarantine removes the message, so this
//     platform's copy becomes the only one. No custody, no quarantine.
//   - The mailbox has a veto, off by default and per mailbox. A rule cannot reach
//     into a mailbox that has not opted in.
//   - What a connector cannot do, it says so, rather than skipping quietly — the
//     same reason an enrichment that cannot run reports indeterminate, not false.
package actions

import (
	"fmt"
	"strings"
)

// Type identifies what an action does. The strings are stable: they are in the
// database, the audit trail and the API.
type Type string

const (
	// Review queues the message for a person and touches no mailbox. The safest
	// thing a rule can do that is not nothing, and the right first action for a
	// rule an operator is still making up their mind about.
	Review Type = "review"

	// MarkRead marks the message read where it sits.
	MarkRead Type = "mark_read"

	// Flag marks it without moving it: a flag on IMAP, a category on Graph.
	Flag Type = "flag"

	// Move moves it to a named folder. One type covers junk, promotions and
	// anything else a deployment files things into — the folder is configuration,
	// not a separate capability.
	Move Type = "move"

	// Trash moves it to the provider's deleted-items folder, where the recipient
	// can still recover it. Distinct from Move because the folder is the
	// provider's own and is not named the same thing everywhere.
	Trash Type = "trash"

	// Quarantine removes it from the mailbox entirely and holds the only copy.
	Quarantine Type = "quarantine"

	// Notify posts to a webhook. Touches no mailbox; useful for a chat channel or
	// a ticketing system that should hear about a detection.
	Notify Type = "notify"
)

// Definition describes a type: what it does, what it needs, and what configuring
// an instance of it requires.
type Definition struct {
	Type  Type   `json:"type"`
	Label string `json:"label"`

	// Detail is what it does, in the words shown to whoever turns it on.
	Detail string `json:"detail"`

	// Destructive marks an action that takes the message away from its recipient.
	Destructive bool `json:"destructive"`

	// NeedsCustody marks one that cannot be undone without this platform's copy.
	NeedsCustody bool `json:"needs_custody"`

	// TouchesMailbox is false for actions that only change state here. Those need
	// no mailbox permission and no connector.
	TouchesMailbox bool `json:"touches_mailbox"`

	// Providers lists the connector kinds that can carry it out.
	Providers []string `json:"providers"`

	// Params are the settings an instance of this type needs.
	Params []Param `json:"params,omitempty"`

	// Rank orders types from least to most disruptive. Actions on a message run
	// in this order, so a rule set to flag and quarantine flags a message that
	// still exists; the reverse order would flag nothing.
	Rank int `json:"rank"`
}

// Param is one setting on an instance.
type Param struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Detail   string `json:"detail,omitempty"`
	Required bool   `json:"required"`

	// Placeholder is an example rather than a default: a folder name guessed
	// wrong files mail somewhere nobody looks.
	Placeholder string `json:"placeholder,omitempty"`
}

// Types is everything this platform knows how to do, least disruptive first.
var Types = []Definition{
	{
		Type: Review, Label: "Send for review", Rank: 10,
		Detail: "Queue the message for a person to look at. The mailbox is not " +
			"touched and the recipient sees nothing.",
		Providers: []string{"imap", "graph", "rspamd"},
	},
	{
		Type: Notify, Label: "Notify a webhook", Rank: 20,
		Detail: "Post the detection to a URL — a chat channel, a ticket queue. " +
			"Touches no mailbox.",
		Providers: []string{"imap", "graph", "rspamd"},
		Params: []Param{
			{Name: "url", Label: "Webhook URL", Required: true,
				Placeholder: "https://hooks.example.com/…",
				Detail:      "Receives a JSON summary of the message and the rules that fired."},
		},
	},
	{
		Type: MarkRead, Label: "Mark as read", Rank: 30,
		Detail:         "Mark the message read where it sits. For noise that is real but that nobody needs to open.",
		TouchesMailbox: true, Providers: []string{"imap", "graph"},
	},
	{
		Type: Flag, Label: "Flag", Rank: 40,
		Detail: "Flag the message without moving it — a flag on IMAP, a category " +
			"on Microsoft 365. The recipient keeps it and can see something noticed.",
		TouchesMailbox: true, Providers: []string{"imap", "graph"},
	},
	{
		Type: Move, Label: "Move to a folder", Rank: 50,
		Detail: "Move the message to a folder you name — junk, promotions, a " +
			"review folder. The recipient can still find it.",
		TouchesMailbox: true, Providers: []string{"imap", "graph"},
		Params: []Param{
			{Name: "folder", Label: "Folder", Required: true, Placeholder: "Junk",
				Detail: "The folder as the provider names it. A folder that does not " +
					"exist is an error rather than a silently created one — creating " +
					"folders in somebody's mailbox is not something a rule should do."},
		},
	},
	{
		Type: Trash, Label: "Move to deleted items", Rank: 60,
		Detail: "Move the message to the provider's deleted-items folder. " +
			"Recoverable by the recipient until they empty it.",
		TouchesMailbox: true, Providers: []string{"imap", "graph"},
	},
	{
		Type: Quarantine, Label: "Quarantine", Rank: 70,
		Detail: "Remove the message from the mailbox entirely and hold the only " +
			"copy. The recipient cannot see or recover it; releasing puts it back. " +
			"Refused unless the original is held, because otherwise it could not be.",
		Destructive: true, NeedsCustody: true, TouchesMailbox: true,
		Providers: []string{"imap", "graph"},
	},
}

var byType = func() map[Type]Definition {
	m := make(map[Type]Definition, len(Types))
	for _, d := range Types {
		m[d.Type] = d
	}
	return m
}()

// Define returns a type's definition.
func Define(t Type) (Definition, bool) {
	d, ok := byType[t]
	return d, ok
}

// Supports reports whether a connector kind can carry out this type.
func (d Definition) Supports(provider string) bool {
	for _, p := range d.Providers {
		if p == provider {
			return true
		}
	}
	return false
}

// Instance is a configured, named action that rules are attached to.
type Instance struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  Type   `json:"type"`

	// Config holds the type's parameters. Empty for types that have none.
	Config map[string]string `json:"config,omitempty"`

	// Enabled is a deployment-wide off switch. Turning an instance off stops
	// every rule using it without anyone having to remember which rules those
	// were — which is what you want at three in the morning.
	Enabled bool `json:"enabled"`
}

// Validate checks an instance against its type.
func (i Instance) Validate() error {
	d, ok := byType[i.Type]
	if !ok {
		return fmt.Errorf("actions: %q is not an action type", i.Type)
	}
	if strings.TrimSpace(i.Label) == "" {
		return fmt.Errorf("actions: an action needs a label")
	}
	for _, p := range d.Params {
		if p.Required && strings.TrimSpace(i.Config[p.Name]) == "" {
			return fmt.Errorf("actions: %s needs %s", d.Label, p.Label)
		}
	}
	return nil
}

// Definition returns the type behind an instance.
func (i Instance) Definition() Definition { return byType[i.Type] }

// Order sorts instances least disruptive first, which is the order they are
// carried out in. See Definition.Rank.
func Order(in []Instance) []Instance {
	out := append([]Instance(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && byType[out[j].Type].Rank < byType[out[j-1].Type].Rank; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
