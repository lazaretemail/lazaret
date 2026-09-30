// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log"

	"github.com/lazaretemail/lazaret/actions"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Carrying out what a rule asked for.
//
// This is the most dangerous code in the platform. Everything else reports; this
// changes somebody's mailbox without asking them, because a rule fired. So it is
// written to refuse rather than to guess, and each refusal below is a thing that
// would otherwise be a message nobody can get back.
//
// # The four gates
//
//  1. The rule must have an action configured. Rules have none until an
//     administrator gives them one, so a fresh deployment does nothing.
//  2. The mailbox must allow remediation. Off by default, per mailbox, and it is
//     the mailbox owner's veto over every rule in the system.
//  3. A destructive action must have custody. Quarantine removes the only copy the
//     recipient has; if this platform does not hold another, the message is gone
//     for good and the action is refused.
//  4. A released message is left alone. A person has already overruled the verdict,
//     and re-acting on it would undo their decision within seconds — with the only
//     visible symptom being a message that will not stay released.
//
// # Order
//
// Actions run least disruptive first, which package actions guarantees. A rule set
// to flag and quarantine flags a message that still exists; the other order flags
// nothing.

// autoAct queues the actions the matched rules call for.
//
// Returns what it queued, so the ingest response can say — a connector that just
// handed over a message deserves to know the platform is about to change it.
func (p *Pipeline) autoAct(ctx context.Context, tenant string, a *Analysis, opts IngestOptions) []string {
	// Gate 4 first, because it is about the message rather than the rules: a
	// person's decision outranks every rule that would undo it.
	if a.Released {
		return nil
	}

	// A retrospective scan never acts. The message was delivered weeks ago and a
	// sweep is not a delivery decision — see services/ingest/backfill.go. The
	// connector already declines to act on what a scan returns; this makes the
	// engine decline to ask, so neither side relies on the other for it.
	if opts.BackfillID != "" {
		return nil
	}
	if len(a.Matched) == 0 || opts.MailboxID == "" {
		return nil
	}

	configured, err := p.store.RuleActions(ctx, tenant)
	if err != nil {
		log.Printf("actions: reading the configuration: %v", err)
		return nil
	}
	if len(configured) == 0 {
		return nil // nothing configured anywhere, which is the default
	}

	// Gate 1: the union of what the matched rules ask for, deduplicated by
	// instance — two rules attached to the same "Auto-trash" trash it once.
	seen := map[string]bool{}
	var wanted []actions.Instance
	for _, m := range a.Matched {
		for _, cfg := range configured[m.ID] {
			if seen[cfg.ID] {
				continue
			}
			seen[cfg.ID] = true
			wanted = append(wanted, cfg.Instance)
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	// Least disruptive first, so a rule set to flag and quarantine flags a
	// message that still exists.
	wanted = actions.Order(wanted)

	// Gate 2: the mailbox's veto, read once.
	box, err := p.mailbox(ctx, tenant, opts.MailboxID)
	if err != nil || box == nil {
		log.Printf("actions: %s: cannot read the mailbox, so nothing is done", a.MessageID)
		return nil
	}

	held := p.store.HasRaw(ctx, tenant, a.MessageID)

	var queued []string
	for _, inst := range wanted {
		def := inst.Definition()

		// Engine-side only: no mailbox, no connector, no permission needed.
		if !def.TouchesMailbox {
			switch inst.Type {
			case actions.Review:
				p.queueForReview(ctx, tenant, a.MessageID, inst.Label)
				queued = append(queued, inst.Label)
			case actions.Notify:
				p.notify(ctx, tenant, inst, a)
				queued = append(queued, inst.Label)
			}
			continue
		}

		if !box.Remediate {
			// Not an error, and worth saying once: the rule asked, the mailbox
			// has not opted in, and the difference matters when somebody asks
			// why nothing happened.
			log.Printf("actions: %s: %q not taken — %s does not allow remediation",
				a.MessageID, inst.Label, box.Address)
			continue
		}

		// Gate 3.
		if def.NeedsCustody && !held {
			log.Printf("actions: %s: %q refused — the original is not held, so it "+
				"could not be released again", a.MessageID, inst.Label)
			continue
		}

		if !def.Supports(box.Kind) {
			log.Printf("actions: %s: %q is not something a %s mailbox can do",
				a.MessageID, inst.Label, box.Kind)
			continue
		}

		if err := p.store.EnqueueAction(ctx, tenant, a.MessageID, opts.MailboxID,
			opString(inst.Type), inst.Config); err != nil {
			log.Printf("actions: %s: queueing %q: %v", a.MessageID, inst.Label, err)
			continue
		}
		queued = append(queued, inst.Label)
	}

	if len(queued) > 0 {
		// Attributed to the rules rather than to a person, so the audit trail can
		// answer "who did this" with something other than a name that is wrong.
		_ = p.store.RecordAction(ctx, tenant, a.MessageID, "auto:"+joinComma(queued),
			"detection rules", "")
		log.Printf("actions: %s: queued %v", a.MessageID, queued)
	}
	return queued
}

// opString maps an action type to the remediation op a connector understands.
//
// Quarantine is "remove" for one reason: that is what the column already said
// before actions existed, and rewriting a queue that somebody is waiting on to make
// a name tidier is not worth the risk.
func opString(k actions.Type) string {
	if k == actions.Quarantine {
		return "remove"
	}
	return string(k)
}

// queueForReview puts a message in front of a person without touching the mailbox.
func (p *Pipeline) queueForReview(ctx context.Context, tenant, messageID, label string) {
	err := p.store.SetTriage(ctx, tenant, messageID, store.Triage{
		State: store.StateNeedsRemediation,
		Note:  "queued automatically by " + label,
	}, "detection rules")
	if err != nil {
		log.Printf("actions: %s: queueing for review: %v", messageID, err)
	}
}

// mailbox reads one mailbox by id.
func (p *Pipeline) mailbox(ctx context.Context, tenant, id string) (*store.Mailbox, error) {
	boxes, err := p.store.Mailboxes(ctx, tenant, false)
	if err != nil {
		return nil, err
	}
	for i := range boxes {
		if boxes[i].ID == id {
			return &boxes[i], nil
		}
	}
	return nil, nil
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
