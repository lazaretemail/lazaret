// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rules"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Looking again at mail that has already been delivered.
//
// Two things make yesterday's verdict wrong, and neither is visible to a pipeline that
// only judges mail on the way in:
//
//   - Intelligence arrives late. A feed adds a domain at two in the afternoon; the
//     message carrying it landed at nine that morning. Most phishing is attributed
//     hours after it is delivered, so this is where a large share of the real catches
//     are.
//   - The link changes. Serving something harmless until the mail has landed is the
//     cheapest evasion there is against anything that looks once.
//
// Both are handled the same way and neither acts. A sweep files findings; a person
// decides. That is the same rule a retrospective scan follows, and for the same reason:
// a message delivered two months ago is not a delivery decision today, and a feed
// update that quarantined three hundred old messages would be a bad afternoon.
//
// # Why this is affordable
//
// Because enrichment is frozen beside each message. Re-running a rule set over ninety
// days is a columnar scan and no network at all — no models, no WHOIS, no browsers.
// Without that it would be a re-analysis of every message, which nobody would run, and
// which would answer a question about March with October's facts anyway.
type Retro struct {
	store  *store.Store
	lists  mql.ListResolver
	engine func() *rules.Engine
	reg    *mql.Registry
	tenant string

	// window is how far back a sweep looks. Beyond this a message is old enough that
	// it is a hunt somebody runs deliberately, not something a nightly job should be
	// walking.
	window time.Duration

	// armed says whether anything triggers a sweep. Reported to the console, because
	// an empty findings list means two opposite things depending on it: nothing has
	// turned up, or nothing is looking.
	armed bool
}

// Arm records that this sweeper is wired to something that triggers it.
func (r *Retro) Arm() { r.armed = true }

// Armed reports whether new content triggers a sweep.
func (r *Retro) Armed() bool { return r != nil && r.armed }

// WindowDays is how far back a sweep looks, for the console to say so.
func (r *Retro) WindowDays() int {
	if r == nil {
		return 0
	}
	return int(r.window.Hours() / 24)
}

// NewRetro returns a sweeper.
func NewRetro(s *store.Store, lists mql.ListResolver, engine func() *rules.Engine, tenant string, window time.Duration) *Retro {
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	return &Retro{store: s, lists: lists, engine: engine, tenant: tenant, window: window}
}

// UseRegistry sets the function set, so a sweep evaluates what it compiled.
func (r *Retro) UseRegistry(reg *mql.Registry) { r.reg = reg }

// SweepRules runs the named rules over stored mail and files a finding for anything
// they match that was not already flagged.
//
// Named rules rather than the whole set, because the question is "what does this new
// content find in what we already have" — running every rule over every message nightly
// would re-derive the verdicts already recorded and file findings for all of them.
//
// A match on a message whose verdict was already malicious is not filed. The point of a
// finding is that a conclusion was reached without something now known; a message
// already quarantined has had its decision made, and filing it again is noise.
func (r *Retro) SweepRules(ctx context.Context, ruleNames []string) (int, error) {
	if r.store == nil || r.engine == nil {
		return 0, fmt.Errorf("no corpus is configured, so there is nothing to sweep")
	}
	eng := r.engine()
	if eng == nil {
		return 0, fmt.Errorf("no rules are loaded")
	}

	wanted := map[string]bool{}
	for _, n := range ruleNames {
		wanted[n] = true
	}

	// The engine's own compiled set, not a recompile. A sweep that compiled the source
	// again could disagree with what is running — a different registry, a rule edited
	// between load and sweep — and a finding that says "this rule would have fired" has
	// to mean the rule that is actually deployed.
	type compiled struct {
		name    string
		checked *mql.Checked
	}
	var set []compiled
	for _, c := range eng.Compiled() {
		if c.Entity == nil || !wanted[c.Entity.Name] {
			continue
		}
		switch c.Entity.Type {
		case rules.KindRule, rules.KindDLP:
		default:
			// An insight query has no "would have fired", and an exclusion firing is
			// the opposite of a finding.
			continue
		}
		if c.Checked.Type.KindOr(mdm.KindBool) != mdm.KindBool {
			continue
		}
		set = append(set, compiled{name: c.Entity.Name, checked: c.Checked})
	}
	if len(set) == 0 {
		return 0, nil
	}

	to := time.Now().UTC()
	from := to.Add(-r.window)
	filed := 0

	_, err := r.store.ScanMessagesWithEvidence(ctx, r.tenant, from, to,
		func(m store.ScannedMessage) error {
			// Already judged malicious: the decision has been made, and re-filing it
			// buries the findings that are actually new.
			if m.Verdict == "malicious" {
				return nil
			}
			var msg mdm.MessageDataModel
			if err := json.Unmarshal(m.MDM, &msg); err != nil {
				return nil
			}
			snap := snapshotOf(m.Evidence)

			for _, c := range set {
				opts := &mql.EvalOptions{Lists: r.lists, Registry: r.reg}
				if c.checked.NeedsEnrichment() {
					opts.Enricher = mql.NewReplay(snap)
				}
				if mql.Eval(ctx, c.checked, &msg, opts).Verdict != mql.Match {
					continue
				}
				fresh, err := r.store.RecordFinding(ctx, r.tenant, store.RetroFinding{
					MessageID: m.MessageID,
					Kind:      store.FindingRule,
					Source:    c.name,
					Detail: fmt.Sprintf("matches a rule that was not in effect when this "+
						"message was judged; the verdict at the time was %q", verdictOr(m.Verdict)),
				})
				if err == nil && fresh {
					filed++
				}
			}
			return nil
		})
	if err != nil {
		return filed, err
	}
	if filed > 0 {
		log.Printf("retro: %d message(s) already delivered match rules that were not in "+
			"effect at the time", filed)
	}
	return filed, nil
}

func verdictOr(v string) string {
	if v == "" {
		return "none recorded"
	}
	return v
}

// LinkDigest is what a link looked like, reduced to something worth comparing.
//
// Deliberately not a hash of the page. A page that changes on every load — a nonce, a
// timestamp, a rotating advert — would then look like an attack every time. What
// matters is whether the link now goes somewhere else or now serves something when it
// served nothing: the final URL after redirects, whether anything was retrieved, and
// the rough size of what came back.
func LinkDigest(effectiveURL string, retrieved bool, bodyLen int) string {
	// Size is bucketed by order of magnitude, so ordinary churn in a page does not
	// read as a change while a 404 becoming a login form does.
	bucket := 0
	for n := bodyLen; n >= 10; n /= 10 {
		bucket++
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%t|%d", effectiveURL, retrieved, bucket)))
	return hex.EncodeToString(h[:8])
}

// SweepLists checks the rules that read the named lists against delivered mail.
//
// A threat-intel list gaining a domain is the same event as a feed gaining a rule: the
// engine now knows something it did not know when Tuesday's mail was judged, and the
// message carrying that domain is already in the corpus. Most attributions land hours
// after delivery, so this is where a large share of the real catches are.
//
// Only rules that actually reference one of the changed lists. Sweeping everything on
// every list refresh would re-derive every verdict in the corpus every fifteen minutes,
// which is both expensive and noise: the findings that are genuinely new would be
// buried under repeats.
func (r *Retro) SweepLists(ctx context.Context, lists []string) (int, error) {
	if r.engine == nil {
		return 0, nil
	}
	eng := r.engine()
	if eng == nil {
		return 0, nil
	}

	changed := map[string]bool{}
	for _, l := range lists {
		changed[strings.TrimPrefix(l, "$")] = true
	}

	var names []string
	for _, c := range eng.Compiled() {
		if c.Entity == nil {
			continue
		}
		for _, l := range c.Checked.Lists {
			if changed[strings.TrimPrefix(l, "$")] {
				names = append(names, c.Entity.Name)
				break
			}
		}
	}
	if len(names) == 0 {
		return 0, nil
	}
	return r.SweepRules(ctx, names)
}
