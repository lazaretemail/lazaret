// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/render"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Looking at a link twice.
//
// A link is visited once, while the message is being judged, and never again. That is a
// known and cheap evasion: serve a Cloudflare holding page, or a real login form for the
// brand you are impersonating, until the mail has cleared the gateway, then swap in the
// credential harvester. Anything that looks once sees the harmless version, and the
// analysis is not wrong — it is just about a page that no longer exists.
//
// So links from delivered mail are looked at again, a few times over the following day,
// and a change is filed as a finding. Nothing is quarantined: the same rule as every
// other retrospective surface. What changed is shown to a person, because "this link now
// goes somewhere else" is a strong signal and not a verdict.
//
// # What is compared
//
// Not the page. A page that differs on every load — a nonce, a timestamp, an advert —
// would be a finding every hour, and keeping a copy of every page of every link would be
// a second corpus. What is kept is a digest of where the link ended up, whether anything
// was served, and roughly how much: enough to catch a redirect target changing or a dead
// link coming alive, and deaf to ordinary churn. See LinkDigest.
//
// # Where the schedule comes from
//
// The frozen evidence, not the pipeline. Every ml.link_analysis answer a message's rules
// received is already stored beside it, with the URL it was asked about and what came
// back — so the watch list is derived from the record rather than collected by a second
// code path that could disagree with it. A message whose links were never fetched has
// nothing to re-visit, which is correct: there is no "before" to compare against.
type LinkWatcher struct {
	store  *store.Store
	client *render.Client
	tenant string

	// every is how often the worker claims due links.
	every time.Duration

	// firstCheck is how long after delivery the first re-visit happens. Soon enough
	// to catch a swap that happens while the mail is still unread, late enough that
	// it is not just the original fetch again.
	firstCheck time.Duration

	// retryIn is the gap between re-visits, and maxAttempts is where watching stops.
	// Four visits over about a day: after that a link that has not changed is not
	// going to be caught by this, and holding it in the schedule forever would make
	// the table grow with every message ever delivered.
	retryIn     time.Duration
	maxAttempts int

	// perTick bounds one round. Each check is a real page fetch through a browser,
	// so a backlog is worked through over several ticks rather than all at once.
	perTick int
}

// NewLinkWatcher returns a watcher with the defaults described above.
func NewLinkWatcher(s *store.Store, c *render.Client, tenant string) *LinkWatcher {
	return &LinkWatcher{
		store:       s,
		client:      c,
		tenant:      tenant,
		every:       5 * time.Minute,
		firstCheck:  30 * time.Minute,
		retryIn:     6 * time.Hour,
		maxAttempts: 4,
		perTick:     25,
	}
}

// Schedule derives a watch list from one message's frozen evidence.
//
// Called after the message is stored. A failure is logged and dropped: not watching a
// link makes the deployment blind to one evasion, and failing the analysis that just
// completed over it would be worse.
func (w *LinkWatcher) Schedule(ctx context.Context, messageID string, evidence []byte) {
	if w == nil || w.store == nil || len(evidence) == 0 {
		return
	}
	due := time.Now().UTC().Add(w.firstCheck)
	for url, digest := range watchableLinks(evidence) {
		if err := w.store.WatchLink(ctx, w.tenant, url, messageID, digest, due); err != nil {
			log.Printf("link watch: scheduling %s: %v", url, err)
			return // one failure is enough to know the table is not accepting writes
		}
	}
}

// watchableLinks reads the ml.link_analysis answers out of frozen evidence.
//
// Keyed by URL so a link several rules asked about is watched once. The digest is taken
// from what the fetch actually returned, which is the only honest "before": recomputing
// it from the live page later would compare the page to itself.
func watchableLinks(evidence []byte) map[string]string {
	var snap struct {
		Entries map[string]struct {
			Capability string          `json:"capability"`
			Value      json.RawMessage `json:"value"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(evidence, &snap); err != nil {
		return nil
	}

	out := map[string]string{}
	for _, e := range snap.Entries {
		if e.Capability != string(enrich.CapMLLinkAnalysis) || len(e.Value) == 0 {
			continue
		}
		var la struct {
			OriginalURL  *struct{ URL *string } `json:"original_url"`
			EffectiveURL *struct{ URL *string } `json:"effective_url"`
			Retrieved    *bool                  `json:"retrieved"`
			FinalDom     *struct {
				Raw *string `json:"raw"`
			} `json:"final_dom"`
		}
		if err := json.Unmarshal(e.Value, &la); err != nil {
			continue
		}
		original := derefURL(la.OriginalURL)
		if original == "" || !watchableScheme(original) {
			continue
		}
		body := 0
		if la.FinalDom != nil && la.FinalDom.Raw != nil {
			body = len(*la.FinalDom.Raw)
		}
		retrieved := la.Retrieved != nil && *la.Retrieved
		out[original] = LinkDigest(derefURL(la.EffectiveURL), retrieved, body)
	}
	return out
}

func derefURL(u *struct{ URL *string }) string {
	if u == nil || u.URL == nil {
		return ""
	}
	return *u.URL
}

// watchableScheme keeps the schedule to things a browser can be pointed at again.
// mailto:, tel: and data: links are in real mail and have no page to re-visit.
func watchableScheme(u string) bool {
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// Run works the schedule until the context ends.
func (w *LinkWatcher) Run(ctx context.Context) {
	if w == nil || w.store == nil || w.client == nil {
		return
	}
	tick := time.NewTicker(w.every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if n, err := w.Tick(ctx); err != nil {
				log.Printf("link watch: %v", err)
			} else if n > 0 {
				log.Printf("link watch: %d link(s) in delivered mail now serve "+
					"something different", n)
			}
		}
	}
}

// Tick claims the links that are due, re-visits them and files what changed. It returns
// how many findings it filed.
func (w *LinkWatcher) Tick(ctx context.Context) (int, error) {
	due, err := w.store.DueLinks(ctx, w.tenant, w.perTick, w.retryIn)
	if err != nil {
		return 0, err
	}
	filed := 0
	for _, link := range due {
		select {
		case <-ctx.Done():
			return filed, ctx.Err()
		default:
		}

		// Attempts was already incremented by the claim, so this is the last visit.
		last := link.Attempts >= w.maxAttempts

		snap, err := w.client.Revisit(ctx, link.URL)
		if err != nil {
			// The renderer being down is not a finding about the link. The claim
			// already pushed it forward, so it comes round again.
			if last {
				_ = w.store.StopWatching(ctx, w.tenant, link.URL, link.MessageID)
			}
			continue
		}

		now := LinkDigest(snap.EffectiveURL, snap.Retrieved, snap.BodyLen)
		if now == link.Digest {
			if last {
				_ = w.store.StopWatching(ctx, w.tenant, link.URL, link.MessageID)
			}
			continue
		}

		fresh, err := w.store.RecordFinding(ctx, w.tenant, store.RetroFinding{
			MessageID: link.MessageID,
			Kind:      store.FindingLink,
			Source:    link.URL,
			Detail:    changeDetail(snap),
		})
		if err != nil {
			log.Printf("link watch: filing %s: %v", link.URL, err)
			continue
		}
		if fresh {
			filed++
		}
		// Stop after a change. The question was "did this link change after
		// delivery", it has been answered, and watching it further would file the
		// same finding against a different digest every six hours.
		_ = w.store.StopWatching(ctx, w.tenant, link.URL, link.MessageID)
	}
	return filed, nil
}

// changeDetail says what the link does now.
//
// Deliberately makes no claim about which field moved. The comparison is a digest, so
// all it knows is that something is different — asserting "it now redirects elsewhere"
// when the change was actually in what came back would be a confident statement the
// evidence does not support, in a finding a person is about to act on.
func changeDetail(s *render.LinkSnapshot) string {
	var b strings.Builder
	b.WriteString("what this link serves has changed since the message was analysed. ")
	if !s.Retrieved {
		b.WriteString("It does not respond now")
		if s.StatusCode > 0 {
			fmt.Fprintf(&b, " (HTTP %d)", s.StatusCode)
		}
		if s.Error != "" {
			b.WriteString(": " + s.Error)
		}
		return b.String()
	}
	b.WriteString("It now resolves to " + s.EffectiveURL)
	if s.StatusCode > 0 {
		fmt.Fprintf(&b, " (HTTP %d)", s.StatusCode)
	}
	fmt.Fprintf(&b, " and returns %d bytes", s.BodyLen)
	return b.String()
}
