// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lazaretemail/lazaret/actions"
)

// Telling something else that a rule fired.
//
// A webhook rather than an email, because the things that want to know — a chat
// channel, a ticket queue, a SIEM — all speak HTTP, and an email about email
// security has a way of arriving in the mailbox nobody is watching.
//
// Deliberately fire-and-forget on a short timeout. A slow endpoint must not hold up
// the delivery of a message, and an endpoint that is down is not a reason to stop
// analysing mail; the detection is already recorded here either way.

// notifyTimeout bounds one post. Short: this is on the delivery path.
const notifyTimeout = 5 * time.Second

// notify posts a summary of the detection to a configured webhook.
func (p *Pipeline) notify(ctx context.Context, tenant string, inst actions.Instance, a *Analysis) {
	url := inst.Config["url"]
	if url == "" {
		return
	}

	var matched []string
	for _, m := range a.Matched {
		matched = append(matched, m.Name)
	}
	body, err := json.Marshal(map[string]any{
		"tenant":     tenant,
		"message_id": a.MessageID,
		"verdict":    a.Verdict,
		"rules":      matched,
		"action":     inst.Label,
		"at":         time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}

	// Detached from the analysis context and run in the background: the message
	// has a verdict and should be delivered to the caller now, not after somebody
	// else's endpoint has finished thinking.
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("actions: %q: posting to the webhook: %v", inst.Label, err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			log.Printf("actions: %q: the webhook answered %s", inst.Label, resp.Status)
		}
	}()
}
