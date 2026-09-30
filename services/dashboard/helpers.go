// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/base64"
	"net/url"
)

// Shaping that the console's API does on the way out.
//
// What survived the move from server-rendered pages: these are decisions about what
// the data means, not about how it looks, so they stayed on this side rather than
// being reimplemented in the browser.

// triageQueues are the tabs, in the order an analyst works them.
var triageQueues = []struct{ Key, Label, Hint string }{
	{"needs_remediation", "Needs remediation", "Confirmed bad and still in a mailbox"},
	{"unreviewed", "Unreviewed", "A rule fired and nobody has looked"},
	{"remediated", "Remediated", "Confirmed and dealt with"},
	{"benign", "Benign", "Reviewed and judged a false positive"},
	{"ignored", "Ignored", "Noisy but harmless — graymail and the like"},
	{"all", "Everything", "Every message, whatever its verdict"},
}

// triageStateOf defaults an unreviewed message.
//
// Absence of a row means nobody has looked, which is unreviewed rather than unknown.
func triageStateOf(m Message) string {
	if m.TriageState == "" {
		return "unreviewed"
	}
	return m.TriageState
}

// verdictOf is the one-word answer the page leads with.
//
// Derived from the detections rather than stored, so it cannot disagree with the
// list of rules printed directly underneath it — which is the sort of inconsistency
// that makes people stop trusting the banner.
func verdictOf(d *MessageDetail) string {
	switch {
	case len(d.Detections) > 0:
		return "malicious"
	case len(d.Indeterminate) > 0:
		return "indeterminate"
	default:
		return "clean"
	}
}

// screenshotSrcFor is where the Rendered tab gets its picture.
//
// A stored message has an endpoint to fetch one from. A transient analysis has no
// row to fetch from afterwards, so it carries the image inline — and that is the
// case worth being careful about: the bytes originate in an untrusted message, and
// an untrusted source can carry a script-bearing SVG. The escape hatch is earned
// rather than asserted: the payload is decoded and re-encoded here, which guarantees
// the string is base64 alphabet and nothing else, and the media type is this
// function's rather than anything the engine claimed.
func screenshotSrcFor(id string, d *MessageDetail) string {
	if d == nil || !d.Renderable {
		return ""
	}
	if d.Screenshot != "" {
		png, err := base64.StdEncoding.DecodeString(d.Screenshot)
		if err != nil || len(png) == 0 {
			return ""
		}
		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	if id == "" {
		return ""
	}
	return "/messages/" + url.PathEscape(id) + "/screenshot"
}

// summarise lifts the handful of MDM fields the header shows out of the whole model,
// so the console does not have to know the shape of the data model to print a sender.
func summarise(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	str := func(path ...string) string {
		cur := any(m)
		for _, p := range path {
			mm, ok := cur.(map[string]any)
			if !ok {
				return ""
			}
			cur = mm[p]
		}
		s, _ := cur.(string)
		return s
	}
	out := map[string]any{
		"Sender":      str("sender", "email", "email"),
		"DisplayName": str("sender", "display_name"),
		"Domain":      str("sender", "email", "domain", "domain"),
		"RootDomain":  str("sender", "email", "domain", "root_domain"),
		"Subject":     str("subject", "subject"),
	}
	if t, ok := m["type"].(map[string]any); ok {
		for _, k := range []string{"inbound", "outbound", "internal"} {
			if b, _ := t[k].(bool); b {
				out["Direction"] = k
			}
		}
	}
	if body, ok := m["body"].(map[string]any); ok {
		if ct, ok := body["current_thread"].(map[string]any); ok {
			if txt, ok := ct["text"].(string); ok {
				out["Preview"] = truncate(txt, 600)
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
