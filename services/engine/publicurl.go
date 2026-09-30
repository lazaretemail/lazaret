// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"net/url"
	"strings"
)

// Where this deployment is reachable from the internet.
//
// One setting, and everything that needs a public URL derives its own from it. The
// alternative — asking an administrator to paste a full callback URL into a form —
// makes them responsible for a path this code already knows, and gets it wrong in
// ways that are hard to see: a trailing slash, http where the proxy wants https, a
// path that was right before the endpoint moved.
//
// It is an environment variable rather than a settings page because it is a fact
// about the deployment's network, decided when the reverse proxy was configured,
// not a policy choice somebody revisits.

// graphNotifyPath is the path the mail connector listens on. Fixed, not
// configurable: it is an implementation detail shared between two of our own
// services, and making it settable would only create a way for them to disagree.
const graphNotifyPath = "/graph/notify"

// publicBase normalises the configured base URL, or returns empty when there is
// none.
//
// Empty is a perfectly good answer and the common one: a deployment that is not
// reachable from the internet polls Microsoft instead, which needs no inbound path
// at all. What must not happen is a half-formed URL being handed to Microsoft,
// because a subscription created against one fails silently — notifications simply
// stop arriving, and the mailbox looks like it has gone quiet.
func publicBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	// A bare hostname is what people type. Assume https rather than rejecting it:
	// the alternative scheme is one Microsoft will not accept anyway.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("the public URL %q is not a URL: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("the public URL %q has no host", raw)
	}
	if u.Scheme != "https" {
		// Microsoft refuses a plaintext notification URL, and finding that out
		// from a failed subscription months later is worse than finding it out
		// at startup.
		return "", fmt.Errorf("the public URL must be https; %q is %s", raw, u.Scheme)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

// graphNotifyURL is where Microsoft should send change notifications, derived.
func graphNotifyURL(base string) string {
	if base == "" {
		return ""
	}
	return base + graphNotifyPath
}
