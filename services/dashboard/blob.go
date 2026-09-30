// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Binary message resources, proxied from the engine.
//
// Proxied rather than linked, because the browser has a session cookie and the engine
// takes a bearer token, and handing the browser a token so it could fetch directly
// would put a credential in a URL or in JavaScript's reach. The dashboard already
// holds the token for this session; it fetches, and streams the result back.

// messageScreenshot serves the picture of a message body.
//
// This is what the "Rendered" tab shows, and the reason it can show anything at all.
// The message's own HTML is attacker-authored: its remote images are read receipts for
// the sender, its CSS escapes whatever box a template puts it in, and its scripts would
// run with this origin and this session. Rendered in a sandboxed browser on an internal
// network and served as a PNG, none of that reaches the analyst — they see exactly what
// the recipient saw, and the message never executes anywhere it could do harm.
func (a *App) messageScreenshot(w http.ResponseWriter, r *http.Request) {
	a.proxyBlob(w, r, "/screenshot", "image/png", "")
}

// messageRaw serves the original bytes of a held message as a download.
func (a *App) messageRaw(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.proxyBlob(w, r, "/raw", "message/rfc822",
		`attachment; filename="`+safeDownloadName(id)+`.eml"`)
}

func (a *App) proxyBlob(w http.ResponseWriter, r *http.Request, suffix, contentType, disposition string) {
	id := r.PathValue("id")
	path := "/v0/messages/" + url.PathEscape(id) + suffix
	if q := r.URL.RawQuery; q != "" {
		path += "?" + q
	}

	resp, err := a.engine.Blob(r.Context(), path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 204 means the engine has nothing to show and said so deliberately — a message
	// with no renderable body. Passed through, so the page can say "nothing to
	// render" rather than showing a broken image.
	if resp.StatusCode == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// The content type is this handler's, never the upstream's. Reflecting a type
	// from a response whose body derives from attacker-controlled bytes is how a
	// proxy gets talked into serving text/html from its own origin.
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if disposition != "" {
		w.Header().Set("Content-Disposition", disposition)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	w.Header().Set("Cache-Control", "private, max-age=300")
	io.Copy(w, resp.Body)
}

// safeDownloadName keeps a message id fit for a filename. Message-IDs are
// attacker-chosen and routinely contain characters that mean something to a shell or
// to a Content-Disposition parser.
func safeDownloadName(id string) string {
	keep := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}
	out := strings.Map(keep, id)
	if len(out) > 80 {
		out = out[:80]
	}
	if out == "" {
		return "message"
	}
	return out
}
