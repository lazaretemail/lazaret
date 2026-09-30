// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// The console is a compiled single-page app, embedded in this binary.
//
// Keeping it inside the Go binary rather than behind a Node server is what lets the
// runtime image stay distroless with no npm in it: the toolchain exists only in the
// build stage. Deployment is still one static binary and one container.

// spa serves the built assets, falling back to index.html so that a deep link like
// /messages/<id> reaches the router instead of 404ing.
type spa struct {
	files fs.FS
	index []byte
}

func newSPA(dist fs.FS) (*spa, error) {
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		// A binary built without running the front-end build would otherwise serve a
		// blank page and look like a routing bug. Say which it is, at start-up.
		return nil, errors.New("console assets are missing: run `npm ci && npm run build` in services/dashboard/web " +
			"(the Docker build does this automatically)")
	}
	return &spa{files: dist, index: index}, nil
}

func (s *spa) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")

	// Anything under assets/ is content-hashed by the build, so a given URL's bytes
	// never change and it can be cached hard. index.html is the opposite: it names
	// the current hashes, so caching it is how a browser ends up asking for a bundle
	// that no longer exists after a deploy.
	if name != "" && name != "index.html" {
		if f, err := s.files.Open(name); err == nil {
			defer f.Close()
			if st, err := f.Stat(); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				w.Header().Set("X-Content-Type-Options", "nosniff")
				http.ServeContent(w, r, name, st.ModTime(), f.(io.ReadSeeker))
				return
			}
		}
	}

	s.serveIndex(w, r, http.StatusOK)
}

// serveIndex hands back the app shell with the console's security headers.
func (s *spa) serveIndex(w http.ResponseWriter, _ *http.Request, code int) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")

	// A fresh nonce per response, for the one thing that legitimately needs to
	// build a stylesheet at runtime: the MQL editor. The alternative was
	// style-src 'unsafe-inline', which would also permit every style an injected
	// script could set — on a page that renders attacker-authored subject lines.
	// Safe to vary per response because this document is served no-store.
	nonce, err := newNonce()
	if err != nil {
		http.Error(w, "could not generate a nonce", http.StatusInternalServerError)
		return
	}

	// A security console renders attacker-authored subject lines and sender names, so
	// it should not be able to load anything at all from anywhere else. The bundle is
	// same-origin, the styles are extracted to a same-origin stylesheet, and no script
	// is inlined — which is why this needs neither unsafe-inline nor unsafe-eval.
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self' 'nonce-"+nonce+"'; "+
			"img-src 'self' data: blob:; font-src 'self'; form-action 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'; connect-src 'self'; frame-src 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	w.Write(bytes.ReplaceAll(s.index, noncePlaceholder, []byte(nonce)))
}

// noncePlaceholder is what index.html ships with and what serveIndex substitutes.
var noncePlaceholder = []byte("__CSP_NONCE__")

func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b[:]), nil
}

// jsonAPINotFound keeps an unmatched /api path from being answered with the app
// shell, which would otherwise reach fetch() as HTML and surface as a JSON parse
// error a long way from the cause.
func jsonAPINotFound(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such endpoint"})
}
