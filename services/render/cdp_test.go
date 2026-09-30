// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// fakeCDP is a CDP server that answers the sequence the link path uses.
//
// Deliberately answers out of order and drags its feet on clean-up, because those are
// the two things that broke against a real engine: replies arriving interleaved across
// concurrent visits, and Target.closeTarget taking longer than the visit had left.
type fakeCDP struct {
	srv *httptest.Server

	mu       sync.Mutex
	seen     []string
	dom      string
	slowKill time.Duration
	auth     string
}

func newFakeCDP(t *testing.T, dom string) *fakeCDP {
	t.Helper()
	f := &fakeCDP{dom: dom}
	mux := http.NewServeMux()
	mux.HandleFunc("/json/version", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.auth = r.Header.Get("Authorization")
		f.mu.Unlock()
		ws := "ws" + strings.TrimPrefix(f.srv.URL, "http") + "/devtools/browser/fake"
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Browser": "Fake/1.0", "webSocketDebuggerUrl": ws,
		})
	})
	mux.HandleFunc("/devtools/browser/fake", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.auth = r.Header.Get("Authorization")
		f.mu.Unlock()
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			data, err := wsutil.ReadClientText(conn)
			if err != nil {
				return
			}
			var msg struct {
				ID     int64  `json:"id"`
				Method string `json:"method"`
				Params struct {
					Expression string `json:"expression"`
				} `json:"params"`
			}
			if json.Unmarshal(data, &msg) != nil {
				continue
			}
			f.mu.Lock()
			f.seen = append(f.seen, msg.Method)
			slow := f.slowKill
			body := f.dom
			f.mu.Unlock()

			var result string
			switch msg.Method {
			case "Target.createBrowserContext":
				result = `{"browserContextId":"ctx-1"}`
			case "Target.createTarget":
				result = `{"targetId":"page-1"}`
			case "Target.attachToTarget":
				result = `{"sessionId":"page-1-session-1"}`
			case "Runtime.evaluate":
				if strings.Contains(msg.Params.Expression, ".length") {
					v, _ := json.Marshal(len(body))
					result = `{"result":{"value":` + string(v) + `}}`
				} else {
					v, _ := json.Marshal(body)
					result = `{"result":{"value":` + string(v) + `}}`
				}
			case "Target.closeTarget", "Target.disposeBrowserContext":
				if slow > 0 {
					// Answer late, on a goroutine, so the client is free to carry
					// on if it is not waiting.
					go func(id int64) {
						time.Sleep(slow)
						f.reply(conn, id, `{}`)
					}(msg.ID)
					continue
				}
				result = `{}`
			default:
				result = `{}`
			}
			f.reply(conn, msg.ID, result)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCDP) reply(conn interface{ Write([]byte) (int, error) }, id int64, result string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = wsutil.WriteServerText(conn, []byte(
		`{"id":`+jsonInt(id)+`,"result":`+result+`}`))
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (f *fakeCDP) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.seen))
	copy(out, f.seen)
	return out
}

// The client gets the document, in an isolated context, and releases what it opened.
//
// The browser context is the isolation boundary: without it a credential page's cookies
// and storage are visible to the next link visited, which for a service whose whole job
// is visiting hostile pages is not a detail.
func TestTheCDPClientFetchesADOMInAnIsolatedContext(t *testing.T) {
	f := newFakeCDP(t, "<html><body>built by script</body></html>")
	c := newCDPClient(mustWS(t, f.srv.URL), nil)
	defer c.Close()

	dom, err := c.DOM(t.Context(), "https://example.test/")
	if err != nil {
		t.Fatalf("fetching: %v", err)
	}
	if !strings.Contains(dom, "built by script") {
		t.Errorf("got %q", dom)
	}

	// Clean-up is detached, so give it a moment before looking.
	time.Sleep(300 * time.Millisecond)
	var created, closed bool
	for _, m := range f.methods() {
		switch m {
		case "Target.createBrowserContext":
			created = true
		case "Target.disposeBrowserContext":
			closed = true
		}
	}
	if !created {
		t.Error("no browser context was created, so one page's cookies are visible to the next")
	}
	if !closed {
		t.Error("the browser context was never disposed, so the engine accumulates them")
	}
}

// Slow clean-up does not slow the visit down.
//
// This was a real bug in this client and it cost ten seconds a link: closeTarget and
// disposeBrowserContext ran inline with five-second budgets each, after a visit that had
// already used its own — so a ten-second fetch budget produced a twenty-second request.
func TestSlowCleanupDoesNotDelayTheVisit(t *testing.T) {
	f := newFakeCDP(t, "<html>ok</html>")
	f.mu.Lock()
	f.slowKill = 3 * time.Second
	f.mu.Unlock()

	c := newCDPClient(mustWS(t, f.srv.URL), nil)
	defer c.Close()

	start := time.Now()
	if _, err := c.DOM(t.Context(), "https://example.test/"); err != nil {
		t.Fatalf("fetching: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the visit took %v, so it waited for clean-up", elapsed)
	}
}

// Replies are matched to their calls, not to their order of arrival.
//
// Every link in a message is visited at once over one connection. If replies were paired
// with calls positionally, one slow page would hand its DOM to a different link's visit
// — which is worse than a failure, because the result would look plausible.
func TestConcurrentVisitsDoNotCrossReplies(t *testing.T) {
	f := newFakeCDP(t, "<html>shared</html>")
	c := newCDPClient(mustWS(t, f.srv.URL), nil)
	defer c.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dom, err := c.DOM(t.Context(), "https://example.test/")
			if err != nil {
				errs <- err
				return
			}
			if !strings.Contains(dom, "shared") {
				errs <- errUnexpected(dom)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent visit: %v", err)
	}
}

type errUnexpected string

func (e errUnexpected) Error() string { return "unexpected dom: " + string(e) }

// The bearer token is presented on both the discovery request and the websocket.
//
// Obscura refuses a non-loopback bind without one. Sending it on discovery and not on
// the socket would work at start-up and fail on the first link, which is the worst place
// to find out.
func TestTheTokenIsSentOnDiscoveryAndOnTheSocket(t *testing.T) {
	f := newFakeCDP(t, "<html>ok</html>")
	header := http.Header{}
	header.Set("Authorization", "Bearer sekrit")

	wsURL, err := resolveCDPEndpoint(f.srv.URL, header)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	f.mu.Lock()
	onDiscovery := f.auth
	f.auth = ""
	f.mu.Unlock()
	if onDiscovery != "Bearer sekrit" {
		t.Errorf("discovery sent %q", onDiscovery)
	}

	c := newCDPClient(wsURL, header)
	defer c.Close()
	if _, err := c.DOM(t.Context(), "https://example.test/"); err != nil {
		t.Fatalf("fetching: %v", err)
	}
	f.mu.Lock()
	onSocket := f.auth
	f.mu.Unlock()
	if onSocket != "Bearer sekrit" {
		t.Errorf("the websocket handshake sent %q", onSocket)
	}
}

func mustWS(t *testing.T, base string) string {
	t.Helper()
	u, err := resolveCDPEndpoint(base, nil)
	if err != nil {
		t.Fatalf("resolving %s: %v", base, err)
	}
	return u
}
