// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// A small CDP client, for driving a browser that is not Chromium.
//
// # Why not chromedp, which this service already depends on
//
// chromedp is the right tool against Chromium and the wrong one against anything else.
// It keeps a model of the browser's targets and sessions, maintained from the events
// Chromium emits, and an engine that emits them slightly differently desynchronises it.
// Measured against obscura over ten links from one real email: five never completed and
// each cost the full render timeout, with the log filling up with
//
//	ERROR: executor for "page-1-session" doesn't exist
//
// — 155 seconds against Chromium's 12. On the five that did complete the DOM was
// byte-identical to Chromium's and obscura was the faster of the two, so the engine was
// never the problem. The client was.
//
// What the link path actually needs is nine messages in a fixed order, and none of them
// requires a model of anything:
//
//	Target.createBrowserContext      isolation, so one hostile page cannot see the next
//	Target.createTarget              a page inside it
//	Target.attachToTarget            flattened, so replies carry a sessionId
//	Page.enable
//	Page.navigate
//	Runtime.evaluate outerHTML.length      polled until the document stops growing
//	Runtime.evaluate outerHTML             the one answer this path wants
//	Target.closeTarget
//	Target.disposeBrowserContext
//
// Written out, that is this file. It speaks to the connection and holds no opinion about
// what the browser has open, which is exactly why it does not desynchronise.
//
// # It is deliberately not a general CDP library
//
// It implements what the link path uses and nothing else. A general one would be a large
// surface to maintain for a service that asks a browser one question.
type cdpClient struct {
	url    string
	header http.Header

	// dialTimeout bounds establishing the connection, separately from a call.
	dialTimeout time.Duration

	mu      sync.Mutex
	conn    net.Conn
	pending map[int64]chan cdpReply
	// generation increments on every reconnect, so a reply arriving from a
	// connection that has since been replaced is discarded rather than delivered.
	generation uint64

	nextID atomic.Int64

	// writeMu serialises frame writes. The wsutil writer is not safe for concurrent
	// use and this client is called from every link visit at once.
	writeMu sync.Mutex
}

// cdpReply is one response, already split into its halves.
type cdpReply struct {
	result json.RawMessage
	err    error
}

// newCDPClient returns a client for a websocket endpoint.
func newCDPClient(wsURL string, header http.Header) *cdpClient {
	if header == nil {
		header = http.Header{}
	}
	return &cdpClient{
		url:         wsURL,
		header:      header,
		dialTimeout: 10 * time.Second,
		pending:     map[int64]chan cdpReply{},
	}
}

// ensure returns a live connection, dialling if there is not one.
func (c *cdpClient) ensure(ctx context.Context) (net.Conn, uint64, error) {
	c.mu.Lock()
	if c.conn != nil {
		conn, gen := c.conn, c.generation
		c.mu.Unlock()
		return conn, gen, nil
	}
	c.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()

	dialer := ws.Dialer{Header: ws.HandshakeHeaderHTTP(c.header)}
	conn, _, _, err := dialer.Dial(dialCtx, c.url)
	if err != nil {
		return nil, 0, fmt.Errorf("dialling the link browser at %s: %w", c.url, err)
	}

	c.mu.Lock()
	// Another goroutine may have dialled while this one was waiting.
	if c.conn != nil {
		existing, gen := c.conn, c.generation
		c.mu.Unlock()
		_ = conn.Close()
		return existing, gen, nil
	}
	c.generation++
	c.conn = conn
	gen := c.generation
	c.mu.Unlock()

	go c.read(conn, gen)
	return conn, gen, nil
}

// read pumps replies until the connection dies, then fails everything waiting on it.
func (c *cdpClient) read(conn net.Conn, gen uint64) {
	for {
		data, err := wsutil.ReadServerText(conn)
		if err != nil {
			c.dropConn(gen, fmt.Errorf("link browser connection lost: %w", err))
			return
		}

		var msg struct {
			ID     int64           `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(data, &msg); err != nil || msg.ID == 0 {
			// An event, or something unparsable. Nothing here subscribes to events:
			// the sequence is driven by replies, and readiness is polled rather
			// than awaited, so an engine that does not emit an event this client
			// expected cannot stall it.
			continue
		}

		reply := cdpReply{result: msg.Result}
		if msg.Error != nil {
			reply.err = fmt.Errorf("%s (CDP %d)", msg.Error.Message, msg.Error.Code)
		}

		c.mu.Lock()
		ch, ok := c.pending[msg.ID]
		delete(c.pending, msg.ID)
		c.mu.Unlock()
		if ok {
			ch <- reply
		}
	}
}

// dropConn closes a dead connection and releases everyone waiting on it.
func (c *cdpClient) dropConn(gen uint64, cause error) {
	c.mu.Lock()
	if c.generation != gen {
		// Already replaced by a later dial.
		c.mu.Unlock()
		return
	}
	conn := c.conn
	c.conn = nil
	waiting := c.pending
	c.pending = map[int64]chan cdpReply{}
	c.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	// Every in-flight call fails rather than waiting for a deadline that is
	// measured in tens of seconds. A visit that cannot reach the browser should
	// report so now; the served HTML is already in hand from the HTTP client.
	for _, ch := range waiting {
		ch <- cdpReply{err: cause}
	}
}

// call sends one command and waits for its reply.
//
// sessionID may be empty, which addresses the browser itself rather than a page.
func (c *cdpClient) call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	conn, gen, err := c.ensure(ctx)
	if err != nil {
		return nil, err
	}

	id := c.nextID.Add(1)
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if sessionID != "" {
		msg["sessionId"] = sessionID
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	ch := make(chan cdpReply, 1)
	c.mu.Lock()
	if c.generation != gen {
		// Reconnected between ensure and here; the caller retries at the next visit.
		c.mu.Unlock()
		return nil, fmt.Errorf("link browser reconnected mid-call")
	}
	c.pending[id] = ch
	c.mu.Unlock()

	c.writeMu.Lock()
	err = wsutil.WriteClientText(conn, body)
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		c.dropConn(gen, err)
		return nil, fmt.Errorf("sending %s: %w", method, err)
	}

	select {
	case reply := <-ch:
		if reply.err != nil {
			return nil, fmt.Errorf("%s: %w", method, reply.err)
		}
		return reply.result, nil
	case <-ctx.Done():
		// Stop the reader delivering into a channel nobody is reading.
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Close shuts the connection.
func (c *cdpClient) Close() {
	c.mu.Lock()
	gen := c.generation
	c.mu.Unlock()
	c.dropConn(gen, fmt.Errorf("link browser client closed"))
}

// DOM navigates to a URL in an isolated context and returns the document after script
// has run.
//
// The clean-up is unconditional. A target or a browser context left behind is a page
// still holding memory in a process that is meant to be the cheap half of this service,
// and a hostile page is exactly the one that will fail partway through.
func (c *cdpClient) DOM(ctx context.Context, url string) (string, error) {
	var ctxID string
	if res, err := c.call(ctx, "", "Target.createBrowserContext", map[string]any{}); err == nil {
		var out struct {
			BrowserContextID string `json:"browserContextId"`
		}
		if json.Unmarshal(res, &out) == nil {
			ctxID = out.BrowserContextID
		}
	}
	// An engine without browser contexts is not refused, but it is not silently
	// treated as isolated either — see remoteBrowser, which checks this at start-up
	// and says so once.
	if ctxID != "" {
		defer c.cleanup("Target.disposeBrowserContext", map[string]any{"browserContextId": ctxID})
	}

	create := map[string]any{"url": "about:blank"}
	if ctxID != "" {
		create["browserContextId"] = ctxID
	}
	res, err := c.call(ctx, "", "Target.createTarget", create)
	if err != nil {
		return "", err
	}
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(res, &target); err != nil || target.TargetID == "" {
		return "", fmt.Errorf("the link browser did not return a target id")
	}
	defer c.cleanup("Target.closeTarget", map[string]any{"targetId": target.TargetID})

	// Flattened, so replies and events carry a sessionId on the one connection
	// rather than needing a second socket per page.
	res, err = c.call(ctx, "", "Target.attachToTarget",
		map[string]any{"targetId": target.TargetID, "flatten": true})
	if err != nil {
		return "", err
	}
	var attach struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(res, &attach); err != nil || attach.SessionID == "" {
		return "", fmt.Errorf("the link browser did not return a session id")
	}
	sid := attach.SessionID

	if _, err := c.call(ctx, sid, "Page.enable", map[string]any{}); err != nil {
		return "", err
	}
	if _, err := c.call(ctx, sid, "Page.navigate", map[string]any{"url": url}); err != nil {
		return "", err
	}

	// Settled by watching the document, not by waiting for an event.
	//
	// Waiting for Page.loadEventFired is what a CDP client normally does and is what
	// cost 30 seconds a link in the first attempt: an engine that does not fire it
	// leaves the caller waiting for the whole timeout. Polling readyState instead
	// fixed the hangs and was still slow, because "complete" is not what this path
	// wants — one real link took obscura 32 seconds to reach it against Chromium's
	// 0.9, and the interesting content was there long before.
	//
	// What the caller actually wants is "the DOM has stopped changing", so that is
	// what is asked. The length is evaluated rather than the document, so a page that
	// is still growing is not serialised across the wire on every poll.
	stable, last := 0, -1
	deadline := time.Now().Add(domSettleWait)
	for time.Now().Before(deadline) {
		size, err := c.evalInt(ctx, sid, "document.documentElement.outerHTML.length")
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			// Mid-navigation, so there is no document to measure yet.
			size = -1
		}
		if size >= 0 && size == last {
			stable++
			if stable >= domStablePolls {
				break
			}
		} else {
			stable = 0
		}
		last = size

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(domSettlePoll):
		}
	}

	return c.evalString(ctx, sid, "document.documentElement.outerHTML")
}

// cleanup closes a target or context without making the caller wait for it.
//
// Detached on purpose. These run after a visit, including after one that used its whole
// budget, and doing them inline on a browser that is already struggling added both
// timeouts to the caller's latency — which is how a ten-second fetch budget produced a
// twenty-second request. The page still has to be released or the engine accumulates
// them, so it is done, just not on the path anyone is waiting on.
func (c *cdpClient) cleanup(method string, params map[string]any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := c.call(ctx, "", method, params); err != nil {
			// Worth a line: an engine that will not release pages runs out of
			// memory eventually, and the first sign of it is here.
			log.Printf("lazaret-render: link browser %s: %v", method, err)
		}
	}()
}

// How long to wait for a document to stop changing, how often to look, and how many
// unchanged looks count as settled.
//
// Three polls of 150ms means a page is taken 450ms after it last grew, which is enough
// for script that builds a form in one go and short enough that ten links do not add up
// to a minute. The ceiling is well inside the render timeout, so a page that never stops
// changing — an advert carousel, a live feed — yields what it has rather than costing
// the whole budget.
const (
	domSettleWait  = 6 * time.Second
	domSettlePoll  = 150 * time.Millisecond
	domStablePolls = 3
)

// evalInt evaluates an expression and returns its numeric value.
func (c *cdpClient) evalInt(ctx context.Context, sessionID, expr string) (int, error) {
	res, err := c.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression": expr, "returnByValue": true,
	})
	if err != nil {
		return 0, err
	}
	var out struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res, &out); err != nil || len(out.Result.Value) == 0 {
		return 0, fmt.Errorf("no value")
	}
	var n int
	if err := json.Unmarshal(out.Result.Value, &n); err != nil {
		return 0, err
	}
	return n, nil
}

// evalString evaluates an expression and returns its string value.
func (c *cdpClient) evalString(ctx context.Context, sessionID, expr string) (string, error) {
	res, err := c.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
		// A page can define a getter that throws on anything it does not like; a
		// thrown exception is reported rather than hanging the evaluation.
		"awaitPromise": false,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return "", err
	}
	if out.ExceptionDetails != nil {
		return "", fmt.Errorf("evaluating in the page: %s", out.ExceptionDetails.Text)
	}
	if len(out.Result.Value) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(out.Result.Value, &s); err != nil {
		// Not a string — a page that has redefined outerHTML, say. Not an error
		// worth failing the visit over; the served HTML is still the result.
		return "", nil
	}
	return s, nil
}
