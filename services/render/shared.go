// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// A link verdict store shared by every process in the deployment.
//
// The cache beside this one is in this process and lasts fifteen minutes. That removes
// the duplicate work inside a campaign's burst and nothing else: restart the service
// and it is empty, run two of them and each pays separately, and a URL seen on Monday
// is fetched again on Tuesday. Link analysis is around thirty-eight fetches a message
// and the dominant cost of an analysis, so the repeats are worth having.
//
// This makes the answer last across restarts and across processes. A URL a campaign
// sent to fifty mailboxes is visited once by the deployment rather than once per
// process per quarter of an hour.
//
// # Why a hand-written client
//
// Garnet speaks RESP, and the obvious move is a Redis client library. Two commands are
// needed — GET and SETEX — and RESP is a protocol somebody can read in one sitting: a
// type byte, a length, a payload. A few hundred lines here against a large dependency
// and its transitive graph, in a service that already carries a headless browser, is
// the better trade. It also sidesteps pulling something named for the database this
// project deliberately does not use.
//
// # It must never be the reason a fetch fails
//
// A cache that can break the thing it accelerates is worse than no cache. Every
// operation here has a short deadline and every failure is a miss: Garnet being down
// makes analysis slower and never makes it wrong, and the service does not wait on a
// dead socket while a message's budget runs out.
type sharedStore struct {
	addr string
	ttl  time.Duration

	// maxEntry caps what is worth sending. A fetched page carries its DOM, and
	// pushing a ten megabyte page across the network to save fetching it again is
	// not a saving.
	maxEntry int

	mu   sync.Mutex
	pool []*conn

	// down is when the store was last found unreachable. While it is recent,
	// operations return immediately rather than dialling: a deployment with no
	// Garnet should not pay a connection timeout on every link.
	down time.Time

	stats sharedStats
}

type sharedStats struct {
	mu       sync.Mutex
	Hits     int64
	Misses   int64
	Stores   int64
	Failures int64
}

// backoffAfterFailure is how long the store stays out of the path once it has failed.
// Long enough that a dead Garnet costs one dial per minute rather than one per link;
// short enough that a restarted one is picked up without restarting this service.
const backoffAfterFailure = time.Minute

// opTimeout bounds one command. A cache lookup that takes longer than this has already
// lost to simply fetching the page.
const opTimeout = 250 * time.Millisecond

type conn struct {
	c  net.Conn
	br *bufio.Reader
}

func newSharedStore(addr string, ttl time.Duration, maxEntry int) *sharedStore {
	return &sharedStore{addr: addr, ttl: ttl, maxEntry: maxEntry}
}

// Get returns a stored result, or nil.
func (s *sharedStore) Get(ctx context.Context, key string) *FetchResult {
	if s == nil || s.addr == "" || s.backingOff() {
		return nil
	}
	raw, err := s.do(ctx, "GET", key)
	if err != nil {
		s.failed(err)
		return nil
	}
	if raw == nil {
		s.count(&s.stats.Misses)
		return nil
	}
	var res FetchResult
	if err := json.Unmarshal(raw, &res); err != nil {
		// A value this process cannot read is a miss, not an error: the format may
		// have changed under a rolling upgrade, and the right answer is to fetch.
		s.count(&s.stats.Misses)
		return nil
	}
	s.count(&s.stats.Hits)
	return &res
}

// Put stores a result, best effort.
func (s *sharedStore) Put(ctx context.Context, key string, res *FetchResult) {
	if s == nil || s.addr == "" || res == nil || s.backingOff() {
		return
	}
	body, err := json.Marshal(res)
	if err != nil || len(body) > s.maxEntry {
		return
	}
	if _, err := s.do(ctx, "SETEX", key, strconv.Itoa(int(s.ttl.Seconds())), string(body)); err != nil {
		s.failed(err)
		return
	}
	s.count(&s.stats.Stores)
}

// Stats reports hits, misses, stores and failures.
func (s *sharedStore) Stats() (hits, misses, stores, failures int64) {
	if s == nil {
		return 0, 0, 0, 0
	}
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()
	return s.stats.Hits, s.stats.Misses, s.stats.Stores, s.stats.Failures
}

func (s *sharedStore) count(p *int64) {
	s.stats.mu.Lock()
	*p++
	s.stats.mu.Unlock()
}

func (s *sharedStore) backingOff() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.down.IsZero() && time.Since(s.down) < backoffAfterFailure
}

func (s *sharedStore) failed(err error) {
	s.count(&s.stats.Failures)
	s.mu.Lock()
	first := s.down.IsZero() || time.Since(s.down) >= backoffAfterFailure
	s.down = time.Now()
	// Everything pooled is suspect once a command has failed.
	for _, c := range s.pool {
		c.c.Close()
	}
	s.pool = nil
	s.mu.Unlock()

	if first {
		log.Printf("render: the shared link store is not answering (%v); link results "+
			"will not be shared between processes until it is. Fetching still works.", err)
	}
}

// do runs one command and returns a bulk string, or nil for a nil reply.
func (s *sharedStore) do(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	c, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := c.c.SetDeadline(deadline); err != nil {
		c.c.Close()
		return nil, err
	}

	if err := writeCommand(c, args); err != nil {
		c.c.Close()
		return nil, err
	}
	out, err := readReply(c.br)
	if err != nil {
		c.c.Close()
		return nil, err
	}
	s.put(c)
	return out, nil
}

func (s *sharedStore) get(ctx context.Context) (*conn, error) {
	s.mu.Lock()
	if n := len(s.pool); n > 0 {
		c := s.pool[n-1]
		s.pool = s.pool[:n-1]
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()

	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	return &conn{c: nc, br: bufio.NewReader(nc)}, nil
}

func (s *sharedStore) put(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A small pool. This service makes at most a few concurrent lookups — the tab
	// limit bounds it — and an idle connection per possible caller is waste.
	if len(s.pool) >= 8 {
		c.c.Close()
		return
	}
	s.pool = append(s.pool, c)
}

// writeCommand sends a RESP array of bulk strings, which is how every command is
// written and the only form worth supporting.
func writeCommand(c *conn, args []string) error {
	buf := make([]byte, 0, 64)
	buf = append(buf, '*')
	buf = strconv.AppendInt(buf, int64(len(args)), 10)
	buf = append(buf, '\r', '\n')
	for _, a := range args {
		buf = append(buf, '$')
		buf = strconv.AppendInt(buf, int64(len(a)), 10)
		buf = append(buf, '\r', '\n')
		buf = append(buf, a...)
		buf = append(buf, '\r', '\n')
	}
	_, err := c.c.Write(buf)
	return err
}

// readReply reads one reply. Bulk strings and nils are what GET returns; simple
// strings are what SETEX returns; errors are the server refusing.
func readReply(br *bufio.Reader) ([]byte, error) {
	line, err := readLine(br)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, errors.New("empty reply")
	}
	switch line[0] {
	case '+': // simple string, e.g. OK
		return line[1:], nil
	case '-': // error
		return nil, fmt.Errorf("store refused the command: %s", line[1:])
	case ':': // integer
		return line[1:], nil
	case '$': // bulk string
		n, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return nil, fmt.Errorf("unreadable bulk length %q", line[1:])
		}
		if n < 0 {
			return nil, nil // a nil bulk string: the key is not there
		}
		body := make([]byte, n+2) // payload plus CRLF
		if _, err := ioReadFull(br, body); err != nil {
			return nil, err
		}
		return body[:n], nil
	}
	return nil, fmt.Errorf("unexpected reply type %q", line[0])
}

func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	// Trim CRLF. A line shorter than that is a malformed frame.
	if len(line) < 2 {
		return nil, errors.New("short line")
	}
	return line[:len(line)-2], nil
}

func ioReadFull(br *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := br.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
