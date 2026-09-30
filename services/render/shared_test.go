// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// A tiny RESP server, enough to answer the two commands this client sends.
func fakeStore(t *testing.T, handle func(args []string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					args, err := readCommand(br)
					if err != nil {
						return
					}
					if _, err := c.Write([]byte(handle(args))); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func readCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n := 0
	if _, err := fmtSscan(strings.TrimSpace(line[1:]), &n); err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := br.ReadString('\n'); err != nil { // the $len line
			return nil, err
		}
		v, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		out = append(out, strings.TrimRight(v, "\r\n"))
	}
	return out, nil
}

func fmtSscan(s string, n *int) (int, error) {
	v := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}
		v = v*10 + int(c-'0')
	}
	*n = v
	return 1, nil
}

// A result put into the store comes back out of it.
func TestSharedStoreRoundTrip(t *testing.T) {
	var stored string
	addr := fakeStore(t, func(args []string) string {
		switch strings.ToUpper(args[0]) {
		case "SETEX":
			stored = args[3]
			return "+OK\r\n"
		case "GET":
			if stored == "" {
				return "$-1\r\n"
			}
			return "$" + itoa(len(stored)) + "\r\n" + stored + "\r\n"
		}
		return "-ERR unknown\r\n"
	})

	s := newSharedStore(addr, time.Hour, 1<<20)
	ctx := context.Background()

	if got := s.Get(ctx, "k"); got != nil {
		t.Fatal("an empty store answered a lookup")
	}
	s.Put(ctx, "k", &FetchResult{EffectiveURL: "https://example.test/landing", Retrieved: true})

	got := s.Get(ctx, "k")
	if got == nil {
		t.Fatal("what was stored did not come back")
	}
	if got.EffectiveURL != "https://example.test/landing" {
		t.Errorf("round trip changed the result: %+v", got)
	}
	if h, _, st, f := s.Stats(); h != 1 || st != 1 || f != 0 {
		t.Errorf("stats hits=%d stores=%d failures=%d", h, st, f)
	}
}

// The store being down must never fail a fetch, and must not be dialled on every link
// once it has failed.
//
// A cache that can break the thing it accelerates is worse than no cache. This is the
// property that lets the store be wired in by default: a deployment with no Garnet is
// slower and never wrong, and does not pay a connection timeout per link.
func TestSharedStoreFailsSoftAndBacksOff(t *testing.T) {
	// A port nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := newSharedStore(addr, time.Hour, 1<<20)
	ctx := context.Background()

	start := time.Now()
	if got := s.Get(ctx, "k"); got != nil {
		t.Fatal("a dead store answered")
	}
	first := time.Since(start)

	// Now backing off: the next twenty lookups must not dial at all.
	start = time.Now()
	for i := 0; i < 20; i++ {
		if got := s.Get(ctx, "k"); got != nil {
			t.Fatal("a dead store answered")
		}
		s.Put(ctx, "k", &FetchResult{Retrieved: true})
	}
	rest := time.Since(start)

	if rest > first {
		t.Errorf("twenty lookups after a failure took %v, longer than the one that "+
			"failed (%v): the store is being dialled on every link", rest, first)
	}
	if _, _, _, f := s.Stats(); f != 1 {
		t.Errorf("failures=%d, want exactly the one that tripped the backoff", f)
	}
}

// A value this process cannot read is a miss, not an error.
//
// The format may have changed under a rolling upgrade, and the right answer is to
// fetch the page rather than to fail the analysis.
func TestSharedStoreTreatsGarbageAsAMiss(t *testing.T) {
	addr := fakeStore(t, func(args []string) string {
		if strings.ToUpper(args[0]) == "GET" {
			return "$7\r\nnot-json\r\n"[:4] + "not-jso\r\n"
		}
		return "+OK\r\n"
	})
	s := newSharedStore(addr, time.Hour, 1<<20)
	if got := s.Get(context.Background(), "k"); got != nil {
		t.Error("unreadable stored bytes were returned as a result")
	}
	if _, m, _, f := s.Stats(); m != 1 || f != 0 {
		t.Errorf("misses=%d failures=%d; unreadable is a miss, not a failure", m, f)
	}
}

// An entry too large to be worth sending is not sent.
func TestSharedStoreSkipsOversizedEntries(t *testing.T) {
	sent := 0
	addr := fakeStore(t, func(args []string) string {
		if strings.ToUpper(args[0]) == "SETEX" {
			sent++
		}
		return "+OK\r\n"
	})
	s := newSharedStore(addr, time.Hour, 64)
	s.Put(context.Background(), "k", &FetchResult{FinalDOM: strings.Repeat("x", 4096)})
	if sent != 0 {
		t.Error("a page too large to cache locally was pushed across the network anyway")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
