// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// The property the whole design rests on, kept: messages from one sender are
// judged in the order they arrived, because sender profiles answer from events
// strictly before the message being judged.
func TestSameSenderStaysInOrder(t *testing.T) {
	p := newOrderedPool(8)

	var mu sync.Mutex
	seen := map[string][]int{}

	for sender := 0; sender < 5; sender++ {
		for i := 0; i < 20; i++ {
			key := fmt.Sprintf("sender%d.test", sender)
			i := i
			p.Submit(key, func() {
				mu.Lock()
				seen[key] = append(seen[key], i)
				mu.Unlock()
			})
		}
	}
	p.Wait()

	for key, order := range seen {
		if len(order) != 20 {
			t.Errorf("%s: %d messages, want 20", key, len(order))
		}
		for i := range order {
			if order[i] != i {
				t.Fatalf("%s: message %d ran at position %d — one sender's order was not kept",
					key, order[i], i)
			}
		}
	}
}

// And the point of doing it at all: different senders overlap, rather than each
// waiting for the last as a strictly serial scan does.
func TestDifferentSendersRunConcurrently(t *testing.T) {
	const workers = 4
	p := newOrderedPool(workers)

	var mu sync.Mutex
	var running, peak int

	// One message from each of many senders, so they land on different shards.
	for i := 0; i < 64; i++ {
		p.Submit(fmt.Sprintf("s%d.test", i), func() {
			mu.Lock()
			running++
			if running > peak {
				peak = running
			}
			mu.Unlock()

			time.Sleep(5 * time.Millisecond)

			mu.Lock()
			running--
			mu.Unlock()
		})
	}
	p.Wait()

	if peak < 2 {
		t.Errorf("peak concurrency was %d; a sharded pool that never overlaps is just a serial scan", peak)
	}
	if peak > workers {
		t.Errorf("peak concurrency was %d, over the %d workers", peak, workers)
	}
}

// Two different addresses at one domain share a domain profile, so they must
// share a shard — keying on the address alone would let them race.
func TestSameDomainSharesAShard(t *testing.T) {
	a := senderKey([]byte("From: Alice <alice@example.test>\r\nSubject: x\r\n\r\nbody"))
	b := senderKey([]byte("From: Bob <bob@example.test>\r\nSubject: y\r\n\r\nbody"))
	if a != b {
		t.Errorf("two addresses at one domain keyed differently (%q vs %q); the domain profile would race", a, b)
	}
	if a != "example.test" {
		t.Errorf("key = %q, want the domain", a)
	}
}

func TestSenderKeyHandlesAwkwardHeaders(t *testing.T) {
	cases := map[string]string{
		"From: plain@example.test\r\n\r\nbody":         "example.test",
		"from: Mixed <UP@EXAMPLE.TEST>\r\n\r\nbody":    "example.test",
		"Subject: first\r\nFrom: a@b.test\r\n\r\nbody": "b.test",
		"Subject: none at all\r\n\r\nbody":             "no-sender",
		"From: not an address at all\r\n\r\nbody":      "unparsable",
		"\r\nFrom: after@the.headers\r\n":              "no-sender",
	}
	for raw, want := range cases {
		if got := senderKey([]byte(raw)); got != want {
			t.Errorf("senderKey(%q) = %q, want %q", raw, got, want)
		}
	}
}
