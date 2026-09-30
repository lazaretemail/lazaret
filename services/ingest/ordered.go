// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"hash/fnv"
	"net/mail"
	"strings"
	"sync"
)

// A worker pool that preserves order where order means something.
//
// A retrospective scan is strictly serial today, and that is why 242 messages took
// the better part of an hour: each one waits for the last, and each one is seconds
// of enrichment. The obvious fix — a worker pool — breaks the property the whole
// design rests on. Sender profiles answer from events strictly before the message
// being judged, so processing order is belief order; shuffle it and January gets
// judged against March, and every early message looks like a first contact.
//
// But that constraint is per sender, not global. Two messages from different
// senders cannot affect each other's profile, so they may be judged at the same
// time without either seeing the other. Only messages that share a sender have to
// stay in order.
//
// So the work is sharded by sender rather than queued globally: same sender, same
// shard, strictly in order; different senders, usually different shards, running
// together. On a real mailbox consecutive messages are nearly always from
// different senders, so most of the parallelism is available and none of the
// ordering is given up.
//
// Sharding on the domain rather than the address because profiles are kept per
// address *and* per domain: two different addresses at one domain do affect the
// same domain profile, so they must share a shard.
type orderedPool struct {
	shards []chan func()
	wg     sync.WaitGroup
}

func newOrderedPool(workers int) *orderedPool {
	if workers < 1 {
		workers = 1
	}
	p := &orderedPool{shards: make([]chan func(), workers)}
	for i := range p.shards {
		p.shards[i] = make(chan func(), 1)
		p.wg.Add(1)
		go func(ch chan func()) {
			defer p.wg.Done()
			for task := range ch {
				task()
			}
		}(p.shards[i])
	}
	return p
}

// Submit queues work, blocking if that shard is busy.
//
// Blocking rather than buffering: a scan that reads faster than it can analyse
// should be slowed by the analysis, not hold a window of messages in memory.
func (p *orderedPool) Submit(key string, task func()) {
	p.shards[shardOf(key, len(p.shards))] <- task
}

// Wait drains every shard.
func (p *orderedPool) Wait() {
	for _, ch := range p.shards {
		close(ch)
	}
	p.wg.Wait()
}

func shardOf(key string, n int) int {
	if n <= 1 {
		return 0
	}
	h := fnv.New32a()
	h.Write([]byte(key))
	return int(h.Sum32() % uint32(n))
}

// senderKey is what two messages must share to need ordering between them.
//
// The From domain, read from the headers without parsing the whole message: this
// runs before analysis and must not cost anything close to what analysis costs.
// An unreadable or absent From falls back to a single shared key, which is the
// safe direction — those messages serialise with each other rather than racing.
func senderKey(raw []byte) string {
	const key = "from:"
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 8<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers
		}
		if len(line) < len(key) || !strings.EqualFold(line[:len(key)], key) {
			continue
		}
		addr, err := mail.ParseAddress(strings.TrimSpace(line[len(key):]))
		if err != nil {
			return "unparsable"
		}
		if at := strings.LastIndexByte(addr.Address, '@'); at >= 0 {
			return strings.ToLower(addr.Address[at+1:])
		}
		return strings.ToLower(addr.Address)
	}
	return "no-sender"
}
