// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// LoadJSONL reads a history file: one JSON event per line.
//
// This is the smallest thing that makes profile.* real without a database. A pipeline
// that has been running writes its own events; someone evaluating rules against a
// mailbox export produces one of these from it; module 2 replaces both with DuckLake.
// The format is deliberately the Event struct itself, so there is nothing to translate
// and nothing to get subtly wrong between producer and consumer.
//
//	{"at":"2026-01-03T12:00:00Z","sender_email":"cfo@partner.test",
//	 "sender_domain":"partner.test","direction":"inbound","verdict":"benign"}
//
// Blank lines and # comments are skipped so a file can be annotated by hand.
func LoadJSONL(r io.Reader) (*Memory, error) {
	m := NewMemory()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var e jsonEvent
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return nil, fmt.Errorf("profile: line %d: %w", line, err)
		}
		ev, err := e.event()
		if err != nil {
			return nil, fmt.Errorf("profile: line %d: %w", line, err)
		}
		m.Add(ev)
	}
	return m, scanner.Err()
}

// LoadFile is LoadJSONL over a path.
func LoadFile(path string) (*Memory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadJSONL(f)
}

type jsonEvent struct {
	At           string `json:"at"`
	SenderEmail  string `json:"sender_email"`
	SenderDomain string `json:"sender_domain"`
	ReplyTo      string `json:"reply_to"`
	Direction    string `json:"direction"`
	Verdict      string `json:"verdict"`
	AuthFailed   bool   `json:"auth_failed"`
}

func (j jsonEvent) event() (Event, error) {
	at, err := time.Parse(time.RFC3339, j.At)
	if err != nil {
		return Event{}, fmt.Errorf("parsing at: %w", err)
	}

	// An event with a time but no subject is not an error in the data, it is an event
	// about nobody, and silently indexing it under "" would make every profile for an
	// unparsable sender share one history.
	if j.SenderEmail == "" && j.SenderDomain == "" && j.ReplyTo == "" {
		return Event{}, fmt.Errorf("no sender_email, sender_domain or reply_to")
	}

	dir := Direction(strings.ToLower(j.Direction))
	switch dir {
	case Inbound, Outbound, Internal:
	case "":
		dir = Inbound
	default:
		return Event{}, fmt.Errorf("unknown direction %q", j.Direction)
	}

	verdict := Verdict(strings.ToLower(j.Verdict))
	switch verdict {
	case VerdictUnknown, VerdictBenign, VerdictMalicious, VerdictSpam, VerdictFalsePositive:
	default:
		return Event{}, fmt.Errorf("unknown verdict %q", j.Verdict)
	}

	// The domain is derivable from the address, and a file that omits it should still
	// answer profile.by_sender_domain.
	domain := j.SenderDomain
	if domain == "" {
		if _, rest, found := strings.Cut(j.SenderEmail, "@"); found {
			domain = rest
		}
	}

	return Event{
		At:           at,
		SenderEmail:  j.SenderEmail,
		SenderDomain: domain,
		ReplyTo:      j.ReplyTo,
		Direction:    dir,
		Verdict:      verdict,
		AuthFailed:   j.AuthFailed,
	}, nil
}

// SenderEmails and SenderDomains are the history-backed named lists.
//
// `$sender_emails` and `$sender_domains` mean "addresses and domains this organisation
// has heard from before", which is exactly what the history holds. They are lists rather
// than profile fields because rules use them for membership — `sender.email.email in
// $sender_emails` — and a set answers that in one lookup where a profile would not.
//
// Only inbound and internal events count. An address the organisation has written *to*
// has not sent anything, and counting it would make every outbound correspondent look
// like an established sender.
func (m *Memory) SenderEmails() []string {
	return m.senders(func(e Event) string { return e.SenderEmail })
}

// SenderDomains is SenderEmails by domain.
func (m *Memory) SenderDomains() []string {
	return m.senders(func(e Event) string { return e.SenderDomain })
}

func (m *Memory) senders(pick func(Event) string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := map[string]bool{}
	for _, evs := range m.byEmail {
		for _, e := range evs {
			if e.Direction == Outbound {
				continue
			}
			if v := norm(pick(e)); v != "" {
				seen[v] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
