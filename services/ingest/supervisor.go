// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"github.com/lazaretemail/lazaret/telemetry"

	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// The Supervisor runs the mailboxes an administrator configured, rather than the ones
// someone put on the command line.
//
// Flags were right while there was one mailbox and no way to describe a second. They
// stop being right as soon as adding a mailbox is a thing an administrator does in the
// dashboard: a flag means a restart, a restart means a deployment, and a connector that
// needs redeploying to watch one more inbox is a connector nobody adds inboxes to.
//
// So this polls the engine for the mailbox list and reconciles: start what is new, stop
// what is gone, restart what changed. The flags still work and are still the right way
// to run a single mailbox from a shell, but they are no longer the only way.
type Supervisor struct {
	Engine   *Engine
	Base     string
	Token    string
	Interval time.Duration
	HTTP     *http.Client

	// Defaults for the fields a mailbox row does not carry, because they are
	// properties of this deployment rather than of the mailbox: where Graph should
	// send notifications, which directory the application is registered in.
	GraphTenant, GraphClient, GraphNotify, GraphAddr, GraphState string
	GraphBase, GraphLogin                                        string
	IMAPPoll, GraphPoll, GraphWatchdog                           time.Duration

	mu      sync.Mutex
	running map[string]*supervised

	// graph is the Microsoft application registration as last read from the
	// engine. Nil until one is configured, which for most deployments is never.
	graph *GraphApp
}

// Filer is a source that can carry out a rule's action on a message.
//
// Separate from Remediator, which is about quarantine and its reversal — the two
// halves of custody, where the platform holds the only copy and must be able to
// put it back. These are the gentler ones: move it, flag it, mark it read. A
// connector that has not implemented them does not claim the interface, and the
// dispatch above reports that rather than quietly succeeding.
type Filer interface {
	// Apply carries out one op. Config holds the action's settings — the folder
	// a move goes to, say — copied from the configured action when the work was
	// queued, so that editing the action later does not change what an
	// already-queued one does.
	Apply(ctx context.Context, op, messageID string, config map[string]string) error
}

// Remediator is a source that can act on its mailbox after the fact.
//
// Separate from Source because the two things happen at different times and for
// different reasons: a Source collects mail as it arrives, while this carries out a
// decision a person made later, in another process, about a message that has already
// been delivered and analysed.
type Remediator interface {
	// Remove deletes a message from the mailbox. Not finding it is success.
	Remove(ctx context.Context, messageID string) error

	// Restore puts held bytes back.
	Restore(ctx context.Context, messageID string, raw []byte) error
}

type supervised struct {
	fingerprint string
	source      Source
	cancel      context.CancelFunc
	done        chan struct{}
}

// remoteMailbox is a mailbox as the engine describes it, credentials included.
//
// Read from /v0/mailboxes/secrets, which only an API token can reach — a browser
// session is refused there however privileged it is, so an XSS in the dashboard cannot
// reach a credential.
type remoteMailbox struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Address   string `json:"address"`
	Host      string `json:"host"`
	Username  string `json:"username"`
	TLSMode   string `json:"tls_mode"`
	Folder    string `json:"folder"`
	GraphUser string `json:"graph_user"`
	Secret    string `json:"secret"`
	Enabled   bool   `json:"enabled"`
	Remediate bool   `json:"remediate"`
}

// fingerprint is everything that would require restarting the source if it changed.
//
// Deliberately includes the secret. A rotated password that does not restart the
// connector leaves it authenticating with the old one until something else happens to
// change, and the symptom is a mailbox that quietly stops being read.
func (m remoteMailbox) fingerprint() string {
	return strings.Join([]string{
		m.Kind, m.Address, m.Host, m.Username, m.TLSMode, m.Folder,
		fmt.Sprintf("%t", m.Remediate), m.GraphUser, fmt.Sprintf("%t", m.Enabled),
		fmt.Sprintf("%x", len(m.Secret)) + hashish(m.Secret),
	}, "\x00")
}

// hashish is a short, non-reversible digest, used only to notice a change.
func hashish(s string) string {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

// Run reconciles until ctx is cancelled.
func (s *Supervisor) Run(ctx context.Context, deliver Deliver) error {
	if s.Interval <= 0 {
		s.Interval = time.Minute
	}
	if s.HTTP == nil {
		s.HTTP = telemetry.Client(&http.Client{Timeout: 30 * time.Second})
	}
	s.running = map[string]*supervised{}

	t := time.NewTicker(s.Interval)
	defer t.Stop()

	for {
		if err := s.reconcile(ctx, deliver); err != nil {
			// An unreachable engine is not a reason to stop collecting mail. The
			// sources already running keep running; only the list of them is stale.
			log.Printf("supervisor: %v", err)
		}
		s.remediate(ctx)
		select {
		case <-ctx.Done():
			s.stopAll()
			return nil
		case <-t.C:
		}
	}
}

func (s *Supervisor) reconcile(ctx context.Context, deliver Deliver) error {
	boxes, err := s.fetch(ctx)
	if err != nil {
		return err
	}

	// The application registration, on the same tick as the mailbox list. A
	// client secret expires — two years by default and often far less — and the
	// fix for that should be pasting a new one into a form, not restarting a
	// container. A failure to read it is logged and the previous value kept: a
	// momentary engine hiccup should not take every Microsoft mailbox down.
	if app, err := s.graphApp(ctx); err != nil {
		log.Printf("supervisor: reading the Microsoft registration: %v", err)
	} else {
		s.mu.Lock()
		s.graph = app
		s.mu.Unlock()
	}

	want := map[string]remoteMailbox{}
	for _, m := range boxes {
		if m.Enabled {
			want[m.ID] = m
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A Graph source's identity is the mailbox row *and* the registration, so a
	// rotated client secret restarts it. Without that the source keeps presenting
	// the old secret and every token request fails with an error that says
	// nothing about why — the mailbox simply stops working, some months after
	// anyone touched it.
	graphPrint := graphFingerprint(s.graph)

	for id, run := range s.running {
		m, keep := want[id]
		if keep && m.fingerprint()+graphPrintFor(m, graphPrint) == run.fingerprint {
			continue
		}
		reason := "removed or disabled"
		if keep {
			reason = "configuration changed"
		}
		log.Printf("supervisor: stopping %s (%s)", id, reason)
		run.cancel()
		<-run.done
		delete(s.running, id)
	}

	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		if _, ok := s.running[id]; ok {
			continue
		}
		m := want[id]
		src, err := s.source(m)
		if err != nil {
			log.Printf("supervisor: %s (%s): %v", m.Address, id, err)
			continue
		}
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		s.running[id] = &supervised{
			fingerprint: m.fingerprint() + graphPrintFor(m, graphPrint),
			source:      src, cancel: cancel, done: done,
		}
		log.Printf("supervisor: starting %s for %s", src.Name(), m.Address)
		go func(src Source, addr string) {
			defer close(done)
			if err := src.Run(runCtx, deliver); err != nil && runCtx.Err() == nil {
				log.Printf("supervisor: %s (%s) stopped: %v", src.Name(), addr, err)
			}
		}(src, m.Address)

		// Retrospective scans run alongside the live watch rather than instead
		// of it, on their own goroutine: a ninety-day sweep takes hours and new
		// mail must not wait behind it. A connector whose kind cannot walk its
		// history simply does not offer the capability, and a scan created
		// against that mailbox stays pending and visible rather than silently
		// doing nothing.
		if hist, ok := src.(HistoricalSource); ok {
			go RunBackfills(runCtx, s.Engine, id, hist, s.Interval)
		} else {
			log.Printf("supervisor: %s cannot scan history for %s", src.Name(), m.Address)
		}
	}
	return nil
}

// remediate collects and carries out the work the engine has queued.
//
// Polled on the same tick as the mailbox list. That sets the latency of a release:
// an analyst clicks, and the message reappears within one interval. It could be a
// push instead, but a connector that has to be reachable from the engine is a
// connector that cannot sit behind a firewall, and most of them do.
func (s *Supervisor) remediate(ctx context.Context) {
	s.mu.Lock()
	ids := make([]string, 0, len(s.running))
	sources := make(map[string]Source, len(s.running))
	for id, run := range s.running {
		ids = append(ids, id)
		sources[id] = run.source
	}
	s.mu.Unlock()
	sort.Strings(ids)

	for _, id := range ids {
		r, ok := sources[id].(Remediator)
		if !ok {
			continue
		}
		jobs, err := s.claim(ctx, id)
		if err != nil {
			log.Printf("supervisor: %s: %v", id, err)
			continue
		}
		for _, j := range jobs {
			var err error
			switch j.Op {
			case "remove":
				err = r.Remove(ctx, j.MessageID)
			case "restore":
				err = r.Restore(ctx, j.MessageID, j.Raw)
			default:
				// Everything a rule's actions can ask for. A connector that
				// cannot do one says so rather than reporting success — a
				// message somebody believes was moved and which is still in an
				// inbox is worse than a visible failure.
				filer, ok := sources[id].(Filer)
				if !ok {
					err = fmt.Errorf("a %s mailbox cannot %s a message",
						sources[id].Name(), j.Op)
					break
				}
				err = filer.Apply(ctx, j.Op, j.MessageID, j.Config)
			}
			msg := ""
			if err != nil {
				msg = err.Error()
				log.Printf("supervisor: %s %s: %v", j.Op, j.MessageID, err)
			}
			// Reported either way. A remediation nobody acknowledged is retried
			// forever, and one that failed silently is a message somebody believes
			// was removed and which is still in an inbox.
			if err := s.finish(ctx, j.ID, msg); err != nil {
				log.Printf("supervisor: reporting %d: %v", j.ID, err)
			}
		}
	}
}

type remediation struct {
	ID        int64             `json:"id"`
	MessageID string            `json:"message_id"`
	Op        string            `json:"op"`
	Raw       []byte            `json:"raw,omitempty"`
	Config    map[string]string `json:"config,omitempty"`
}

func (s *Supervisor) claim(ctx context.Context, mailboxID string) ([]remediation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.Base+"/v0/mailboxes/"+url.PathEscape(mailboxID)+"/remediations", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claiming remediations: %s", resp.Status)
	}
	var out struct {
		Remediations []remediation `json:"remediations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Remediations, nil
}

func (s *Supervisor) finish(ctx context.Context, id int64, failure string) error {
	body, _ := json.Marshal(map[string]string{"error": failure})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/v0/remediations/%d", s.Base, id), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reporting remediation %d: %s", id, resp.Status)
	}
	return nil
}

func (s *Supervisor) stopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, run := range s.running {
		run.cancel()
		<-run.done
		delete(s.running, id)
	}
}

func (s *Supervisor) source(m remoteMailbox) (Source, error) {
	switch m.Kind {
	case "imap":
		if m.Host == "" || m.Username == "" || m.Secret == "" {
			return nil, fmt.Errorf("imap mailbox needs a host, a username and a credential")
		}
		tls := m.TLSMode
		if tls == "" {
			tls = "tls"
		}
		folder := m.Folder
		if folder == "" {
			folder = "INBOX"
		}
		return &IMAPSource{
			MailboxID: m.ID,
			Addr:      m.Host, Username: m.Username, Password: m.Secret,
			Mailbox: folder, Remediate: m.Remediate,
			TLSMode: tls, PollInterval: s.IMAPPoll, Engine: s.Engine,
		}, nil

	case "graph":
		if !s.graph.Configured() {
			return nil, fmt.Errorf("a Graph mailbox needs the Microsoft application " +
				"registration, which an administrator sets on the dashboard under " +
				"Settings → Microsoft 365: it is one registration for the whole " +
				"deployment rather than a property of this mailbox")
		}
		user := m.GraphUser
		if user == "" {
			user = m.Address
		}
		// The registration decides the cloud when it names one; the flags are the
		// fallback, for unmanaged mode where there is no registration to read.
		graphBase, loginBase := s.graph.hosts()
		if graphBase == "" {
			graphBase, loginBase = s.GraphBase, s.GraphLogin
		}
		return &GraphSource{
			MailboxID: m.ID,
			// From the registration, not from flags. The mailbox row carries
			// only which mailbox it is; the identity used to reach it belongs
			// to the deployment.
			TenantID:     s.graph.DirectoryID,
			ClientID:     s.graph.ClientID,
			ClientSecret: s.graph.ClientSecret,
			Mailboxes:    []string{user}, NotificationURL: s.graph.NotifyURL,
			// One listener for the deployment, not one per mailbox: two sources
			// binding the same port would leave the second permanently failing.
			Addr: s.GraphAddr, ClientState: s.graph.ClientState,
			PollInterval: s.GraphPoll, Watchdog: s.GraphWatchdog,
			Remediate: m.Remediate, Engine: s.Engine,
			GraphBase: graphBase, LoginBase: loginBase,
		}, nil
	}
	return nil, fmt.Errorf("unknown mailbox kind %q", m.Kind)
}

func (s *Supervisor) fetch(ctx context.Context) ([]remoteMailbox, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Base+"/v0/mailboxes/secrets", nil)
	if err != nil {
		return nil, err
	}
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading the mailbox list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading the mailbox list: %s", resp.Status)
	}
	var out struct {
		Mailboxes []remoteMailbox `json:"mailboxes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Mailboxes, nil
}

func (s *Supervisor) Name() string { return "supervisor" }

// The Microsoft 365 application registration, fetched from the engine.
//
// It used to be three command-line flags here, which meant onboarding Microsoft 365
// was a redeploy and made this the last thing an administrator could not do from the
// web interface. Now it is a settings page, and the connector reads it on the same
// tick it reads the mailbox list.
//
// Refetched rather than cached for the process lifetime, because it changes: a
// client secret expires — Microsoft's default is two years and plenty of directories
// set six months — and the fix for that should be pasting a new one into a form, not
// restarting a container.

// GraphApp is the registration as the engine returns it to a service token.
type GraphApp struct {
	DirectoryID  string `json:"directory_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	NotifyURL    string `json:"notify_url"`
	ClientState  string `json:"client_state"`

	// Cloud is which Microsoft cloud the tenant is in, from the registration. It
	// takes precedence over -graph-base and -graph-login-base, so a managed
	// deployment configures its cloud in the same form as everything else about the
	// registration; the flags remain for unmanaged mode, where there is no engine
	// to hold a registration.
	Cloud string `json:"cloud"`

	HasSecret bool `json:"has_secret"`
}

// hosts returns the Graph API and token hosts this registration names, or empty
// strings when it names none and the flags should decide.
func (g *GraphApp) hosts() (graphBase, loginBase string) {
	if g == nil {
		return "", ""
	}
	switch g.Cloud {
	case "usgov":
		return "https://graph.microsoft.us", "https://login.microsoftonline.us"
	case "usgovdod":
		return "https://dod-graph.microsoft.us", "https://login.microsoftonline.us"
	case "china":
		return "https://microsoftgraph.chinacloudapi.cn", "https://login.chinacloudapi.cn"
	default:
		// Including "public": the source already defaults to the public cloud when
		// these are empty, so saying so here would only duplicate it.
		return "", ""
	}
}

// Configured reports a registration complete enough to authenticate with.
func (g *GraphApp) Configured() bool {
	return g != nil && g.DirectoryID != "" && g.ClientID != "" && g.ClientSecret != ""
}

// graphApp reads the registration. A nil result with no error means none is
// configured, which is the normal state of a deployment with no Microsoft mailboxes.
func (s *Supervisor) graphApp(ctx context.Context) (*GraphApp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Base+"/v0/graph-app/secrets", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)

	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading the Graph registration: %s", resp.Status)
	}
	var g GraphApp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&g); err != nil {
		return nil, err
	}
	return &g, nil
}

// graphFingerprint identifies a registration, so a source is restarted when it
// changes and left alone when it does not.
//
// The secret is included, hashed with everything else: a rotated client secret must
// restart the source, and a source still holding the old one fails every token
// request with an error that says nothing about why.
func graphFingerprint(g *GraphApp) string {
	if g == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(g.DirectoryID + "\x00" + g.ClientID + "\x00" +
		g.ClientSecret + "\x00" + g.NotifyURL + "\x00" + g.ClientState + "\x00" + g.Cloud))
	return hex.EncodeToString(sum[:8])
}

// graphPrintFor folds the registration into a Graph mailbox's fingerprint and
// leaves an IMAP one alone — an IMAP mailbox does not care what Microsoft
// credentials the deployment holds, and restarting it when they change would be a
// reconnection for no reason.
func graphPrintFor(m remoteMailbox, graphPrint string) string {
	if m.Kind != "graph" {
		return ""
	}
	return "|" + graphPrint
}
