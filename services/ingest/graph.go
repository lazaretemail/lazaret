// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"github.com/lazaretemail/lazaret/telemetry"

	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Microsoft 365, via the Graph API.
//
// Two mechanisms, and a deployment gets whichever one works:
//
//   - **Webhook.** Graph POSTs a change notification within seconds of a message
//     arriving. Requires an HTTPS endpoint Microsoft can reach from the internet, and
//     a subscription that must be renewed before it expires — mail subscriptions last
//     about three days at most.
//   - **Polling.** A delta query asked on an interval. Slower, and needs nothing
//     inbound at all.
//
// Webhook is preferred and polling is the fallback, because the failure modes of the
// webhook are all environmental: no public URL, a firewall, a reverse proxy that eats
// the validation handshake, a tenant whose admin has not granted the permission. Every
// one of those is invisible from inside the process and none of them should mean mail
// stops being scanned.
//
// So the failover is not just "try once at startup". A subscription can be accepted and
// then silently stop delivering — Microsoft drops a subscription whose endpoint returns
// errors, and a proxy change can break delivery without anyone touching this service.
// The source therefore watches for *silence*: if no notification arrives within the
// watchdog window, it starts polling anyway, and keeps trying to re-establish the
// subscription in the background. A connector that is quietly receiving nothing looks
// exactly like a quiet mailbox, and that is the failure worth engineering against.

// GraphSource ingests from Microsoft 365.
type GraphSource struct {
	// TenantID, ClientID and ClientSecret identify the app registration.
	TenantID     string
	ClientID     string
	ClientSecret string

	// Mailboxes to watch, as user principal names. Graph subscriptions are per
	// mailbox, so this is a list rather than a tenant-wide switch.
	Mailboxes []string

	// NotificationURL is the public HTTPS endpoint Graph will call. Empty disables the
	// webhook entirely and goes straight to polling, which is the right configuration
	// for a deployment with no inbound path.
	NotificationURL string

	// Addr is where this process listens for notifications.
	Addr string

	// ClientState is the shared secret Graph echoes back in every notification. It is
	// the only thing distinguishing a real notification from anyone on the internet
	// who has found the endpoint.
	ClientState string

	// PollInterval is how often the fallback asks.
	PollInterval time.Duration

	// Watchdog is how long silence is tolerated before polling starts anyway. Mail
	// arrives unevenly, so this needs to be longer than a plausible quiet period; an
	// hour is quiet for a working mailbox and short enough to matter.
	Watchdog time.Duration

	// MailboxID is the engine's identifier for this mailbox, set when the engine
	// configured this connector. It travels with every message so remediation can
	// be aimed at one mailbox rather than fanned out across all of them.
	MailboxID string

	// Remediate allows this connector to remove mail from the mailbox.
	//
	// Off by default: a connector added to observe a production mailbox should not
	// start deleting from it because a rule fired.
	Remediate bool

	// softDeleteOnce keeps the sovereign-cloud warning to one line per process.
	softDeleteOnce sync.Once

	Engine *Engine

	HTTPClient *http.Client

	// GraphBase and LoginBase are the API and token hosts. Empty means the public
	// cloud. They exist because the sovereign clouds are not on those hosts —
	// GCC High and DoD use graph.microsoft.us, 21Vianet uses microsoftgraph.chinacloudapi.cn
	// — and hardcoding one endpoint quietly makes the connector unusable for a whole
	// class of tenant. Tests point them at a stub.
	GraphBase string
	LoginBase string

	mu        sync.Mutex
	token     string
	tokenTill time.Time
	lastNotif time.Time
	polling   bool

	// deltaLinks remembers where each mailbox's delta query got to, so a poll asks for
	// what changed rather than re-reading the mailbox.
	deltaLinks map[string]string
}

func (g *GraphSource) Name() string { return "graph" }

func (g *GraphSource) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return telemetry.Client(&http.Client{Timeout: 60 * time.Second})
}

func (g *GraphSource) graphBase() string {
	if g.GraphBase != "" {
		return strings.TrimSuffix(g.GraphBase, "/")
	}
	return "https://graph.microsoft.com"
}

// sameHost refuses a continuation link that points somewhere other than the configured
// Graph endpoint.
func (g *GraphSource) sameHost(link string) error {
	u, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("unparsable continuation link: %w", err)
	}
	base, err := url.Parse(g.graphBase())
	if err != nil {
		return err
	}
	if !strings.EqualFold(u.Host, base.Host) {
		return fmt.Errorf("refusing a continuation link to %s; expected %s", u.Host, base.Host)
	}
	return nil
}

func (g *GraphSource) loginBase() string {
	if g.LoginBase != "" {
		return strings.TrimSuffix(g.LoginBase, "/")
	}
	return "https://login.microsoftonline.com"
}

func (g *GraphSource) pollInterval() time.Duration {
	if g.PollInterval > 0 {
		return g.PollInterval
	}
	return 2 * time.Minute
}

func (g *GraphSource) watchdog() time.Duration {
	if g.Watchdog > 0 {
		return g.Watchdog
	}
	return time.Hour
}

// Run starts the webhook if it can and polling if it must.
func (g *GraphSource) Run(ctx context.Context, deliver Deliver) error {
	g.mu.Lock()
	g.deltaLinks = map[string]string{}
	g.mu.Unlock()

	if g.NotificationURL == "" {
		log.Printf("graph: no notification URL configured; polling every %s", g.pollInterval())
		g.setPolling(true)
		return g.pollLoop(ctx, deliver)
	}

	// The notification listener starts first. Graph validates a subscription by calling
	// the endpoint *during* the create request, so an endpoint that is not yet
	// listening makes the create fail — and the failover would then blame the tenant
	// for a race in this process.
	errs := make(chan error, 1)
	go func() { errs <- g.serve(ctx, deliver) }()

	go g.subscribeLoop(ctx)
	go g.watchdogLoop(ctx, deliver)

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		return nil
	}
}

// serve listens for change notifications.
func (g *GraphSource) serve(ctx context.Context, deliver Deliver) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /graph/notify", func(w http.ResponseWriter, r *http.Request) {
		// The validation handshake. Graph sends a token as a query parameter and
		// expects it echoed back as text/plain within 10 seconds, before any
		// subscription exists. Getting this wrong is the single most common reason a
		// subscription cannot be created, and it is why the listener starts first.
		if token := r.URL.Query().Get("validationToken"); token != "" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, token)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var payload struct {
			Value []graphNotification `json:"value"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		// Acknowledge before doing the work. Graph expects a response within seconds
		// and retries — then drops the subscription — if it does not get one, and a
		// full rule evaluation takes longer than that budget.
		w.WriteHeader(http.StatusAccepted)

		g.mu.Lock()
		g.lastNotif = time.Now()
		g.mu.Unlock()

		for _, n := range payload.Value {
			if subtle.ConstantTimeCompare([]byte(n.ClientState), []byte(g.ClientState)) != 1 {
				log.Printf("graph: discarding a notification with the wrong clientState")
				continue
			}
			go g.fetchAndDeliver(context.WithoutCancel(ctx), n, deliver)
		}
	})

	srv := &http.Server{Addr: g.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sd, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(sd)
	}()

	log.Printf("graph: notification endpoint on %s (public URL %s)", g.Addr, g.NotificationURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type graphNotification struct {
	SubscriptionID string `json:"subscriptionId"`
	ClientState    string `json:"clientState"`
	ChangeType     string `json:"changeType"`
	Resource       string `json:"resource"`
	ResourceData   struct {
		ID string `json:"id"`
	} `json:"resourceData"`
}

// subscribeLoop creates subscriptions and renews them before they expire.
//
// If it cannot — no permission, unreachable endpoint, a tenant that refuses — polling
// starts instead and this keeps trying. The two are not exclusive for a moment during
// changeover, which is deliberate: a duplicate ingest is deduplicated by the engine,
// and a gap is not recoverable.
func (g *GraphSource) subscribeLoop(ctx context.Context) {
	fails := 0
	for ctx.Err() == nil {
		ok := true
		for _, mbox := range g.Mailboxes {
			if err := g.subscribe(ctx, mbox); err != nil {
				log.Printf("graph: subscribing %s: %v", mbox, err)
				ok = false
			}
		}

		if ok {
			fails = 0
			g.setPolling(false)
		} else {
			fails++
			// Two consecutive rounds of failure is enough to conclude the webhook is
			// not going to work here, rather than being briefly unavailable.
			if fails >= 2 {
				g.setPolling(true)
			}
		}

		// Mail subscriptions expire in about three days; renewing well inside that
		// leaves room for several failures before one lapses.
		select {
		case <-ctx.Done():
			return
		case <-time.After(12 * time.Hour):
		}
	}
}

func (g *GraphSource) subscribe(ctx context.Context, mailbox string) error {
	body, _ := json.Marshal(map[string]any{
		"changeType":         "created",
		"notificationUrl":    g.NotificationURL,
		"resource":           fmt.Sprintf("users/%s/mailFolders('inbox')/messages", mailbox),
		"expirationDateTime": time.Now().Add(70 * time.Hour).UTC().Format(time.RFC3339),
		"clientState":        g.ClientState,
	})
	resp, err := g.call(ctx, http.MethodPost, g.graphBase()+"/v1.0/subscriptions", body)
	if err != nil {
		return err
	}
	log.Printf("graph: subscribed to %s (%s)", mailbox, string(truncate(resp, 120)))
	return nil
}

// watchdogLoop notices a subscription that has gone quiet.
//
// A subscription that was accepted and then stopped delivering looks, from in here,
// exactly like a mailbox nobody is writing to. Silence is therefore treated as a
// symptom rather than as good news.
func (g *GraphSource) watchdogLoop(ctx context.Context, deliver Deliver) {
	g.mu.Lock()
	g.lastNotif = time.Now()
	g.mu.Unlock()

	t := time.NewTicker(g.watchdog() / 4)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.mu.Lock()
			quiet := time.Since(g.lastNotif)
			already := g.polling
			g.mu.Unlock()

			if quiet > g.watchdog() && !already {
				log.Printf("graph: no notification in %s; falling back to polling", quiet.Truncate(time.Minute))
				g.setPolling(true)
				go g.pollLoop(ctx, deliver)
			}
		}
	}
}

func (g *GraphSource) setPolling(on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.polling = on
}

func (g *GraphSource) isPolling() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.polling
}

// pollLoop asks each mailbox what changed, on an interval.
// reportHealth tells the engine how the last exchange with Graph went, when this
// connector is one the engine configured.
func (g *GraphSource) reportHealth(ctx context.Context, seen int64, err error) {
	if g.Engine != nil {
		g.Engine.ReportHealth(ctx, g.MailboxID, seen, err)
	}
}

func (g *GraphSource) pollLoop(ctx context.Context, deliver Deliver) error {
	t := time.NewTicker(g.pollInterval())
	defer t.Stop()

	for {
		if g.isPolling() {
			for _, mbox := range g.Mailboxes {
				err := g.pollOnce(ctx, mbox, deliver)
				if err != nil {
					log.Printf("graph: polling %s: %v", mbox, err)
				}
				// Reported either way. A poll that succeeded is the only
				// evidence there is that the app registration, the client
				// secret and the mailbox permission are all still good, and a
				// poll that failed says which of them is not.
				g.reportHealth(context.WithoutCancel(ctx), 0, err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// pollOnce runs a delta query, following the link from last time.
func (g *GraphSource) pollOnce(ctx context.Context, mailbox string, deliver Deliver) error {
	g.mu.Lock()
	next := g.deltaLinks[mailbox]
	g.mu.Unlock()

	if next == "" {
		// First run: ask only for what arrives from now on. Starting from the
		// beginning would re-ingest the whole mailbox, which the engine would
		// deduplicate but only after evaluating every message in it.
		next = fmt.Sprintf(
			"%s/v1.0/users/%s/mailFolders/inbox/messages/delta?$select=id,receivedDateTime",
			g.graphBase(), url.PathEscape(mailbox))
	}

	for next != "" && ctx.Err() == nil {
		raw, err := g.call(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		var page struct {
			Value []struct {
				ID       string `json:"id"`
				Received string `json:"receivedDateTime"`
			} `json:"value"`
			NextLink  string `json:"@odata.nextLink"`
			DeltaLink string `json:"@odata.deltaLink"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("decoding a delta page: %w", err)
		}

		for _, m := range page.Value {
			if m.ID == "" {
				continue // a removed message: an id and an @removed marker, nothing to scan
			}
			received, _ := time.Parse(time.RFC3339, m.Received)
			g.deliverMessage(ctx, mailbox, m.ID, received, deliver)
		}

		// nextLink and deltaLink are absolute URLs chosen by the server, and every
		// request carries a bearer token. Following one blindly would send that token
		// wherever the response said to — so a link that leaves the configured Graph
		// host is refused rather than followed. Against real Graph this never fires;
		// it exists because "the server told us to" is not a reason to hand out a
		// credential.
		next = ""
		if page.NextLink != "" {
			if err := g.sameHost(page.NextLink); err != nil {
				return err
			}
			next = page.NextLink
		}
		if page.DeltaLink != "" {
			if err := g.sameHost(page.DeltaLink); err != nil {
				return err
			}
			g.mu.Lock()
			g.deltaLinks[mailbox] = page.DeltaLink
			g.mu.Unlock()
		}
	}
	return nil
}

// fetchAndDeliver handles one webhook notification.
func (g *GraphSource) fetchAndDeliver(ctx context.Context, n graphNotification, deliver Deliver) {
	mailbox := mailboxFromResource(n.Resource)
	id := n.ResourceData.ID
	if id == "" {
		return
	}
	g.deliverMessage(ctx, mailbox, id, time.Now().UTC(), deliver)
}

// deliverMessage fetches the MIME and hands it to the engine.
//
// $value on a message returns the original RFC 5322 bytes rather than Graph's parsed
// JSON, which matters: the engine's whole input is a raw message, and a model
// reconstructed from Microsoft's parse would be Microsoft's opinion of the headers
// rather than what arrived.
func (g *GraphSource) deliverMessage(ctx context.Context, mailbox, id string, received time.Time, deliver Deliver) {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s/$value",
		g.graphBase(), url.PathEscape(mailbox), url.PathEscape(id))

	raw, err := g.call(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		log.Printf("graph: fetching %s: %v", id, err)
		return
	}

	verdict, err := deliver(ctx, RawMessage{
		Raw: raw, Source: "graph", Mailbox: mailbox, MailboxID: g.MailboxID,
		ProviderID: id, ReceivedAt: received,
	})
	if err != nil {
		log.Printf("graph: analysing %s: %v", id, err)
		return
	}

	if verdict.Actionable() && g.Remediate {
		if err := g.quarantine(ctx, mailbox, id, verdict); err != nil {
			log.Printf("graph: quarantining %s: %v", id, err)
		}
	}
}

// quarantine takes a message out of the mailbox.
//
// Not a move to Deleted Items and not a move to Junk. Both leave the message in the
// mailbox, one click from being read, which is not what quarantine means here.
//
// # permanentDelete, not DELETE
//
// Graph has two ways to remove a message and the difference matters.
//
// `DELETE` is a soft delete: the item lands in Deleted Items, and the recipient can
// pull it straight back out. That is not custody, it is filing with extra steps.
//
// `POST .../permanentDelete` puts the item in the **Purges** folder in the dumpster.
// Outlook and Outlook on the web cannot reach it and Recover Deleted Items will not
// return it, so the recipient genuinely no longer has the message — while an
// administrator with eDiscovery can still produce it, and a mailbox on hold keeps it.
// That is exactly the shape custody wants: gone from the mailbox, still accounted for.
//
// It went generally available in Graph v1.0 and needs `Mail.ReadWrite`, which this
// connector already holds; there is no extra permission to grant.
//
// It is not offered in the sovereign clouds — US Government L4 and L5, and 21Vianet —
// so those fall back to DELETE with a warning, because a weaker removal is better
// than a connector that cannot remediate at all there.
func (g *GraphSource) quarantine(ctx context.Context, mailbox, id string, v *Verdict) error {
	if err := g.removeMessage(ctx, mailbox, id); err != nil {
		return err
	}
	log.Printf("graph: removed %s from %s (%s)", v.MessageID, mailbox, describe(v))
	return g.Engine.RecordAction(ctx, v.MessageID, "quarantine", describe(v), "lazaret-ingest/graph")
}

// removeMessage permanently deletes, falling back to a soft delete where the action
// does not exist.
func (g *GraphSource) removeMessage(ctx context.Context, mailbox, id string) error {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s/permanentDelete",
		g.graphBase(), url.PathEscape(mailbox), url.PathEscape(id))
	_, err := g.call(ctx, http.MethodPost, endpoint, nil)
	if err == nil {
		return nil
	}
	if !unsupportedAction(err) {
		return err
	}

	// Once per process, not once per message: in a sovereign cloud this is every
	// message, and the point is to tell an operator that removal is weaker there, not
	// to fill the log.
	g.softDeleteOnce.Do(func() {
		log.Printf("graph: permanentDelete is not available on %s, falling back to DELETE; "+
			"removed mail will be recoverable by the recipient from Deleted Items", g.graphBase())
	})
	endpoint = fmt.Sprintf("%s/v1.0/users/%s/messages/%s",
		g.graphBase(), url.PathEscape(mailbox), url.PathEscape(id))
	_, err = g.call(ctx, http.MethodDelete, endpoint, nil)
	return err
}

// unsupportedAction reports a Graph deployment that does not implement an action.
//
// On the status code, never the message. A 404 here is ambiguous — it is also what an
// already-deleted message returns — but the fallback is harmless in that case, because
// the DELETE returns 404 too and the caller sees the same not-found. What must not
// trigger a fallback is 401 or 403: retrying a permissions failure as a soft delete
// would leave a recoverable copy in every mailbox while the connector looked healthy.
func unsupportedAction(err error) bool {
	var ge *graphError
	if !errors.As(err, &ge) {
		return false
	}
	return ge.Status == http.StatusNotFound || ge.Status == http.StatusNotImplemented
}

// Remove finds a message by its internet Message-ID and deletes it.
//
// Graph's own message id is per-mailbox and is not what the engine records, so the
// lookup is by internetMessageId — which is the header value, and the same identity
// the audit log shows.
//
// Not finding it is success, for the same reason as on IMAP: the recipient may have
// deleted it, or this may be the second of two watched mailboxes.
func (g *GraphSource) Remove(ctx context.Context, messageID string) error {
	for _, mailbox := range g.Mailboxes {
		ids, err := g.findByMessageID(ctx, mailbox, messageID)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err := g.removeMessage(ctx, mailbox, id); err != nil {
				return err
			}
			log.Printf("graph: removed %s from %s", messageID, mailbox)
		}
	}
	return nil
}

// Restore puts a held message back, as MIME.
func (g *GraphSource) Restore(ctx context.Context, messageID string, raw []byte) error {
	if len(raw) == 0 {
		return errors.New("nothing to restore: no message bytes")
	}
	for _, mailbox := range g.Mailboxes {
		ids, err := g.findByMessageID(ctx, mailbox, messageID)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			log.Printf("graph: %s is already in %s", messageID, mailbox)
			continue
		}
		// Posting text/plain MIME to the messages collection creates the message
		// from the original bytes, rather than from a JSON representation that
		// would have to reconstruct every header.
		endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages", g.graphBase(), url.PathEscape(mailbox))
		if _, err := g.callMIME(ctx, endpoint, raw); err != nil {
			return err
		}
		log.Printf("graph: restored %s to %s", messageID, mailbox)
	}
	return nil
}

func (g *GraphSource) findByMessageID(ctx context.Context, mailbox, messageID string) ([]string, error) {
	// Quoted and escaped: the value comes from a message header, and an unescaped
	// quote would change the filter rather than fail it.
	filter := "internetMessageId eq '" + strings.ReplaceAll(messageID, "'", "''") + "'"
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages?$select=id&$filter=%s",
		g.graphBase(), url.PathEscape(mailbox), url.QueryEscape(filter))
	raw, err := g.call(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Value))
	for _, v := range out.Value {
		ids = append(ids, v.ID)
	}
	return ids, nil
}

// callMIME posts raw message bytes.
func (g *GraphSource) callMIME(ctx context.Context, endpoint string, raw []byte) ([]byte, error) {
	token, err := g.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("graph: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// call makes an authenticated Graph request.
func (g *GraphSource) call(ctx context.Context, method, endpoint string, body []byte) ([]byte, error) {
	token, err := g.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &graphError{
			Status: resp.StatusCode,
			Method: method,
			Where:  shortEndpoint(endpoint),
			Body:   string(truncate(payload, 300)),
		}
	}
	return payload, nil
}

// graphError carries the status code rather than only a message.
//
// It exists because the first version of the permanentDelete fallback decided whether
// an action was unsupported by looking for "404" in the error text — and the error
// text contains the endpoint, so a server on port 40407 matched. Every removal in
// such a deployment would have quietly downgraded from a permanent delete to a
// recoverable one, with nothing in the logs but a line saying the cloud did not
// support it. Status codes are structured data and comparing them to strings is how
// that kind of thing happens.
type graphError struct {
	Status int
	Method string
	Where  string
	Body   string
}

func (e *graphError) Error() string {
	return fmt.Sprintf("%s %s: %d: %s", e.Method, e.Where, e.Status, e.Body)
}

// accessToken fetches and caches a client-credentials token.
func (g *GraphSource) accessToken(ctx context.Context) (string, error) {
	g.mu.Lock()
	if g.token != "" && time.Now().Before(g.tokenTill) {
		t := g.token
		g.mu.Unlock()
		return t, nil
	}
	g.mu.Unlock()

	form := url.Values{
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"scope":         {g.graphBase() + "/.default"},
		"grant_type":    {"client_credentials"},
	}
	endpoint := g.loginBase() + "/" + url.PathEscape(g.TenantID) + "/oauth2/v2.0/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("token endpoint: %s: %s", resp.Status, truncate(payload, 300))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(payload, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", errors.New("token endpoint returned no access_token")
	}

	g.mu.Lock()
	g.token = tok.AccessToken
	// A minute of headroom, so a token does not expire between the check and the call.
	g.tokenTill = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - time.Minute)
	g.mu.Unlock()

	return tok.AccessToken, nil
}

// mailboxFromResource pulls the user out of "users/{upn}/mailFolders('inbox')/messages/{id}".
func mailboxFromResource(resource string) string {
	parts := strings.Split(resource, "/")
	for i, p := range parts {
		if p == "Users" || p == "users" {
			if i+1 < len(parts) {
				return strings.Trim(parts[i+1], "'")
			}
		}
	}
	return ""
}

func shortEndpoint(s string) string {
	if i := strings.Index(s, "?"); i > 0 {
		return s[:i]
	}
	return s
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
