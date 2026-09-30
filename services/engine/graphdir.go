// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/services/engine/store"
	"github.com/lazaretemail/lazaret/telemetry"
)

// Walking the directory, so an estate can be onboarded in one go.
//
// Adding mailboxes one at a time is fine for six and absurd for six hundred. An
// administrator who has just pasted an application registration already told us how to
// authenticate against their tenant; asking them to then re-type every address by hand
// is asking them to transcribe a list Microsoft is willing to hand over.
//
// # Why the engine calls Microsoft, when the connector is the thing that talks to it
//
// Everywhere else, the connector holds the provider socket and the engine never reaches
// out: see mailbox_health.go, where the connector reports because the engine cannot
// reach it. That rule is about the *engine reaching the connector*, not about egress,
// and it is not violated here.
//
// The reason it cannot be the connector is simpler and decides it: at the moment this
// is useful there is no connector to ask. A Graph source exists per configured mailbox,
// and the administrator doing this has zero configured mailboxes — that is the whole
// point. Routing discovery through a claim-and-report queue would also make an
// interactive act asynchronous, and "press a button, wait for a background worker to
// notice" is a poor way to answer "what is in my tenant".
//
// So: one outbound HTTPS call to Microsoft, read-only, on an administrator's explicit
// request. The engine already makes outbound calls for RDAP.
//
// # The extra permission, said out loud
//
// Collecting mail needs Mail.Read. Listing the directory needs User.Read.All, which is
// a *different* consent an administrator has to grant, and a tenant that has not will
// get a 403 here while mail collection works perfectly. That is a confusing failure to
// debug from a generic error, so it is detected and named — see errNeedsUserRead.

// GraphUser is one account Microsoft reported.
type GraphUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"display_name,omitempty"`
	UserPrincipalName string `json:"user_principal_name"`

	// Mail is the primary SMTP address. An account without one has no Exchange
	// mailbox to collect from, which is the only reliable signal /users carries.
	//
	// Always emitted, never omitted: the endpoint only returns accounts that passed
	// Mailboxable, so every one it sends has an address. Marking it optional would
	// make the console's type say it might be missing, and every use of it would
	// then need a guard for a case that cannot occur.
	Mail string `json:"mail"`

	// AccountEnabled and UserType are reported rather than filtered on, so the
	// console can show why something is not offered instead of silently omitting it.
	AccountEnabled bool   `json:"account_enabled"`
	UserType       string `json:"user_type,omitempty"`

	// Configured says this address is already a mailbox here. Shown rather than
	// hidden: an administrator running a second walk after adding forty people
	// wants to see that the forty are accounted for, not wonder where they went.
	Configured bool `json:"configured"`
}

// Mailboxable reports whether this account is worth offering as a mailbox.
//
// Three things disqualify one, and none of them is a judgement call:
//
//   - No mail address: there is no Exchange mailbox behind it. Unlicensed accounts,
//     most service principals and many synced objects look like this.
//   - Disabled in the directory: the account is not in use.
//   - A guest: their mail lives in their own organisation's tenant, and this
//     registration cannot read it.
//
// What it deliberately does not try to decide is whether a licensed member *really*
// has a mailbox provisioned. Graph will not say from this endpoint without a call per
// user, and guessing would mean either hiding real mailboxes or inventing certainty.
// One that turns out not to exist reports itself as unreachable on the next health tick,
// which is a thing the console already shows.
func (u GraphUser) Mailboxable() bool {
	return u.Mail != "" && u.AccountEnabled && !strings.EqualFold(u.UserType, "Guest")
}

// graphDirTimeout bounds a whole walk. A large tenant pages, and each page is a round
// trip to Microsoft; this is generous enough for tens of thousands of accounts and
// short enough that a hung call does not hold an admin's browser open indefinitely.
const graphDirTimeout = 2 * time.Minute

// maxDirectoryPages caps a walk at roughly a million accounts.
//
// A bound rather than trust: nextLink is a URL Microsoft hands back and this follows it
// in a loop, so a malformed or cyclic response must terminate. It is far above any real
// tenant, so hitting it means something is wrong rather than something is large.
const maxDirectoryPages = 1000

// errNeedsUserRead is returned when the registration can collect mail but may not read
// the directory. Its text is the whole fix, because the alternative is an administrator
// reading "403 Forbidden" and checking the client secret they just pasted correctly.
var errNeedsUserRead = fmt.Errorf(
	"this application registration is not allowed to read the directory. Collecting mail " +
		"needs Mail.Read; listing accounts additionally needs the User.Read.All " +
		"application permission, granted with admin consent in Entra ID. Mail collection " +
		"is unaffected either way")

// graphDirectory lists the accounts in the tenant's directory.
func (a *API) graphDirectory(ctx context.Context, tenant string) ([]GraphUser, error) {
	app, err := a.store.GraphApp(store.WithTenant(ctx, tenant), tenant, true)
	if err != nil {
		return nil, err
	}
	if app == nil || !app.Configured() {
		return nil, fmt.Errorf("no Microsoft 365 application registration is configured, " +
			"so there is no directory to read. Add one under Settings → Microsoft 365")
	}

	ctx, cancel := context.WithTimeout(ctx, graphDirTimeout)
	defer cancel()

	graphBase, loginBase := app.Hosts()
	client := telemetry.Client(&http.Client{Timeout: 30 * time.Second})

	token, err := graphAppToken(ctx, client, loginBase, graphBase, app)
	if err != nil {
		return nil, err
	}
	return graphUsers(ctx, client, graphBase, token)
}

// graphUsers pages through /users.
//
// Split from the caller so it can be exercised against a stub: the paging, the host
// check on the continuation link and the permission refusal are the parts with rules in
// them, and none of them should need a store or a real tenant to test.
func graphUsers(ctx context.Context, client *http.Client, graphBase, token string) ([]GraphUser, error) {
	// Server-side filtering on the two properties that support a plain filter, and
	// $select so a tenant of twenty thousand does not send twenty thousand full user
	// objects. `mail ne null` is deliberately *not* in the filter: a negation on a
	// nullable property needs the advanced query parameters, which not every tenant
	// accepts, and getting that wrong fails the whole walk. It is applied here
	// instead, where it costs nothing.
	next := graphBase + "/v1.0/users?" + url.Values{
		"$select": {"id,displayName,userPrincipalName,mail,accountEnabled,userType"},
		"$filter": {"accountEnabled eq true"},
		"$top":    {"999"},
	}.Encode()

	var out []GraphUser
	for page := 0; next != "" && page < maxDirectoryPages; page++ {
		// Every page after the first is a URL Microsoft gave us. Checking it still
		// points at the Graph host keeps a redirected or tampered response from
		// turning this loop into a request to somewhere else carrying our token.
		if !strings.HasPrefix(next, graphBase+"/") {
			return nil, fmt.Errorf("the directory listing tried to continue at %s, which is "+
				"not %s", shortURL(next), graphBase)
		}

		body, err := graphGet(ctx, client, next, token)
		if err != nil {
			return nil, err
		}
		var parsed struct {
			Value []struct {
				ID                string `json:"id"`
				DisplayName       string `json:"displayName"`
				UserPrincipalName string `json:"userPrincipalName"`
				Mail              string `json:"mail"`
				AccountEnabled    *bool  `json:"accountEnabled"`
				UserType          string `json:"userType"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("the directory listing could not be read: %w", err)
		}
		for _, u := range parsed.Value {
			out = append(out, GraphUser{
				ID:                u.ID,
				DisplayName:       u.DisplayName,
				UserPrincipalName: u.UserPrincipalName,
				Mail:              u.Mail,
				AccountEnabled:    u.AccountEnabled == nil || *u.AccountEnabled,
				UserType:          u.UserType,
			})
		}
		next = parsed.NextLink
	}
	return out, nil
}

// graphAppToken gets a client-credentials token for the Graph API.
func graphAppToken(ctx context.Context, client *http.Client, loginBase, graphBase string, app *store.GraphApp) (string, error) {
	form := url.Values{
		"client_id":     {app.ClientID},
		"client_secret": {app.ClientSecret},
		"scope":         {graphBase + "/.default"},
		"grant_type":    {"client_credentials"},
	}
	endpoint := loginBase + "/" + url.PathEscape(app.DirectoryID) + "/oauth2/v2.0/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", loginBase, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode/100 != 2 {
		// Microsoft's own description, which names the actual problem — an expired
		// secret, a wrong directory id, consent never granted. Anything this code
		// substituted would be a guess.
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Description != "" {
			return "", fmt.Errorf("Microsoft refused the application's credentials: %s",
				firstLine(e.Description))
		}
		return "", fmt.Errorf("Microsoft refused the application's credentials (HTTP %d)", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("the token response from %s could not be read", loginBase)
	}
	return tok.AccessToken, nil
}

// graphGet performs one authenticated GET.
func graphGet(ctx context.Context, client *http.Client, endpoint, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach Microsoft Graph: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))

	switch {
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusUnauthorized:
		return nil, errNeedsUserRead
	case resp.StatusCode/100 != 2:
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error.Message != "" {
			return nil, fmt.Errorf("Microsoft Graph refused the request: %s", firstLine(e.Error.Message))
		}
		return nil, fmt.Errorf("Microsoft Graph refused the request (HTTP %d)", resp.StatusCode)
	}
	return body, nil
}

// shortURL keeps a refusal message readable when the URL is a Graph skip token, which
// runs to hundreds of characters.
func shortURL(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// ---------------------------------------------------------------------------
// Over HTTP
// ---------------------------------------------------------------------------

// listGraphDirectory walks the tenant's directory and reports what could be collected.
//
// Admin only, and a read. It is a listing of every account in the organisation, which
// is not a thing an analyst has any reason to pull, and it spends a call against
// somebody's Microsoft tenant.
func (a *API) listGraphDirectory(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	users, err := a.graphDirectory(ctx, tenant)
	if err != nil {
		// A refusal from Microsoft is the administrator's problem to fix, not a
		// fault in this deployment, so it is a 400 carrying the explanation rather
		// than a 500 that reads as "this broke".
		fail(w, http.StatusBadGateway, err)
		return
	}

	// Which of them are already here. Marked rather than removed — see GraphUser.
	configured, err := a.store.Mailboxes(ctx, tenant, false)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	have := map[string]bool{}
	for _, m := range configured {
		have[strings.ToLower(m.Address)] = true
	}

	out := make([]GraphUser, 0, len(users))
	var mailboxes, alreadyHave int
	for _, u := range users {
		if !u.Mailboxable() {
			continue
		}
		u.Configured = have[strings.ToLower(u.Mail)]
		if u.Configured {
			alreadyHave++
		}
		mailboxes++
		out = append(out, u)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"users": out,
		// The three numbers together are the sentence the page needs to say:
		// "460 accounts in the directory, 431 with a mailbox, 412 already collected".
		// Any one of them alone is misleading.
		"accounts_in_directory": len(users),
		"with_mailboxes":        mailboxes,
		"already_configured":    alreadyHave,
	})
}

// addGraphMailboxes configures several mailboxes from the directory at once.
//
// The addresses are sent back by the console rather than re-walked here, so what gets
// added is what the administrator saw and chose. A second walk could return a different
// list — somebody joins, somebody is disabled — and adding accounts nobody looked at is
// exactly the surprise this feature must not produce.
func (a *API) addGraphMailboxes(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Addresses []string `json:"addresses"`

		// Enabled says whether to start collecting immediately. Defaulting to true
		// is right — an administrator who picked four hundred mailboxes means to
		// collect from them — but adding them paused is offered, because pointing a
		// new deployment at an entire estate at once is a reasonable thing to want
		// to stage.
		Enabled *bool `json:"enabled"`

		// Remediate is not accepted here, deliberately. Letting an automated verdict
		// delete mail is a decision per mailbox, and a bulk form with a tick box
		// would grant it to four hundred at once from a screen whose subject is
		// onboarding. It stays where it is: the mailbox form, one at a time.
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBody)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if len(in.Addresses) == 0 {
		fail(w, http.StatusBadRequest, fmt.Errorf("no addresses were given"))
		return
	}
	if len(in.Addresses) > maxBulkMailboxes {
		fail(w, http.StatusBadRequest, fmt.Errorf(
			"%d mailboxes in one request; the limit is %d", len(in.Addresses), maxBulkMailboxes))
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	app, err := a.store.GraphApp(ctx, tenant, false)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if app == nil || !app.Configured() {
		fail(w, http.StatusBadRequest, fmt.Errorf(
			"no Microsoft 365 application registration is configured, so these mailboxes "+
				"would have nothing to authenticate with"))
		return
	}

	enabled := in.Enabled == nil || *in.Enabled
	boxes := make([]store.Mailbox, 0, len(in.Addresses))
	for _, addr := range in.Addresses {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		boxes = append(boxes, store.Mailbox{
			TenantID: tenant,
			Kind:     "graph",
			Address:  addr,
			// The user principal name Graph is addressed by. The mail address is
			// what Microsoft reported as primary, and addressing /users/{upn} by it
			// works for the overwhelming majority; where they differ the console
			// sends the principal name.
			GraphUser: addr,
			Enabled:   enabled,
			// Off, and not offered above. Observing an estate is the safe default;
			// letting it delete mail is a separate, deliberate act.
			Remediate: false,
		})
	}

	added, skipped, err := a.store.AddMailboxes(ctx, tenant, boxes)
	if err != nil {
		// Partial success is reported as a failure *with* what was added, because
		// the administrator needs both halves: the count that worked and the one
		// that did not.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(), "added": len(added), "skipped": skipped,
		})
		return
	}

	// New mailboxes change $recipient_emails, which 45 rules read. Rebuilt once for
	// the whole batch rather than once per mailbox — the single-mailbox form does it
	// per save, and four hundred of those would be four hundred rebuilds.
	if err := a.lists.Rebuild(ctx); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"added":   len(added),
		"skipped": skipped,
		"enabled": enabled,
	})
}

// maxBulkMailboxes bounds one bulk add. Well above any plausible estate, and low enough
// that a malformed request cannot ask the engine to write a million rows.
const maxBulkMailboxes = 5000

// setMailboxEnabled pauses or resumes one mailbox.
func (a *API) setMailboxEnabled(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	switch err := a.store.SetMailboxEnabled(ctx, tenant, r.PathValue("id"), in.Enabled); {
	case errors.Is(err, store.ErrNoMailbox):
		fail(w, http.StatusNotFound, err)
		return
	case err != nil:
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// $recipient_emails is built from configured mailboxes, and a paused mailbox is
	// still one of this organisation's addresses — mail to it is still inbound, and
	// the rules that ask "is this one of ours" should still say yes. Rebuilt anyway,
	// because the list is derived and the cheapest way to be sure it matches the
	// table is to derive it again.
	if err := a.lists.Rebuild(ctx); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": in.Enabled})
}
