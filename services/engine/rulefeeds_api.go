// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// The rule feed API.
//
// Admin only, and the token is never read back. A feed's access token follows the
// same rule as a mailbox credential: it goes in, it is used by the engine, and no
// response ever contains it — the console is told whether one is stored and
// nothing more.

func (a *API) listRuleFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := a.store.RuleFeeds(r.Context(), a.tenantOf(r), false)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	if feeds == nil {
		feeds = []store.RuleFeed{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": feeds})
}

func (a *API) saveRuleFeed(w http.ResponseWriter, r *http.Request) {
	var in struct {
		store.RuleFeed
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBody)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	feed := in.RuleFeed
	feed.TenantID = a.tenantOf(r)
	feed.Secret = in.Secret
	if feed.ID != "" {
		// Updating: confirm it is this tenant's before writing, so an id from
		// somewhere else is a 404 rather than a silent create.
		if _, err := a.store.RuleFeed(r.Context(), feed.TenantID, feed.ID, false); err != nil {
			a.feedError(w, err)
			return
		}
	}

	saved, err := a.store.SaveRuleFeed(r.Context(), feed)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (a *API) deleteRuleFeed(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	if err := a.store.DeleteRuleFeed(r.Context(), tenant, r.PathValue("id")); err != nil {
		a.feedError(w, err)
		return
	}
	// The clone is left on disk deliberately. Deleting a feed should not be able to
	// remove a directory tree because of a bad id, and a stale clone costs disk
	// rather than correctness — nothing loads it once the row is gone.
	if a.feeds != nil {
		if _, err := a.feeds.Reload(r.Context()); err != nil {
			// The feed is gone either way; the running rule set is simply still the
			// old one until the next successful reload.
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reload_error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// syncRuleFeed pulls one feed now, rather than waiting for its schedule.
//
// Synchronous, because an admin who has just fixed a token wants to know whether it
// worked, and a job id they have to poll is a worse answer than waiting a few
// seconds for the truth.
func (a *API) syncRuleFeed(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	feed, err := a.store.RuleFeed(r.Context(), tenant, r.PathValue("id"), true)
	if err != nil {
		a.feedError(w, err)
		return
	}
	if a.feeds == nil {
		fail(w, http.StatusServiceUnavailable, errors.New("rule feeds are not configured on this engine"))
		return
	}

	if err := a.feeds.SyncOne(r.Context(), *feed); err != nil {
		// 200 with the error on the feed, not a 5xx: the request succeeded, the
		// sync did not, and the console needs to render that distinction.
		after, _ := a.store.RuleFeed(r.Context(), tenant, feed.ID, false)
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "feed": after})
		return
	}

	loaded, reloadErr := a.feeds.Reload(r.Context())
	after, _ := a.store.RuleFeed(r.Context(), tenant, feed.ID, false)
	out := map[string]any{"ok": true, "feed": after, "rules_loaded": loaded}
	if reloadErr != nil {
		out["reload_error"] = reloadErr.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) feedError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNoFeed) {
		fail(w, http.StatusNotFound, err)
		return
	}
	fail(w, http.StatusBadGateway, err)
}
