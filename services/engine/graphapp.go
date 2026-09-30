// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// The Microsoft 365 application registration, over HTTP.
//
// Three endpoints and a deliberate asymmetry between two of them, which is the same
// asymmetry mailbox credentials have:
//
//   - An administrator in a browser may write the registration and read everything
//     about it except the client secret. A session is a thing that can be stolen,
//     and a stolen session that can read a client secret is a stolen tenant.
//   - A connector authenticating with a service token may read the secret, because
//     it has to present it to Microsoft. Nothing else may.
//
// Before this, the directory and client ids were command-line flags on the mail
// connector, which meant onboarding Microsoft 365 was a redeploy — and meant the one
// remaining thing in the platform that an administrator could not do from the web
// interface.

// getGraphApp returns the registration without its secret.
func (a *API) getGraphApp(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	app, err := a.store.GraphApp(store.WithTenant(r.Context(), tenant), tenant, false)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if app == nil {
		// Not an error: a deployment with no Microsoft mailboxes has no
		// registration, and the settings page needs to render an empty form
		// rather than a failure. The derived callback still goes out, because
		// the page shows it whether or not a registration exists — it is what
		// the administrator has to allow through their proxy.
		writeJSON(w, http.StatusOK, store.GraphApp{NotifyURL: graphNotifyURL(a.publicBase)})
		return
	}
	// Derived, never stored: one deployment-wide public URL, and the path is
	// ours. See publicurl.go for why this is not a form field.
	app.NotifyURL = graphNotifyURL(a.publicBase)

	// Belt and braces. GraphApp(false) does not decrypt, and this makes it
	// impossible for a later change to that function to leak through here.
	app.ClientSecret = ""
	app.ClientState = ""
	writeJSON(w, http.StatusOK, app)
}

// updateGraphApp stores the registration.
func (a *API) updateGraphApp(w http.ResponseWriter, r *http.Request) {
	var in store.GraphApp
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	if err := a.store.SaveGraphApp(ctx, tenant, in, callerName(r)); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	// Recorded, because this is a credential change with tenant-wide reach: it is
	// the identity every Microsoft mailbox authenticates as.
	_ = a.store.RecordAction(ctx, tenant, "", "graph-app-updated", callerName(r), "")

	app, err := a.store.GraphApp(ctx, tenant, false)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	app.NotifyURL = graphNotifyURL(a.publicBase)
	writeJSON(w, http.StatusOK, app)
}

// deleteGraphApp forgets the registration.
func (a *API) deleteGraphApp(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	if err := a.store.DeleteGraphApp(ctx, tenant); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	_ = a.store.RecordAction(ctx, tenant, "", "graph-app-removed", callerName(r), "")
	w.WriteHeader(http.StatusNoContent)
}

// graphAppSecrets returns the registration including its secret, for a connector.
//
// Service tokens only, enforced the same way mailbox credentials are: a signed-in
// browser session is refused outright rather than filtered, so the rule is one
// comparison rather than a property of what happens to be serialised.
func (a *API) graphAppSecrets(w http.ResponseWriter, r *http.Request) {
	caller := CallerFrom(r.Context())
	if caller == nil || caller.Service == "" {
		fail(w, http.StatusForbidden, errors.New(
			"this endpoint is for service tokens; a signed-in session cannot read the client secret"))
		return
	}

	tenant := a.tenantOf(r)
	app, err := a.store.GraphApp(store.WithTenant(r.Context(), tenant), tenant, true)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if app == nil {
		// No registration configured. 204 rather than an error: a connector asks
		// on a timer and a deployment with no Microsoft mailboxes never will have
		// one.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// The connector is told where Microsoft should call, rather than working it
	// out: the engine owns the deployment's public identity, and two services
	// deriving the same URL independently is two places for it to drift.
	app.NotifyURL = graphNotifyURL(a.publicBase)
	writeJSON(w, http.StatusOK, app)
}
