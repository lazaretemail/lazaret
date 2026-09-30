// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Only accounts with a mailbox behind them are offered.
//
// The directory is not a list of mailboxes. It holds unlicensed accounts, synced
// objects and service principals with no Exchange mailbox at all, guests whose mail
// lives in someone else's tenant, and disabled accounts. Offering those to an
// administrator who is about to press "add all" would configure collection from things
// that cannot be collected from, and every one of them would then sit on the settings
// page reporting an error.
func TestOnlyRealMailboxesAreOffered(t *testing.T) {
	cases := []struct {
		name string
		user GraphUser
		want bool
	}{
		{"a licensed member", GraphUser{
			Mail: "dana@example.test", AccountEnabled: true, UserType: "Member"}, true},
		{"no mail address, so no mailbox", GraphUser{
			UserPrincipalName: "svc-backup@example.test", AccountEnabled: true, UserType: "Member"}, false},
		{"disabled in the directory", GraphUser{
			Mail: "leaver@example.test", AccountEnabled: false, UserType: "Member"}, false},
		{"a guest, whose mail is in another tenant", GraphUser{
			Mail: "partner@other.test", AccountEnabled: true, UserType: "Guest"}, false},
		// Microsoft is inconsistent about the case of this value, and a shared
		// mailbox often reports an empty userType rather than "Member".
		{"a guest in lower case", GraphUser{
			Mail: "partner@other.test", AccountEnabled: true, UserType: "guest"}, false},
		{"a shared mailbox with no userType", GraphUser{
			Mail: "invoices@example.test", AccountEnabled: true}, true},
	}
	for _, c := range cases {
		if got := c.user.Mailboxable(); got != c.want {
			t.Errorf("%s: offered=%v, want %v", c.name, got, c.want)
		}
	}
}

// Each sovereign cloud gets its own hosts.
//
// Hardcoding the public cloud makes the platform silently unusable for a whole class of
// tenant: a GCC High deployment would send its token request to a host its tenant does
// not exist on, and be told so in a message about the application rather than about the
// endpoint.
func TestEachCloudHasItsOwnHosts(t *testing.T) {
	seen := map[string]bool{}
	for _, cloud := range []string{store.CloudPublic, store.CloudUSGov, store.CloudUSGovDoD, store.CloudChina} {
		graph, login := store.GraphApp{Cloud: cloud}.Hosts()
		if graph == "" || login == "" {
			t.Fatalf("%s has no hosts", cloud)
		}
		if seen[graph] {
			t.Errorf("%s reuses the Graph host %s of another cloud", cloud, graph)
		}
		seen[graph] = true
	}

	// Empty means public, because that is what every row written before the column
	// existed meant.
	blank, blankLogin := store.GraphApp{}.Hosts()
	pub, pubLogin := store.GraphApp{Cloud: store.CloudPublic}.Hosts()
	if blank != pub || blankLogin != pubLogin {
		t.Errorf("an unset cloud resolved to %s, not the public cloud %s", blank, pub)
	}

	// A typo falls back rather than failing. Mail collection must not stop because
	// somebody mistyped a configuration field.
	if odd, _ := (store.GraphApp{Cloud: "gcc-high"}).Hosts(); odd != pub {
		t.Errorf("an unknown cloud resolved to %s rather than falling back to the public cloud", odd)
	}
}

// A cloud that is not one of the known values is refused on the way in.
//
// The fallback above keeps a bad value from breaking collection; this keeps a bad value
// from being stored in the first place. Both matter: the first is about surviving one,
// the second about not acquiring one.
func TestAnUnknownCloudIsNotStored(t *testing.T) {
	for _, ok := range []string{"", store.CloudPublic, store.CloudUSGov, store.CloudUSGovDoD, store.CloudChina} {
		if !store.ValidCloud(ok) {
			t.Errorf("%q was refused and should not have been", ok)
		}
	}
	for _, bad := range []string{"gcc", "GCCHigh", "azure", "public "} {
		if store.ValidCloud(bad) {
			t.Errorf("%q was accepted as a Microsoft cloud", bad)
		}
	}
}

// A tenant larger than one page is read whole.
//
// Graph caps a page at 999 and hands back a continuation link. A walk that stops at the
// first page silently offers an administrator the first 999 of their 4,000 accounts and
// gives no sign that the rest exist — which looks exactly like a small tenant.
func TestTheDirectoryIsPagedToTheEnd(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("page requested without the token: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `{"value":[
				{"id":"3","mail":"c@example.test","accountEnabled":true,"userType":"Member"}]}`)
			return
		}
		fmt.Fprintf(w, `{"value":[
			{"id":"1","mail":"a@example.test","accountEnabled":true,"userType":"Member"},
			{"id":"2","mail":"b@example.test","accountEnabled":true,"userType":"Member"}],
			"@odata.nextLink":%q}`, base+"/v1.0/users?page=2")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	got, err := graphUsers(t.Context(), srv.Client(), srv.URL, "tok")
	if err != nil {
		t.Fatalf("walking: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d accounts across two pages, want 3", len(got))
	}
	if got[2].Mail != "c@example.test" {
		t.Errorf("the second page was not read: last account is %s", got[2].Mail)
	}
}

// A continuation link pointing somewhere else is refused.
//
// nextLink is a URL taken from a response and followed in a loop with a bearer token
// attached. Following one to another host would hand a token that can read the whole
// directory to whoever supplied the link.
func TestAContinuationLinkOffTheGraphHostIsRefused(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the walk followed a link to another host, sending it %q",
			r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer evil.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"value":[{"id":"1","mail":"a@example.test","accountEnabled":true}],
			"@odata.nextLink":%q}`, evil.URL+"/v1.0/users?page=2")
	}))
	defer srv.Close()

	_, err := graphUsers(t.Context(), srv.Client(), srv.URL, "tok")
	if err == nil {
		t.Fatal("a continuation link to another host was followed")
	}
	if !strings.Contains(err.Error(), "not "+srv.URL) {
		t.Errorf("the refusal does not say where it was asked to go: %v", err)
	}
}

// Being allowed to read mail but not the directory says exactly that.
//
// The permissions are separate consents: Mail.Read collects mail, User.Read.All lists
// accounts. A tenant with the first and not the second gets a 403 here while collection
// works perfectly — and an administrator reading "403 Forbidden" will go and check the
// client secret they just pasted correctly.
func TestMissingDirectoryPermissionNamesThePermission(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusUnauthorized} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":{"code":"Authorization_RequestDenied"}}`, code)
		}))
		_, err := graphUsers(t.Context(), srv.Client(), srv.URL, "tok")
		srv.Close()

		if !errors.Is(err, errNeedsUserRead) {
			t.Fatalf("HTTP %d reported as %v", code, err)
		}
		if !strings.Contains(err.Error(), "User.Read.All") {
			t.Errorf("HTTP %d does not name the permission to grant: %v", code, err)
		}
		if !strings.Contains(err.Error(), "Mail collection is unaffected") {
			t.Errorf("HTTP %d does not say collection still works: %v", code, err)
		}
	}
}

// Microsoft's own refusal is passed through rather than replaced.
//
// An expired client secret, a wrong directory id and consent never granted are three
// different problems with three different fixes, and Microsoft names which. Anything
// this code substituted would be a guess that sends someone to check the wrong thing.
func TestMicrosoftsOwnRefusalIsWhatTheAdminSees(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"AADSTS7000222: `+
			`The provided client secret keys for app are expired.\r\nTrace ID: abc"}`)
	}))
	defer srv.Close()

	_, err := graphAppToken(t.Context(), srv.Client(), srv.URL, srv.URL,
		&store.GraphApp{DirectoryID: "d", ClientID: "c", ClientSecret: "s"})
	if err == nil {
		t.Fatal("an expired secret was accepted")
	}
	if !strings.Contains(err.Error(), "AADSTS7000222") {
		t.Errorf("Microsoft's own diagnosis was dropped: %v", err)
	}
	// Only the first line: the trace id is several hundred characters of noise that
	// pushes the sentence that matters off the screen.
	if strings.Contains(err.Error(), "Trace ID") {
		t.Errorf("the refusal carries Microsoft's trace noise: %v", err)
	}
}
