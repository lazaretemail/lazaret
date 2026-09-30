// SPDX-License-Identifier: AGPL-3.0-only

// Package lists resolves the named lists rules reference with `$name`.
//
// Lists come from three places, and the difference matters. Static data — free email
// providers, URL shorteners, file extension families — is published by Sublime under an
// MIT licence at github.com/sublime-security/static-files and can simply be shipped.
// Org-scoped lists ($org_domains, $org_vips) come from the deployment's own configuration.
// The rest are history- or feed-backed and belong to a later module.
//
// # Unconfigured is not empty
//
// A list nobody has configured answers "I do not know", never "no". Rules depend on lists
// the way they depend on fields, and quietly treating a missing list as empty switches off
// every rule that uses it with no sign that anything is wrong. Contains therefore reports
// whether the list is known at all, and the evaluator turns an unknown list into null.
package lists

import (
	"context"
	"strings"
	"sync"

	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
)

// Set is one named list.
type Set struct {
	Name string

	// values holds the entries, lower-cased for the case-insensitive lookups that most
	// rules use.
	values map[string]bool

	// ordered preserves the entries for rules that iterate a list rather than test
	// membership.
	ordered []string
}

// NewSet builds a list from its entries.
func NewSet(name string, entries []string) *Set {
	s := &Set{Name: name, values: make(map[string]bool, len(entries))}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		s.ordered = append(s.ordered, e)
		s.values[strings.ToLower(e)] = true
	}
	return s
}

// Len reports how many entries the list holds.
func (s *Set) Len() int { return len(s.ordered) }

// Has reports membership. Lookups are case-insensitive by default because domains, file
// extensions and email addresses — which is almost everything in a list — are.
func (s *Set) Has(value string) bool { return s.values[strings.ToLower(value)] }

// Resolver is the standard list resolver.
type Resolver struct {
	mu   sync.RWMutex
	sets map[string]*Set
}

// NewResolver returns an empty resolver. Every list is unknown until added, which is the
// honest starting state.
func NewResolver() *Resolver {
	return &Resolver{sets: map[string]*Set{}}
}

// Add registers a list, replacing any existing one of the same name.
func (r *Resolver) Add(set *Set) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets[set.Name] = set
}

// Names lists the configured lists.
func (r *Resolver) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.sets))
	for n := range r.sets {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// Known reports whether a list is configured.
func (r *Resolver) Known(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sets[name]
	return ok
}

// Contains implements mql.ListResolver.
func (r *Resolver) Contains(_ context.Context, name string, value mql.Value, fold bool) (found, known bool) {
	r.mu.RLock()
	set, ok := r.sets[name]
	r.mu.RUnlock()
	if !ok {
		return false, false
	}
	s, ok := value.AsString()
	if !ok {
		// A null or non-textual value is not in any list, but the list itself is known,
		// so the answer is a definite no rather than an unknown.
		return false, true
	}
	return set.Has(s), true
}

// Elements implements mql.ListResolver.
func (r *Resolver) Elements(_ context.Context, name string) ([]mql.Value, bool) {
	r.mu.RLock()
	set, ok := r.sets[name]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	out := make([]mql.Value, len(set.ordered))
	for i, e := range set.ordered {
		out[i] = mql.StringValue(e)
	}
	return out, true
}

// AddOrgLists registers the lists derived from an organisation's own configuration.
//
// These are the ones no feed can provide: only the deployment knows which domains are its
// own, and $org_domains alone appears in 211 corpus rules.
func (r *Resolver) AddOrgLists(cfg *orgconfig.Config) {
	if cfg == nil {
		return
	}
	r.Add(NewSet("org_domains", cfg.DomainList()))
	r.Add(NewSet("org_slds", cfg.SLDList()))
	r.Add(NewSet("tenant_domains", cfg.DomainList()))
	r.Add(NewSet("org_display_names", cfg.DisplayNameList()))
	r.Add(NewSet("org_vips", cfg.VIPEmailList()))
}

// LoadDir registers every list file in a directory.
//
// The layout is the one sublime-security/static-files uses: one file per list, named
// after it, one entry per line. `.csv` files there are ranked domain lists whose first
// column is the rank, so only the second column is taken.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
