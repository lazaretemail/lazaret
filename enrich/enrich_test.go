// SPDX-License-Identifier: AGPL-3.0-only

package enrich_test

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
)

func TestUnavailableIsErrUnavailable(t *testing.T) {
	// Callers must be able to distinguish "capability missing" from a genuine failure with
	// errors.Is alone, however the error was constructed and however deeply it is wrapped.
	cases := map[string]error{
		"NotImplemented": enrich.NotImplemented(enrich.CapMLLinkAnalysis),
		"Unavailablef":   enrich.Unavailablef(enrich.CapNetworkWhois, "dial timeout"),
		"with cause":     &enrich.Unavailable{Capability: enrich.CapFileExplode, Err: errors.New("no route to host")},
		"wrapped":        fmt.Errorf("evaluating rule: %w", enrich.NotImplemented(enrich.CapBetaOCR)),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(err, enrich.ErrUnavailable) {
				t.Errorf("errors.Is(%v, ErrUnavailable) = false, want true", err)
			}
		})
	}

	if errors.Is(errors.New("parse error"), enrich.ErrUnavailable) {
		t.Error("an unrelated error matched ErrUnavailable")
	}
}

func TestUnavailableUnwrapsCause(t *testing.T) {
	cause := errors.New("connection refused")
	err := &enrich.Unavailable{Capability: enrich.CapMLNLUClassifier, Reason: "dialing lazaret-ml", Err: cause}

	if !errors.Is(err, cause) {
		t.Error("the underlying cause is not recoverable with errors.Is")
	}

	// The message has to name the capability: it is what a rule author greps for.
	want := "ml.nlu_classifier unavailable: dialing lazaret-ml: connection refused"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestTrackerDeduplicatesAndSorts(t *testing.T) {
	var tr enrich.Tracker

	if tr.Any() {
		t.Error("a fresh Tracker reports missing capabilities")
	}
	if got := tr.Missing(); got != nil {
		t.Errorf("Missing() on a fresh Tracker = %v, want nil", got)
	}

	// Several hundred rules asking for the same capability should be reported once.
	for range 200 {
		tr.Record(enrich.CapMLLinkAnalysis)
	}
	tr.Record(enrich.CapNetworkWhois)
	tr.Record(enrich.CapFileExplode)

	want := []enrich.Capability{
		enrich.CapFileExplode,
		enrich.CapMLLinkAnalysis,
		enrich.CapNetworkWhois,
	}
	if got := tr.Missing(); !slices.Equal(got, want) {
		t.Errorf("Missing() = %v, want %v", got, want)
	}
	if !tr.Any() {
		t.Error("Any() = false after recording capabilities")
	}
}

func TestNilTrackerIsUsable(t *testing.T) {
	// Evaluation paths that do not care about reporting should not have to allocate one,
	// nor guard every call site with a nil check.
	var tr *enrich.Tracker
	tr.Record(enrich.CapFileExplode)
	if tr.Any() {
		t.Error("a nil Tracker reports missing capabilities")
	}
	if got := tr.Missing(); got != nil {
		t.Errorf("Missing() on a nil Tracker = %v, want nil", got)
	}
}

func TestTrackerIsConcurrencySafe(t *testing.T) {
	// Rules within a run may be evaluated in parallel; this fails under -race if not.
	var tr enrich.Tracker
	caps := []enrich.Capability{enrich.CapMLLogoDetect, enrich.CapBetaScanQR, enrich.CapProfileBySender}

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Record(caps[i%len(caps)])
			_ = tr.Missing()
		}()
	}
	wg.Wait()

	if got := len(tr.Missing()); got != len(caps) {
		t.Errorf("Missing() returned %d capabilities, want %d", got, len(caps))
	}
}
