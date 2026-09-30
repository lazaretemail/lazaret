// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"
)

func state(name string, ok bool, rules int) CapabilityState {
	return CapabilityState{Capability: name, OK: ok, Rules: rules}
}

func probeNames(hs []CapabilityState) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.Capability)
	}
	return out
}

// The first probe establishes a baseline. Reporting every capability as having just
// changed would make the very first line after start-up the noisiest one in the log.
func TestFirstProbeIsNotATransition(t *testing.T) {
	was := map[string]bool{}
	recovered, lost := capabilityTransitions(was, []CapabilityState{
		state("ml.link_analysis", false, 130),
		state("file.explode", true, 305),
	})
	if len(recovered) != 0 || len(lost) != 0 {
		t.Errorf("first probe reported transitions: recovered=%v lost=%v", probeNames(recovered), probeNames(lost))
	}
	if len(was) != 2 {
		t.Errorf("baseline not recorded: %v", was)
	}
}

// The case this exists for: the engine probes while the renderer is still starting,
// reports 237 rules dead, and must say so when they come back. Before this, that
// first alarming line stayed in the log uncorrected.
func TestRecoveryIsReported(t *testing.T) {
	was := map[string]bool{}
	down := []CapabilityState{
		state("ml.link_analysis", false, 130),
		state("file.message_screenshot", false, 100),
		state("file.html_screenshot", false, 7),
	}
	capabilityTransitions(was, down) // baseline: everything down

	up := []CapabilityState{
		state("ml.link_analysis", true, 130),
		state("file.message_screenshot", true, 100),
		state("file.html_screenshot", true, 7),
	}
	recovered, lost := capabilityTransitions(was, up)

	if len(recovered) != 3 {
		t.Fatalf("recovered %v, want all three", probeNames(recovered))
	}
	if len(lost) != 0 {
		t.Errorf("reported losses on a recovery: %v", probeNames(lost))
	}
	total := 0
	for _, h := range recovered {
		total += h.Rules
	}
	if total != 237 {
		t.Errorf("recovered %d rules, want 237", total)
	}
	if n := countDown(was); n != 0 {
		t.Errorf("%d capabilities still marked down after recovery", n)
	}
}

// A renderer that dies at three in the morning takes 237 rules with it, and the
// only signal today is that results quietly turn indeterminate.
func TestLossIsReported(t *testing.T) {
	was := map[string]bool{}
	capabilityTransitions(was, []CapabilityState{state("ml.link_analysis", true, 130)})

	recovered, lost := capabilityTransitions(was, []CapabilityState{state("ml.link_analysis", false, 130)})
	if len(lost) != 1 || lost[0].Rules != 130 {
		t.Fatalf("lost %v, want ml.link_analysis with 130 rules", probeNames(lost))
	}
	if len(recovered) != 0 {
		t.Errorf("reported a recovery on a loss: %v", probeNames(recovered))
	}
}

// Steady state must be silent. A line every minute saying nothing changed is how an
// operator learns to stop reading the log.
func TestNoChangeIsSilent(t *testing.T) {
	was := map[string]bool{}
	same := []CapabilityState{state("file.explode", true, 305), state("beta.ocr", false, 67)}
	capabilityTransitions(was, same)

	for i := 0; i < 5; i++ {
		recovered, lost := capabilityTransitions(was, same)
		if len(recovered) != 0 || len(lost) != 0 {
			t.Fatalf("probe %d reported a change when nothing changed", i)
		}
	}
}
