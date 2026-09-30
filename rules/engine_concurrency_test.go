// SPDX-License-Identifier: AGPL-3.0-only

package rules

import "testing"

// Options.Concurrency was ignored: the field existed nowhere, RunWith read only
// RunOptions, and a deployment that set an engine-level value silently got the
// default. Precedence is per-run, then per-engine, then the measured default.
func TestConcurrencyPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine int
		run    int
		want   int
	}{
		{"neither set uses the measured default", 0, 0, defaultConcurrency},
		{"engine-level is honoured", 12, 0, 12},
		{"a run overrides the engine", 12, 3, 3},
		{"a zero run does not override", 12, 0, 12},
	} {
		e := &Engine{opts: Options{Concurrency: tc.engine}}
		var ro *RunOptions
		if tc.run > 0 {
			ro = &RunOptions{Concurrency: tc.run}
		}
		if got := e.concurrency(ro); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
