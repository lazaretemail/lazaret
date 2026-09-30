// SPDX-License-Identifier: AGPL-3.0-only

package container

import "testing"

// Budget must never answer with a share of the host.
//
// This is the whole reason the package exists. DuckDB's own default is 80% of
// system RAM: on the 30GB machine this was written against, the engine would size
// itself at 24GB while sharing the box with twelve other containers, and nothing
// would report a fault — the host would simply run out of memory.
func TestBudgetFallsBackToAFixedNumber(t *testing.T) {
	const fallback = 2 << 30
	got := Budget(0.33, fallback, 512<<20, 16<<30)

	if limit := MemoryLimit(); limit == 0 {
		if got != fallback {
			t.Errorf("with no cgroup limit, Budget = %dMB, want the fallback %dMB",
				got>>20, fallback>>20)
		}
		return
	}
	// In a container, it is a share of the container.
	if got > MemoryLimit() {
		t.Errorf("Budget = %dMB, more than the container's %dMB",
			got>>20, MemoryLimit()>>20)
	}
}

func TestBudgetClamps(t *testing.T) {
	// A share is still bounded at both ends: a tiny container must not be given a
	// budget too small to work in, and a huge one must not be handed everything
	// just because it is there.
	if got := Budget(0.33, 64<<20, 512<<20, 16<<30); got < 512<<20 {
		t.Errorf("Budget = %dMB, below the 512MB floor", got>>20)
	}
	if got := Budget(0.33, 1<<40, 512<<20, 16<<30); got > 16<<30 {
		t.Errorf("Budget = %dMB, above the 16GB ceiling", got>>20)
	}
}

func TestCPUsIsAtLeastOne(t *testing.T) {
	if got := CPUs(); got < 1 {
		t.Errorf("CPUs() = %d", got)
	}
}

// A quota that is not a whole number of cores rounds up, because a thread pool of
// zero does no work and 1.5 cores can usefully run two threads.
func TestCPUsRoundsUp(t *testing.T) {
	for _, tc := range []struct{ quota, period, want int64 }{
		{150000, 100000, 2}, // 1.5 cores
		{100000, 100000, 1},
		{50000, 100000, 1}, // half a core is still one thread
		{400000, 100000, 4},
	} {
		got := (tc.quota + tc.period - 1) / tc.period
		if got != tc.want {
			t.Errorf("quota %d / period %d = %d, want %d",
				tc.quota, tc.period, got, tc.want)
		}
	}
}
