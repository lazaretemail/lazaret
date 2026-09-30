// SPDX-License-Identifier: AGPL-3.0-only

package rules_test

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rules"
)

// slowEnricher stands in for a service that waits: a browser fetching a link, an
// inference server, a registry. It records the highest number of calls in flight at
// once, which is the thing being tested.
type slowEnricher struct {
	delay    time.Duration
	inFlight atomic.Int32
	peak     atomic.Int32
	total    atomic.Int32
}

func (s *slowEnricher) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	n := s.inFlight.Add(1)
	for {
		p := s.peak.Load()
		if n <= p || s.peak.CompareAndSwap(p, n) {
			break
		}
	}
	defer s.inFlight.Add(-1)
	s.total.Add(1)

	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return mql.NullValue, ctx.Err()
	}
	return mql.StringValue("ok"), nil
}

// ruleSet builds n rules that each need an enrichment, with distinct arguments so the
// per-message cache cannot collapse them into one call.
func ruleSet(t *testing.T, n int) *rules.Engine {
	t.Helper()
	var ents []*rules.Entity
	for i := 0; i < n; i++ {
		ents = append(ents, &rules.Entity{
			Name:   fmt.Sprintf("rule %d", i),
			Type:   rules.KindRule,
			Source: fmt.Sprintf(`network.whois("host%d.example.invalid").found`, i),
		})
	}
	eng, errs := rules.New(ents, &rules.Options{})
	if len(errs) > 0 {
		t.Fatalf("building the engine: %v", errs)
	}
	return eng
}

// Rules that wait on a service must wait at the same time.
//
// Sequentially, sixteen rules each waiting 50ms take eight tenths of a second doing
// nothing. That is the whole shape of the problem this addresses: a real message spent
// ninety seconds almost entirely idle, waiting on one enrichment after another.
func TestRulesEvaluateConcurrently(t *testing.T) {
	eng := ruleSet(t, 16)
	svc := &slowEnricher{delay: 50 * time.Millisecond}
	msg := &mdm.MessageDataModel{}

	start := time.Now()
	eng.RunWith(context.Background(), msg, &rules.RunOptions{
		Enricher: mql.NewCache(svc),
	})
	elapsed := time.Since(start)

	if got := svc.peak.Load(); got < 2 {
		t.Errorf("peak concurrent enrichment calls = %d, want more than one — "+
			"the rules ran one after another", got)
	}
	// Sixteen 50ms waits in sequence is 800ms. Anything near that means no overlap.
	if elapsed > 500*time.Millisecond {
		t.Errorf("took %s for 16 rules waiting 50ms each; sequential would be ~800ms "+
			"and concurrent should be a fraction of it", elapsed)
	}
}

// The report must not depend on the scheduler.
//
// Parallel evaluation is only acceptable if it is invisible in the output: the same
// rules, in the same order, with the same verdicts. Anything else would make a
// detection report irreproducible, which is worse than slow.
func TestReportIsIdenticalWhateverTheConcurrency(t *testing.T) {
	eng := ruleSet(t, 24)
	msg := &mdm.MessageDataModel{}

	names := func(r *rules.Report) []string {
		var out []string
		for _, d := range r.Flagged {
			out = append(out, d.Entity.Name)
		}
		for _, d := range r.Indeterminate {
			out = append(out, "?"+d.Entity.Name)
		}
		return out
	}

	serial := eng.RunWith(context.Background(), msg, &rules.RunOptions{
		Enricher: mql.NewCache(&slowEnricher{}), Concurrency: 1,
	})
	for i := 0; i < 5; i++ {
		parallel := eng.RunWith(context.Background(), msg, &rules.RunOptions{
			Enricher: mql.NewCache(&slowEnricher{}), Concurrency: 8,
		})
		if !reflect.DeepEqual(names(serial), names(parallel)) {
			t.Fatalf("run %d differs from sequential evaluation:\n serial   %v\n parallel %v",
				i, names(serial), names(parallel))
		}
		if len(parallel.Missing) != len(serial.Missing) {
			t.Errorf("run %d: missing capabilities differ", i)
		}
	}
}

// Two rules asking the same question concurrently must produce one call, not two.
// The cache holds a sync.Once per entry precisely so that the second arrival waits
// on the first rather than racing it.
func TestConcurrentIdenticalCallsAreMadeOnce(t *testing.T) {
	var ents []*rules.Entity
	for i := 0; i < 12; i++ {
		ents = append(ents, &rules.Entity{
			Name:   fmt.Sprintf("rule %d", i),
			Type:   rules.KindRule,
			Source: `network.whois("same.example.invalid").found`,
		})
	}
	eng, errs := rules.New(ents, &rules.Options{})
	if len(errs) > 0 {
		t.Fatal(errs)
	}

	svc := &slowEnricher{delay: 20 * time.Millisecond}
	eng.RunWith(context.Background(), &mdm.MessageDataModel{}, &rules.RunOptions{
		Enricher: mql.NewCache(svc), Concurrency: 12,
	})

	if got := svc.total.Load(); got != 1 {
		t.Errorf("the provider was called %d times for one identical question, want 1", got)
	}
}
