// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

func countingEnricher(calls *int) mql.Enricher {
	var mu sync.Mutex
	return mql.EnricherFunc(func(_ context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
		mu.Lock()
		*calls++
		mu.Unlock()
		return mql.StringValue("answer"), nil
	})
}

func TestCacheAnswersIdenticalCallsOnce(t *testing.T) {
	var calls int
	c := mql.NewCache(countingEnricher(&calls))

	att := mql.FromGo(&mdm.Attachment{FileName: mdm.Ptr("a.zip"), Raw: []byte("PK\x03\x04payload")})
	for range 500 {
		if _, err := c.Enrich(context.Background(), enrich.CapFileExplode, []mql.Value{att}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("provider called %d times, want 1 — this is the difference between one scan and one per rule", calls)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestCacheDistinguishesArgumentsAndCapabilities(t *testing.T) {
	var calls int
	c := mql.NewCache(countingEnricher(&calls))
	ctx := context.Background()

	one := mql.FromGo(&mdm.Attachment{FileName: mdm.Ptr("a.zip"), Raw: []byte("first")})
	two := mql.FromGo(&mdm.Attachment{FileName: mdm.Ptr("a.zip"), Raw: []byte("second")})

	// Same name, different bytes: different answer.
	c.Enrich(ctx, enrich.CapFileExplode, []mql.Value{one}, nil)
	c.Enrich(ctx, enrich.CapFileExplode, []mql.Value{two}, nil)
	// Same bytes, different capability.
	c.Enrich(ctx, enrich.CapBetaOCR, []mql.Value{one}, nil)
	// Same everything but a keyword argument.
	c.Enrich(ctx, enrich.CapFileExplode, []mql.Value{one}, map[string]mql.Value{"max_depth": mql.IntValue(5)})

	if calls != 4 {
		t.Errorf("provider called %d times, want 4", calls)
	}

	// Keyword order must not create a second entry.
	before := c.Len()
	c.Enrich(ctx, enrich.CapFileExplode, []mql.Value{one}, map[string]mql.Value{"max_depth": mql.IntValue(5)})
	if c.Len() != before {
		t.Error("an identical call with the same keywords created a new entry")
	}
}

// A service that is down stays down for the message. Retrying once per rule turns one
// outage into hundreds of timeouts and reaches the same verdict far more slowly.
func TestCacheRemembersUnavailability(t *testing.T) {
	var calls int
	inner := mql.EnricherFunc(func(_ context.Context, cap enrich.Capability, _ []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
		calls++
		return mql.NullValue, enrich.NotImplemented(cap)
	})
	c := mql.NewCache(inner)

	for range 100 {
		_, err := c.Enrich(context.Background(), enrich.CapMLNLUClassifier, nil, nil)
		if !mql.IsUnavailable(err) {
			t.Fatalf("err = %v, want unavailable", err)
		}
	}
	if calls != 1 {
		t.Errorf("provider called %d times, want 1", calls)
	}
}

func TestCacheIsSafeForConcurrentUse(t *testing.T) {
	var calls int
	c := mql.NewCache(countingEnricher(&calls))
	att := mql.FromGo(&mdm.Attachment{FileName: mdm.Ptr("a.zip"), Raw: []byte("payload")})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Enrich(context.Background(), enrich.CapFileExplode, []mql.Value{att}, nil)
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Errorf("provider called %d times under concurrency, want 1", calls)
	}
}

func TestCacheWithoutAnInnerEnricherIsUnavailable(t *testing.T) {
	c := mql.NewCache(nil)
	_, err := c.Enrich(context.Background(), enrich.CapBetaOCR, nil, nil)
	if !errors.Is(err, enrich.ErrUnavailable) {
		t.Errorf("err = %v, want unavailable", err)
	}
}
