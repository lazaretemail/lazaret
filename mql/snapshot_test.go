// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// A logo detection result, shaped like the one lazaret-ml returns: a struct with json
// tags, which is what every enricher hands back through mql.FromGo.
type brand struct {
	Name       string   `json:"name"`
	Confidence string   `json:"confidence"`
	Score      float64  `json:"score"`
	Sources    []string `json:"sources,omitempty"`
}

type logoResult struct {
	// Deliberately declared out of alphabetical order. encoding/json keeps struct
	// field order and sorts map keys, so a value and its own round trip marshal
	// differently unless something normalises them — which is what the cache key
	// depends on.
	Zone   string  `json:"zone"`
	Brands []brand `json:"brands"`
	Count  int     `json:"count"`
}

type recordingEnricher struct {
	calls   int
	answers map[enrich.Capability]func(args []mql.Value) (mql.Value, error)
}

func (r *recordingEnricher) Enrich(_ context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	r.calls++
	if fn, ok := r.answers[cap]; ok {
		return fn(args)
	}
	return mql.NullValue, enrich.NotImplemented(cap)
}

// A struct answer survives being frozen and replayed, and a rule reading it sees the
// same fields.
//
// Field names come from json tags on both sides — the schema derives an MQL field name
// with jsonName, and a replayed answer is a map keyed by the same tags — so the round
// trip is faithful rather than approximately faithful.
func TestSnapshotRoundTripsAStructAnswer(t *testing.T) {
	const cap = enrich.Capability("ml.logo_detect")
	live := &recordingEnricher{answers: map[enrich.Capability]func([]mql.Value) (mql.Value, error){
		cap: func([]mql.Value) (mql.Value, error) {
			return mql.FromGo(logoResult{
				Zone:  "body",
				Count: 2,
				Brands: []brand{
					{Name: "Chase", Confidence: "high", Score: 0.94},
					{Name: "PayPal", Confidence: "medium", Score: 0.61},
				},
			}), nil
		},
	}}

	c := mql.NewCache(live)
	arg := mql.StringValue("a message")
	got, err := c.Enrich(context.Background(), cap, []mql.Value{arg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := got.Field("brands").Elements()[0].Field("name"); mustString(t, n) != "Chase" {
		t.Fatalf("live answer reads wrong: %v", n)
	}

	snap := c.Snapshot()
	if snap.Len() != 1 {
		t.Fatalf("snapshot has %d entries", snap.Len())
	}

	// Through storage and back, as it would go into the corpus.
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var back mql.Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}

	replay := mql.NewReplay(&back)
	rv, err := replay.Enrich(context.Background(), cap, []mql.Value{arg}, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	brands := rv.Field("brands").Elements()
	if len(brands) != 2 {
		t.Fatalf("replayed %d brands, want 2", len(brands))
	}
	if n := mustString(t, brands[0].Field("name")); n != "Chase" {
		t.Errorf("replayed brand name %q", n)
	}
	if c := mustString(t, brands[1].Field("confidence")); c != "medium" {
		t.Errorf("replayed confidence %q", c)
	}
	if len(replay.Missed()) != 0 {
		t.Errorf("replay missed something: %v", replay.Missed())
	}
}

// The case that decides whether replay is usable at all.
//
// Around a hundred corpus rules write ml.logo_detect(file.message_screenshot()). The
// inner call returns bytes; the outer call's cache key digests those bytes. After
// storage the screenshot comes back as base64, and unless the digest treats the two
// identically the outer key changes, the lookup misses, and the rule reports a brand of
// nothing — a silent wrong answer rather than a loud failure.
func TestSnapshotReplaysNestedCalls(t *testing.T) {
	const (
		shot = enrich.Capability("file.message_screenshot")
		logo = enrich.Capability("ml.logo_detect")
	)
	png := []byte("\x89PNG\r\n\x1a\n not really a png but binary enough")

	live := &recordingEnricher{answers: map[enrich.Capability]func([]mql.Value) (mql.Value, error){
		shot: func([]mql.Value) (mql.Value, error) { return mql.BytesValue(png), nil },
		logo: func(args []mql.Value) (mql.Value, error) {
			b, ok := args[0].AsBytes()
			if !ok || string(b) != string(png) {
				return mql.NullValue, enrich.Unavailablef(logo, "not the screenshot")
			}
			return mql.FromGo(logoResult{Zone: "body", Count: 1,
				Brands: []brand{{Name: "Microsoft", Confidence: "high", Score: 0.9}}}), nil
		},
	}}

	ctx := context.Background()
	c := mql.NewCache(live)
	img, err := c.Enrich(ctx, shot, []mql.Value{mql.StringValue("msg")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enrich(ctx, logo, []mql.Value{img}, nil); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(c.Snapshot())
	var back mql.Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}

	// Replay in the same order a rule would: screenshot, then logo over its result.
	replay := mql.NewReplay(&back)
	rimg, err := replay.Enrich(ctx, shot, []mql.Value{mql.StringValue("msg")}, nil)
	if err != nil {
		t.Fatalf("replaying the screenshot: %v", err)
	}
	if rimg.Kind() != mdm.KindBytes {
		t.Errorf("a replayed screenshot is %v, not bytes: a string is not a picture", rimg.Kind())
	}
	rv, err := replay.Enrich(ctx, logo, []mql.Value{rimg}, nil)
	if err != nil {
		t.Fatalf("replaying logo detection over the replayed screenshot: %v — the "+
			"nested cache key did not survive storage", err)
	}
	if n := mustString(t, rv.Field("brands").Elements()[0].Field("name")); n != "Microsoft" {
		t.Errorf("replayed nested answer is %q", n)
	}
}

// A question the snapshot cannot answer is unavailable, never null.
//
// This is the whole reason a backtest can be trusted. A rule written today may read a
// capability that was never called on a message from March; answering null would read
// as "the data says no" and turn an unanswered question into a clean verdict.
func TestReplayReportsAMissAsUnavailable(t *testing.T) {
	c := mql.NewCache(&recordingEnricher{answers: map[enrich.Capability]func([]mql.Value) (mql.Value, error){
		"network.whois": func([]mql.Value) (mql.Value, error) { return mql.StringValue("x"), nil },
	}})
	if _, err := c.Enrich(context.Background(), "network.whois", []mql.Value{mql.StringValue("a.example")}, nil); err != nil {
		t.Fatal(err)
	}

	replay := mql.NewReplay(c.Snapshot())
	_, err := replay.Enrich(context.Background(), "file.explode", []mql.Value{mql.StringValue("att")}, nil)
	if err == nil {
		t.Fatal("a capability never recorded came back without an error")
	}
	var un *enrich.Unavailable
	if !asUnavailable(err, &un) {
		t.Fatalf("a miss reported %T, want enrich.Unavailable so the rule goes indeterminate", err)
	}
	if replay.Missed()["file.explode"] != 1 {
		t.Errorf("miss not counted: %v", replay.Missed())
	}

	// A different argument to a recorded capability is also a miss, not the other
	// domain's answer.
	if _, err := replay.Enrich(context.Background(), "network.whois",
		[]mql.Value{mql.StringValue("b.example")}, nil); err == nil {
		t.Error("a different argument was answered from another argument's record")
	}
}

// Errors are frozen with their kind, because indeterminate and failed are not the same
// verdict and an error string cannot be re-typed reliably.
func TestSnapshotKeepsWhetherAnErrorMeantUnavailable(t *testing.T) {
	c := mql.NewCache(&recordingEnricher{answers: map[enrich.Capability]func([]mql.Value) (mql.Value, error){
		"ml.nlu_classifier": func([]mql.Value) (mql.Value, error) {
			return mql.NullValue, enrich.Unavailablef("ml.nlu_classifier", "the service is not answering")
		},
	}})
	ctx := context.Background()
	arg := []mql.Value{mql.StringValue("body")}
	if _, err := c.Enrich(ctx, "ml.nlu_classifier", arg, nil); err == nil {
		t.Fatal("expected an error")
	}

	raw, _ := json.Marshal(c.Snapshot())
	var back mql.Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	_, err := mql.NewReplay(&back).Enrich(ctx, "ml.nlu_classifier", arg, nil)
	var un *enrich.Unavailable
	if !asUnavailable(err, &un) {
		t.Errorf("a frozen unavailable came back as %T; the rule would read as failed "+
			"rather than indeterminate", err)
	}
}

// Capability names survive, so a stored message can report what it can still answer.
func TestSnapshotNamesItsCapabilities(t *testing.T) {
	c := mql.NewCache(&recordingEnricher{answers: map[enrich.Capability]func([]mql.Value) (mql.Value, error){
		"network.whois": func([]mql.Value) (mql.Value, error) { return mql.StringValue("a"), nil },
		"file.explode":  func([]mql.Value) (mql.Value, error) { return mql.StringValue("b"), nil },
		"beta.scan_qr":  func([]mql.Value) (mql.Value, error) { return mql.StringValue("c"), nil },
	}})
	ctx := context.Background()
	for _, cap := range []enrich.Capability{"network.whois", "file.explode", "beta.scan_qr"} {
		if _, err := c.Enrich(ctx, cap, []mql.Value{mql.StringValue("x")}, nil); err != nil {
			t.Fatal(err)
		}
	}
	got := c.Snapshot().Capabilities()
	want := []string{"beta.scan_qr", "file.explode", "network.whois"}
	if len(got) != len(want) {
		t.Fatalf("capabilities %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("capabilities %v, want %v", got, want)
		}
	}
}

func mustString(t *testing.T, v mql.Value) string {
	t.Helper()
	s, ok := v.AsString()
	if !ok {
		t.Fatalf("value %v is not a string", v)
	}
	return s
}

func asUnavailable(err error, target **enrich.Unavailable) bool {
	for err != nil {
		if u, ok := err.(*enrich.Unavailable); ok {
			*target = u
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// A composite enrichment result used as the argument to another enrichment call.
//
// The corpus nests enrichment inside enrichment 409 times, and while 303 of those pass
// a screenshot — bytes, which digest by content either way — 57 pass beta.ocr's result
// and 32 pass ml.link_analysis's, both of which are structs.
//
// Live, that argument is a Go struct and encoding/json writes it in field order.
// Replayed, it is a map and encoding/json sorts the keys. Unless the digest normalises
// both, the outer call's key changes between recording and replay, the lookup misses,
// and the rule quietly reports nothing instead of what it found. The fields here are
// declared out of alphabetical order so the two orderings actually differ.
func TestSnapshotReplaysACompositeArgument(t *testing.T) {
	const (
		inner = enrich.Capability("ml.link_analysis")
		outer = enrich.Capability("ml.nlu_classifier")
	)
	analysis := logoResult{Zone: "body", Count: 3,
		Brands: []brand{{Name: "Okta", Confidence: "high", Score: 0.8}}}

	live := &recordingEnricher{answers: map[enrich.Capability]func([]mql.Value) (mql.Value, error){
		inner: func([]mql.Value) (mql.Value, error) { return mql.FromGo(analysis), nil },
		outer: func(args []mql.Value) (mql.Value, error) {
			// Reads a field off the composite it was handed, as a real rule does.
			if mustString(t, args[0].Field("zone")) != "body" {
				return mql.NullValue, enrich.Unavailablef(outer, "wrong argument")
			}
			return mql.StringValue("credential_theft"), nil
		},
	}}

	ctx := context.Background()
	c := mql.NewCache(live)
	got, err := c.Enrich(ctx, inner, []mql.Value{mql.StringValue("https://example.test")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind() != mdm.KindObject {
		t.Fatalf("the live inner answer is %v; this test needs a struct to be meaningful", got.Kind())
	}
	if _, err := c.Enrich(ctx, outer, []mql.Value{got}, nil); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(c.Snapshot())
	var back mql.Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}

	replay := mql.NewReplay(&back)
	rin, err := replay.Enrich(ctx, inner, []mql.Value{mql.StringValue("https://example.test")}, nil)
	if err != nil {
		t.Fatalf("replaying the inner call: %v", err)
	}
	if rin.Kind() != mdm.KindJSON {
		t.Fatalf("a replayed composite is %v; the test premise no longer holds", rin.Kind())
	}
	out, err := replay.Enrich(ctx, outer, []mql.Value{rin}, nil)
	if err != nil {
		t.Fatalf("replaying the outer call over the replayed composite: %v — a struct "+
			"and its own round trip did not digest the same, so the key moved", err)
	}
	if s := mustString(t, out); s != "credential_theft" {
		t.Errorf("replayed outer answer %q", s)
	}
}
