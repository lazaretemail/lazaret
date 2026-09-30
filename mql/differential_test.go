// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/eml"
	"github.com/lazaretemail/lazaret/mql"
)

// Differential testing against Sublime's own engine.
//
// Opt-in, because it reaches the network. It exists because the corpus pass rate cannot
// detect a wrong answer: a rule that evaluates to the wrong verdict still evaluates, and
// the suite stays green. Everything in the "Inferred" section of docs/SEMANTICS.md was a
// guess until this ran, and one of those guesses — how `X of (...)` treats a null clause —
// was wrong.
//
//	LAZARET_DIFFERENTIAL=1 go test ./mql/ -run Differential -v
//
// analyzer.sublime.security is Sublime's free EML Analyzer API and needs no credentials.
// Queries return a value rather than a verdict, which is what makes null observable.
// Every probe below is synthetic: a fixed three-line message and a one-line expression.
//
// A divergence here is not automatically our bug — it may be theirs, or a change on their
// side. It is a prompt to look, and to re-date the affected rows in docs/SEMANTICS.md.
const analyzerURL = "https://analyzer.sublime.security/v0/messages/analyze"

// probeEML deliberately carries no In-Reply-To, no links and no attachments, so that
// `headers.in_reply_to` is null on both engines. Keeping the probes dependent on exactly
// one absent scalar is what stops a difference in EML parsing being read as a difference
// in evaluation semantics.
const probeEML = "From: Probe <probe@example.com>\r\n" +
	"To: dest@example.org\r\n" +
	"Subject: probe\r\n" +
	"Date: Thu, 18 Sep 2026 12:00:00 +0000\r\n" +
	"Message-ID: <probe@example.com>\r\n" +
	"\r\n" +
	"body\r\n"

// nullBool is an expression of boolean type whose value is null. It is the lever for
// every three-valued probe: MQL has no null literal that type-checks as a boolean.
const nullBool = `strings.contains(headers.in_reply_to, "x")`

func TestDifferentialNullSemantics(t *testing.T) {
	if os.Getenv("LAZARET_DIFFERENTIAL") == "" {
		t.Skip("set LAZARET_DIFFERENTIAL=1 to compare against analyzer.sublime.security")
	}

	probes := []struct{ name, src string }{
		{"guard_null_source", nullBool + " is null"},

		{"and_false", nullBool + " and false"},
		{"and_true", nullBool + " and true"},
		{"or_true", nullBool + " or true"},
		{"or_false", nullBool + " or false"},
		{"not_null", "not " + nullBool},
		{"and_null", nullBool + " and " + nullBool},
		{"or_null", nullBool + " or " + nullBool},

		{"eq_null", `headers.in_reply_to == "x"`},
		{"neq_null", `headers.in_reply_to != "x"`},
		{"lt_null", `headers.in_reply_to < "x"`},
		{"in_null", `headers.in_reply_to in ("a", "b")`},
		{"not_in_null", `headers.in_reply_to not in ("a", "b")`},

		{"of_met_with_null", "1 of (" + nullBool + ", true)"},
		{"of_unmet_with_null", "1 of (" + nullBool + ", false)"},
		{"of_unmet_two", "2 of (" + nullBool + ", false, false)"},
		{"of_met_two", "2 of (" + nullBool + ", true, true)"},
		{"of_unmet_no_null", "1 of (false, false)"},

		{"is_null_precedence", "not headers.in_reply_to is null"},

		{"regex_contains_null", `regex.contains(headers.in_reply_to, "x")`},
		{"regex_count_null", `regex.count(headers.in_reply_to, "x")`},
		{"levenshtein_null", `strings.levenshtein(headers.in_reply_to, "abc")`},

		{"empty_array_length", "length(body.links)"},
		{"glob_no_escape", `strings.like("axb", "a*b")`},
	}

	srcs := make([]string, len(probes))
	for i, p := range probes {
		srcs[i] = p.src
	}
	theirs, err := analyze(t, probeEML, srcs)
	if err != nil {
		t.Fatalf("querying the analyzer: %v", err)
	}

	msg, err := eml.ParseString(probeEML, nil)
	if err != nil {
		t.Fatalf("parsing the probe message: %v", err)
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			want, ok := theirs[p.src]
			if !ok {
				t.Fatalf("the analyzer returned no result for %q", p.src)
			}
			checked, err := mql.Compile(p.src, nil)
			if err != nil {
				t.Fatalf("compiling %q: %v", p.src, err)
			}
			res := mql.Eval(context.Background(), checked, msg, nil)
			if res.Err != nil {
				t.Fatalf("evaluating %q: %v", p.src, res.Err)
			}
			if got := res.Value.String(); got != want {
				t.Errorf("%s\n  ours: %s\nsublime: %s", p.src, got, want)
			}
		})
	}
}

// nullArray is an expression of array type whose value is null. Enrichment results are
// the real source of these — `ml.nlu_classifier(x).topics` with no ML service is a null
// array — but `regex.extract` over a null input produces one with no service required.
const nullArray = `regex.extract(headers.in_reply_to, "(?P<a>x)")`

// TestDifferentialNullArray pins how the array builtins treat a null array.
//
// A null array is not an empty array, and which builtins propagate the null and which
// absorb it is irregular enough that it had to be measured rather than derived. It is
// also the highest-stakes corner of the language for this engine: the corpus is full of
// `not any(ml.…(…), …)` written to exclude newsletters and benign mail, so folding null
// to empty turns an unavailable classifier into a positive assertion and fires the rule.
func TestDifferentialNullArray(t *testing.T) {
	if os.Getenv("LAZARET_DIFFERENTIAL") == "" {
		t.Skip("set LAZARET_DIFFERENTIAL=1 to compare against analyzer.sublime.security")
	}

	probes := []struct{ name, src string }{
		{"bare", nullArray},
		{"length", "length(" + nullArray + ")"},
		{"any", "any(" + nullArray + ", true)"},
		{"not_any", "not any(" + nullArray + ", true)"},
		{"all", "all(" + nullArray + ", true)"},
		{"ratio", "ratio(" + nullArray + ", true)"},
		{"filter", "length(filter(" + nullArray + ", true))"},
		{"map", "length(map(" + nullArray + ", 1))"},
		{"sum", "sum(map(" + nullArray + ", 1))"},
		{"index", nullArray + "[0]"},
	}

	srcs := make([]string, len(probes))
	for i, p := range probes {
		srcs[i] = p.src
	}
	theirs, err := analyze(t, probeEML, srcs)
	if err != nil {
		t.Fatalf("querying the analyzer: %v", err)
	}
	msg, err := eml.ParseString(probeEML, nil)
	if err != nil {
		t.Fatalf("parsing the probe message: %v", err)
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			checked, err := mql.Compile(p.src, nil)
			if err != nil {
				t.Fatalf("compiling %q: %v", p.src, err)
			}
			res := mql.Eval(context.Background(), checked, msg, nil)
			if got := res.Value.String(); got != theirs[p.src] {
				t.Errorf("%s\n  ours: %s\nsublime: %s", p.src, got, theirs[p.src])
			}
		})
	}
}

// TestDifferentialKnownSliceDivergence records the one array behaviour we do not match.
//
// Slicing a null array yields [] upstream and null here, because a null carries no type
// at evaluation time and the documented rule for a null *string* slice is null. Telling
// them apart needs the checker's static type threaded onto the AST, which is real work
// for no corpus benefit: the only genuine MQL slice in the corpus is `[0:39]`, over a
// string, where our answer is already the documented one. Revisit if that changes.
func TestDifferentialKnownSliceDivergence(t *testing.T) {
	if os.Getenv("LAZARET_DIFFERENTIAL") == "" {
		t.Skip("set LAZARET_DIFFERENTIAL=1 to compare against analyzer.sublime.security")
	}
	src := "length(" + nullArray + "[0:1])"
	theirs, err := analyze(t, probeEML, []string{src})
	if err != nil {
		t.Fatalf("querying the analyzer: %v", err)
	}
	msg, _ := eml.ParseString(probeEML, nil)
	checked, err := mql.Compile(src, nil)
	if err != nil {
		t.Fatalf("compiling: %v", err)
	}
	got := mql.Eval(context.Background(), checked, msg, nil).Value.String()
	if got == theirs[src] {
		t.Errorf("we now agree with Sublime on %s (both %s) — remove this test and the "+
			"divergence note in docs/COMPATIBILITY.md", src, got)
	}
	t.Logf("known divergence holds: %s -> ours %s, sublime %s", src, got, theirs[src])
}

// TestDifferentialRejectsOurExtensions records the syntax Sublime does not accept.
//
// It is the other half of the compatibility claim. A rule that runs here and fails there
// is a quieter problem than one that fails here, but it is still a divergence, and the
// project's position is that the standard surface is exactly Sublime's.
func TestDifferentialRejectsOurExtensions(t *testing.T) {
	if os.Getenv("LAZARET_DIFFERENTIAL") == "" {
		t.Skip("set LAZARET_DIFFERENTIAL=1 to compare against analyzer.sublime.security")
	}

	// Word forms of the threshold operator. These were believed to be in the corpus; they
	// are not — all 25 occurrences of "any of" / "all of" / "none of" are inside `//`
	// comments. Sublime's parser rejects them outright.
	for _, src := range []string{
		"any of (true, false)",
		"all of (true, false)",
		"none of (true, false)",
	} {
		t.Run(src, func(t *testing.T) {
			if _, err := mql.Compile(src, nil); err != nil {
				t.Fatalf("we no longer accept %q: %v — update docs/SEMANTICS.md", src, err)
			}
			if _, err := analyze(t, probeEML, []string{src}); err == nil {
				t.Errorf("the analyzer now accepts %q; it is no longer an extension", src)
			}
		})
	}
}

// analyze posts one request carrying every probe, and returns source -> rendered result.
// Batching keeps this to a single call against a free public service.
func analyze(t *testing.T, raw string, srcs []string) (map[string]string, error) {
	t.Helper()

	type query struct {
		Name   string `json:"name"`
		Source string `json:"source"`
	}
	body := struct {
		RawMessage string  `json:"raw_message"`
		Queries    []query `json:"queries"`
	}{RawMessage: base64.StdEncoding.EncodeToString([]byte(raw))}
	for i, s := range srcs {
		body.Queries = append(body.Queries, query{Name: string(rune('a'+i%26)) + s[:min(8, len(s))], Source: s})
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, analyzerURL, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		QueryResults []struct {
			Query   struct{ Source string } `json:"query"`
			Result  json.RawMessage         `json:"result"`
			Success bool                    `json:"success"`
			Error   *string                 `json:"error"`
		} `json:"query_results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	got := make(map[string]string, len(out.QueryResults))
	for _, q := range out.QueryResults {
		if !q.Success {
			msg := "?"
			if q.Error != nil {
				msg = *q.Error
			}
			// A rejected probe is the caller's answer, not a transport failure: the
			// extension test above depends on being able to see it.
			return nil, &analyzerReject{src: q.Query.Source, msg: msg}
		}
		got[q.Query.Source] = string(bytes.TrimSpace(q.Result))
	}
	return got, nil
}

type analyzerReject struct{ src, msg string }

func (e *analyzerReject) Error() string { return "analyzer rejected " + e.src + ": " + e.msg }
