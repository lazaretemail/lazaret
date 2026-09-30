// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/eml"
	"github.com/lazaretemail/lazaret/internal/corpus"
	"github.com/lazaretemail/lazaret/lists"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
)

// Whole-message differential: our verdicts against Sublime's, on the corpus's own samples.
//
// `run_all_detection_rules` makes the analyzer evaluate Sublime's entire feed — 1,259
// rules at the time of writing — with no credentials and nothing uploaded. That is close
// enough to our 1,285 detection rules to compare matched sets directly.
//
//	LAZARET_DIFFERENTIAL=1 go test ./mql/ -run DifferentialCorpus -v
//
// Where TestDifferentialNullSemantics isolates the evaluator, this exercises the whole
// pipeline — MIME, headers, thread splitting, the MDM — so a disagreement here is as
// likely to be a parsing difference as a semantic one. Three outcomes, only one of which
// fails the test:
//
//   - We match, they evaluated the same rule and did not. A false positive, and the
//     serious direction. Fails.
//   - They match, we report a definite no-match. A missed detection. Fails.
//   - They match, we report indeterminate. Expected: they have ML, file explosion and
//     sender profiles and we have none of it here. Logged, not failed.
func TestDifferentialCorpusVerdicts(t *testing.T) {
	if os.Getenv("LAZARET_DIFFERENTIAL") == "" {
		t.Skip("set LAZARET_DIFFERENTIAL=1 to compare against analyzer.sublime.security")
	}
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}

	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	paths, err := filepath.Glob(filepath.Join(corpus.Dir(), "emls", "*.eml"))
	if err != nil || len(paths) == 0 {
		t.Skip("no sample messages in the corpus checkout")
	}

	org := &orgconfig.Config{Domains: []string{"example.com", "sublimesecurity.com"}}
	org.Normalize()

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}

			theirMatched, theirEvaluated, err := analyzeAllRules(raw)
			if err != nil {
				t.Fatalf("querying the analyzer: %v", err)
			}

			msg, err := eml.Parse(raw, &eml.Options{Org: org})
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}

			// Embedded $list data is part of the shipped default, so the comparison runs
			// with it. Without it, rules keyed on $high_trust_sender_root_domains report
			// indeterminate here and matched there, which reads as a gap in the engine
			// rather than a gap in its configuration.
			evalOpts := &mql.EvalOptions{Lists: lists.MustEmbedded()}

			ourMatched := map[string]bool{}
			ourVerdict := map[string]mql.Verdict{}
			for _, e := range entities {
				if e.Type != "rule" {
					continue
				}
				checked, err := mql.Compile(e.Source, nil)
				if err != nil {
					continue
				}
				v := mql.Eval(context.Background(), checked, msg, evalOpts).Verdict
				ourVerdict[e.Name] = v
				if v == mql.Match {
					ourMatched[e.Name] = true
				}
			}

			var falsePositives, missed, explained []string
			for name := range ourMatched {
				// Only comparable if they ran the same rule.
				if theirEvaluated[name] && !theirMatched[name] {
					falsePositives = append(falsePositives, name)
				}
			}
			for name := range theirMatched {
				switch ourVerdict[name] {
				case mql.Match:
				case mql.Indeterminate:
					explained = append(explained, name)
				default:
					if _, known := ourVerdict[name]; known {
						missed = append(missed, name)
					}
				}
			}
			sort.Strings(falsePositives)
			sort.Strings(missed)
			sort.Strings(explained)

			t.Logf("sublime: %d evaluated, %d matched; ours: %d matched",
				len(theirEvaluated), len(theirMatched), len(ourMatched))
			for _, n := range explained {
				t.Logf("  indeterminate here, matched there (expected, needs enrichment): %s", n)
			}
			for _, n := range falsePositives {
				t.Errorf("  FALSE POSITIVE: we match %q, Sublime evaluates it and does not", n)
			}
			for _, n := range missed {
				t.Errorf("  MISSED: Sublime matches %q, we report a definite no-match", n)
			}
		})
	}
}

// analyzeAllRules runs Sublime's whole detection feed over one raw message and returns
// the matched set and the evaluated set. The evaluated set matters: our corpus checkout
// and their active feed are not identical, and a rule they never ran says nothing.
func analyzeAllRules(raw []byte) (matched, evaluated map[string]bool, err error) {
	body := map[string]any{
		"raw_message":             base64.StdEncoding.EncodeToString(raw),
		"run_all_detection_rules": true,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, analyzerURL, bytes.NewReader(buf))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	var out struct {
		RuleResults []struct {
			Rule    struct{ Name string } `json:"rule"`
			Matched bool                  `json:"matched"`
			Success bool                  `json:"success"`
		} `json:"rule_results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, err
	}

	matched, evaluated = map[string]bool{}, map[string]bool{}
	for _, r := range out.RuleResults {
		if !r.Success {
			continue
		}
		evaluated[r.Rule.Name] = true
		if r.Matched {
			matched[r.Rule.Name] = true
		}
	}
	return matched, evaluated, nil
}
