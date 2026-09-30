// SPDX-License-Identifier: AGPL-3.0-only

package corpus_test

import (
	"fmt"
	"regexp"
	"sort"
	"testing"

	"github.com/lazaretemail/lazaret/internal/corpus"
	"github.com/lazaretemail/lazaret/mql"
)

var (
	noField = regexp.MustCompile(`no field "([^"]+)" on (\S+?)(?:;|$)`)
	noFunc  = regexp.MustCompile(`no function "([^"]+)"`)
	noKw    = regexp.MustCompile(`(\S+) has no argument named "([^"]+)"`)
)

// TestModelGaps is a reporting tool rather than an assertion: it groups every
// type-check failure across the corpus by the underlying gap, so the model can be
// completed from evidence instead of one rule at a time.
func TestModelGaps(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	ents, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]int{}
	funcs := map[string]int{}
	kws := map[string]int{}
	other := map[string]int{}

	for _, e := range ents {
		expr, err := mql.Parse(e.Source)
		if err != nil || e.Type == "triage_rule" {
			continue
		}
		_, err = mql.Check(expr, nil)
		if err == nil {
			continue
		}
		for _, d := range err.(mql.ErrorList) {
			switch {
			case noField.MatchString(d.Msg):
				m := noField.FindStringSubmatch(d.Msg)
				fields[m[2]+"."+m[1]]++
			case noFunc.MatchString(d.Msg):
				funcs[noFunc.FindStringSubmatch(d.Msg)[1]]++
			case noKw.MatchString(d.Msg):
				m := noKw.FindStringSubmatch(d.Msg)
				kws[m[1]+" "+m[2]]++
			default:
				other[d.Msg]++
			}
		}
	}
	dump := func(title string, m map[string]int, limit int) {
		var out string
		out += fmt.Sprintln("===", title, len(m))
		type kv struct {
			k string
			n int
		}
		var list []kv
		for k, n := range m {
			list = append(list, kv{k, n})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].n != list[j].n {
				return list[i].n > list[j].n
			}
			return list[i].k < list[j].k
		})
		for i, e := range list {
			if i >= limit {
				out += fmt.Sprintf("  ... and %d more\n", len(list)-limit)
				break
			}
			out += fmt.Sprintf("  %4d  %s\n", e.n, e.k)
		}
		t.Log(out)
	}
	dump("MISSING FIELDS", fields, 80)
	dump("MISSING FUNCTIONS", funcs, 40)
	dump("MISSING KEYWORDS", kws, 20)
	dump("OTHER", other, 25)
}
