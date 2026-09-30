// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/mql"
)

// parseTo parses src and compares the rendered tree to want. Rendering is fully
// parenthesised by the caller's expectation, so these cases pin down precedence rather than
// merely asserting that parsing succeeded.
func parseTo(t *testing.T, src, want string) {
	t.Helper()
	e, err := mql.Parse(src)
	if err != nil {
		t.Fatalf("parsing %q: %v", src, err)
	}
	if got := e.String(); got != want {
		t.Errorf("parse %q\n got: %s\nwant: %s", src, got, want)
	}
}

func TestPrecedence(t *testing.T) {
	// The published table, loosest to tightest: or, and, not, of, comparisons, + -, * /
	// %, unary -, postfix. Two entries are surprising and both are load-bearing: `not`
	// binds more loosely than comparison, and `and` more tightly than `or`.
	tests := []struct{ src, want string }{
		// `and` binds tighter than `or`. Sublime's own documentation calls this out as a
		// frequent source of silently wrong rules.
		{`a and b or c`, `a and b or c`},
		{`a or b and c`, `a or b and c`},

		// `not` is looser than comparison, so it takes the whole comparison.
		{`not a == b`, `not a == b`},
		{`not a and b`, `not a and b`},

		// Arithmetic binds tighter than comparison.
		{`a + b < c * d`, `a + b < c * d`},
		{`a - b - c`, `a - b - c`},
		{`a / b / c`, `a / b / c`},

		// Postfix binds tightest of all.
		{`a.b[0].c(1).d`, `a.b[0].c(1).d`},
		{`-a.b`, `-a.b`},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) { parseTo(t, tc.src, tc.want) })
	}

	// Associativity and grouping: check the shape, not just the text.
	e, err := mql.Parse(`a and b or c`)
	if err != nil {
		t.Fatal(err)
	}
	top, ok := e.(*mql.Binary)
	if !ok || top.Op != mql.Or {
		t.Fatalf("top of `a and b or c` is %T, want an `or`", e)
	}
	if lhs, ok := top.X.(*mql.Binary); !ok || lhs.Op != mql.And {
		t.Errorf("left of the `or` is %T, want an `and`", top.X)
	}
}

func TestParenthesesArePreserved(t *testing.T) {
	// Formatting must not silently re-associate someone's rule. Dropping redundant
	// parentheses would change `type.inbound and (a or b)` into a different rule.
	parseTo(t, `type.inbound and (a or b)`, `type.inbound and (a or b)`)
	parseTo(t, `(a)`, `(a)`)
	parseTo(t, `not (a == b)`, `not (a == b)`)
}

func TestScopeReferences(t *testing.T) {
	tests := []struct{ src, want string }{
		{`any(x, . == "y")`, `any(x, . == "y")`},
		{`any(x, .name == "y")`, `any(x, .name == "y")`},
		{`any(x, any(y, ..name == .name))`, `any(x, any(y, ..name == .name))`},
		{`any(x, any(y, any(z, ...name)))`, `any(x, any(y, any(z, ...name)))`},
		{`.scan.strings.raw`, `.scan.strings.raw`},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) { parseTo(t, tc.src, tc.want) })
	}

	// The dot count is the climb distance, not decoration.
	e := mql.MustParse(`...name`)
	f, ok := e.(*mql.Field)
	if !ok {
		t.Fatalf("got %T, want a field access", e)
	}
	s, ok := f.X.(*mql.ScopeRef)
	if !ok {
		t.Fatalf("base is %T, want a scope reference", f.X)
	}
	if s.Up != 2 {
		t.Errorf("`...` climbs %d scopes, want 2", s.Up)
	}
}

func TestThresholdForms(t *testing.T) {
	// The numeric form is documented; the word forms appear only in the corpus.
	for src, form := range map[string]mql.OfForm{
		`2 of (a, b, c)`: mql.OfCount,
		`any of (a, b)`:  mql.OfAny,
		`all of (a, b)`:  mql.OfAll,
		`none of (a, b)`: mql.OfNone,
	} {
		t.Run(src, func(t *testing.T) {
			e := mql.MustParse(src)
			th, ok := e.(*mql.Threshold)
			if !ok {
				t.Fatalf("got %T, want a threshold", e)
			}
			if th.Form != form {
				t.Errorf("form = %v, want %v", th.Form, form)
			}
			if got := e.String(); got != src {
				t.Errorf("rendered as %q, want %q", got, src)
			}
		})
	}
}

func TestMembershipForms(t *testing.T) {
	for _, src := range []string{
		`x in ("a", "b")`,
		`x in~ ("a", "b")`,
		`x not in ("a", "b")`,
		`x not in~ ("a", "b")`,
		`x in $org_domains`,
		`x not in $org_domains`,
		`x in body.links`,
	} {
		t.Run(src, func(t *testing.T) { parseTo(t, src, src) })
	}

	e := mql.MustParse(`x not in~ ("a")`)
	m, ok := e.(*mql.Membership)
	if !ok {
		t.Fatalf("got %T, want a membership test", e)
	}
	if !m.Negated || !m.Insensitive {
		t.Errorf("negated=%v insensitive=%v, want both true", m.Negated, m.Insensitive)
	}
}

func TestRangeChaining(t *testing.T) {
	// The middle operand must be evaluated once, so a range is its own node rather than
	// two comparisons — it is typically an expensive call.
	e := mql.MustParse(`4 < strings.levenshtein(a, b) <= 7`)
	r, ok := e.(*mql.Range)
	if !ok {
		t.Fatalf("got %T, want a range", e)
	}
	if r.OpLo != mql.Lt || r.OpHi != mql.LtEq {
		t.Errorf("operators are %s and %s, want < and <=", r.OpLo, r.OpHi)
	}
	if _, ok := r.X.(*mql.Call); !ok {
		t.Errorf("middle operand is %T, want the call", r.X)
	}

	parseTo(t, `0 < length(body.links) < 20`, `0 < length(body.links) < 20`)
	parseTo(t, `'abc' <= subject.subject < 'xyz'`, `'abc' <= subject.subject < 'xyz'`)
}

func TestSubscriptAndSlice(t *testing.T) {
	for _, src := range []string{
		`attachments[0]`,
		`attachments[1:]`,
		`attachments[:2]`,
		`attachments[1:2]`,
		`body.current_thread.text[7:10]`,
		`body.previous_threads[length(body.previous_threads) - 1]`,
		`.query_params_decoded["utm_source"]`,
	} {
		t.Run(src, func(t *testing.T) { parseTo(t, src, src) })
	}
}

func TestKeywordArguments(t *testing.T) {
	for _, src := range []string{
		`ml.link_analysis(., mode="aggressive")`,
		`strings.parse_url(x, strict=false)`,
		`beta.scan_base64(x, format="url", ignore_padding=true)`,
	} {
		t.Run(src, func(t *testing.T) { parseTo(t, src, src) })
	}

	// Positional arguments may not follow keyword ones.
	if _, err := mql.Parse(`f(a=1, 2)`); err == nil {
		t.Error("accepted a positional argument after a keyword argument")
	}
}

func TestSyntaxErrors(t *testing.T) {
	tests := []struct {
		src  string
		want string // substring the diagnostic should contain
	}{
		{`a ==`, "expected an expression"},
		{`a == b ==`, "do not chain"},
		{`a == b == c`, "do not chain"},
		{`(a`, "expected"},
		{`f(a`, "expected"},
		{`a.`, "field name"},
		{`3 of `, "expected"},
		{`x is`, "expected"},
		{`x is not`, "expected"},
		{`[1, 2`, "expected"},
		{`a b`, "after the end of the expression"},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			_, err := mql.Parse(tc.src)
			if err == nil {
				t.Fatalf("parsed %q without error", tc.src)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("diagnostic for %q was %q, want it to mention %q", tc.src, err, tc.want)
			}
		})
	}
}

func TestDiagnosticsPointAtTheProblem(t *testing.T) {
	// A mid-expression mistake must be reported where it is, not at the end of the rule.
	// Corpus rules run to hundreds of lines, so a diagnostic that only says "somewhere in
	// here" is close to useless.
	src := "type.inbound\nand sender.emial nonsense\nand subject.subject == \"x\""
	_, err := mql.Parse(src)
	if err == nil {
		t.Fatal("expected an error")
	}
	errs, ok := err.(mql.ErrorList)
	if !ok {
		t.Fatalf("got %T, want an ErrorList", err)
	}
	rendered := errs.Render(src)
	if !strings.Contains(rendered, "^") {
		t.Errorf("rendered diagnostic has no caret:\n%s", rendered)
	}
	if errs[0].Pos.Line != 2 {
		t.Errorf("reported line %d, want 2:\n%s", errs[0].Pos.Line, rendered)
	}
	// Column 18 is where "nonsense" starts.
	if errs[0].Pos.Column != 18 {
		t.Errorf("reported column %d, want 18:\n%s", errs[0].Pos.Column, rendered)
	}
}

func TestTruncatedInputReportsAtEndOfInput(t *testing.T) {
	// When a rule simply stops, end of input is the honest position to report.
	src := "type.inbound\nand sender.email =="
	_, err := mql.Parse(src)
	if err == nil {
		t.Fatal("expected an error")
	}
	errs := err.(mql.ErrorList)
	if !strings.Contains(errs.Error(), "end of input") {
		t.Errorf("diagnostic was %q, want it to mention end of input", errs)
	}
	if errs[0].Pos.Line != 2 {
		t.Errorf("reported line %d, want 2", errs[0].Pos.Line)
	}
}

func TestDeepNestingIsBoundedNotFatal(t *testing.T) {
	// Rule text is untrusted in a multi-tenant deployment. Pathological nesting must
	// produce a diagnostic, not a stack overflow.
	src := strings.Repeat("(", 5000) + "a" + strings.Repeat(")", 5000)
	if _, err := mql.Parse(src); err == nil {
		t.Error("deeply nested input parsed without complaint")
	}
}

func TestLargeLiteralSet(t *testing.T) {
	// One corpus rule is a 242 KB single expression: one call over thousands of CIDRs.
	// Parsing must be comfortable at that size.
	var b strings.Builder
	b.WriteString("beta.ip_in(headers.ips, ")
	for i := range 20000 {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(`"10.0.0.0/8"`)
	}
	b.WriteString(")")

	e, err := mql.Parse(b.String())
	if err != nil {
		t.Fatalf("parsing a large literal set: %v", err)
	}
	call, ok := e.(*mql.Call)
	if !ok {
		t.Fatalf("got %T, want a call", e)
	}
	if got := len(call.Args); got != 20001 {
		t.Errorf("parsed %d arguments, want 20001", got)
	}
}

func FuzzParser(f *testing.F) {
	seeds := []string{
		`type.inbound and any(body.links, .href_url.domain.root_domain in $org_domains)`,
		`2 of (a, b, c)`, `any of (a, b)`, `x is not null`, `a[1:2]`, `a[:]`,
		`f(a, b=1)`, `4 < x <= 7`, `...a`, `not a == b`, `[1, 2, 3]`,
		`a.b(c).d[0]`, `'\'`, `(((a)))`, `a ==`, `f(`, `$`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		e, err := mql.Parse(src)
		if err != nil {
			return
		}
		// A tree that parsed cleanly must render to text that parses to the same tree.
		// Any counterexample is a real bug in precedence or in rendering.
		rendered := e.String()
		again, err := mql.Parse(rendered)
		if err != nil {
			t.Fatalf("input %q rendered to %q, which does not parse: %v", src, rendered, err)
		}
		if got := again.String(); got != rendered {
			t.Fatalf("input %q is not stable under formatting:\n first: %s\nsecond: %s", src, rendered, got)
		}
	})
}
