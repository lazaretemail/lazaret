// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/mql"
)

// lex scans src and fails the test if any diagnostic is produced.
func lex(t *testing.T, src string) []mql.Token {
	t.Helper()
	l := mql.NewLexer(src)
	toks := l.Tokens()
	if errs := l.Errors(); len(errs) > 0 {
		t.Fatalf("unexpected errors lexing %q:\n%s", src, errs.Render(src))
	}
	return toks
}

// kinds drops positions and text, leaving the token shape.
func kinds(toks []mql.Token) []mql.Kind {
	out := make([]mql.Kind, 0, len(toks))
	for _, t := range toks {
		out = append(out, t.Kind)
	}
	return out
}

func TestRawStringsHaveNoEscapes(t *testing.T) {
	// The corpus contains strings.count(subject.subject, '\') — a raw string whose entire
	// content is one backslash, immediately before the closing quote. Treating \' as an
	// escaped quote would swallow the terminator and silently mis-parse the rest of the
	// rule, so this is the single most important case in the lexer.
	tests := []struct {
		src  string
		want string
	}{
		{`'\'`, `\`},
		{`'\d\d\d'`, `\d\d\d`}, // regexes are written as raw strings
		{`'this back\slash is literal'`, `this back\slash is literal`},
		{`'escaping apostrophes isn''t hard'`, `escaping apostrophes isn't hard`},
		{`''`, ``},
		{`''''`, `'`},
		{`'\n'`, `\n`}, // not a newline: raw strings pass it through
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			toks := lex(t, tc.src)
			if toks[0].Kind != mql.String {
				t.Fatalf("kind = %s, want string", toks[0].Kind)
			}
			if got := toks[0].Value; got != tc.want {
				t.Errorf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEscapedStrings(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{`"hello world"`, "hello world"},
		{`"line 1\nline2"`, "line 1\nline2"},
		{`"tab\there"`, "tab\there"},
		{`"carriage\rreturn"`, "carriage\rreturn"},
		{`"quote\"inside"`, `quote"inside`},
		{`"apostrophe\'inside"`, `apostrophe'inside`},
		{`"back\\slash"`, `back\slash`},
		{`"\d\d\d"`, ""}, // invalid escapes; checked separately below
		{`"\u{0a}"`, "\n"},
		{`"\u{0398}"`, "\u0398"},         // greek capital theta
		{`"\u{1f4ec}"`, "\U0001F4EC"},    // open mailbox emoji
		{`"\u{0001f4ec}"`, "\U0001F4EC"}, // leading zeros are allowed
		{`"unicode ✉️ passes through"`, "unicode ✉️ passes through"},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			l := mql.NewLexer(tc.src)
			toks := l.Tokens()
			if strings.Contains(tc.src, `\d`) {
				// Documented: an unrecognised escape is a syntax error, not a literal.
				if len(l.Errors()) == 0 {
					t.Fatal("expected an error for an invalid escape sequence")
				}
				return
			}
			if errs := l.Errors(); len(errs) > 0 {
				t.Fatalf("unexpected errors:\n%s", errs.Render(tc.src))
			}
			if got := toks[0].Value; got != tc.want {
				t.Errorf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStringErrors(t *testing.T) {
	for _, src := range []string{
		`"unterminated`,
		`'unterminated`,
		`"bad escape \q"`,
		`"\u"`,
		`"\u{"`,
		`"\u{zz}"`,
		`"\u{0}"`,         // below the documented minimum code point
		`"\u{110000}"`,    // above unicode.MaxRune
		`"\u{123456789}"`, // more than 8 hex digits
	} {
		t.Run(src, func(t *testing.T) {
			l := mql.NewLexer(src)
			l.Tokens()
			if len(l.Errors()) == 0 {
				t.Errorf("lexed %q without error", src)
			}
		})
	}
}

func TestOperators(t *testing.T) {
	// Two-character operators must not scan as two separate tokens; "=" alone is a keyword
	// argument, which is what makes "=" and "==" and "=~" easy to confuse.
	tests := []struct {
		src  string
		want []mql.Kind
	}{
		{`a == b`, []mql.Kind{mql.Ident, mql.Eq, mql.Ident, mql.EOF}},
		{`a != b`, []mql.Kind{mql.Ident, mql.NotEq, mql.Ident, mql.EOF}},
		{`a =~ b`, []mql.Kind{mql.Ident, mql.IEq, mql.Ident, mql.EOF}},
		{`a !~ b`, []mql.Kind{mql.Ident, mql.INotEq, mql.Ident, mql.EOF}},
		{`a <= b`, []mql.Kind{mql.Ident, mql.LtEq, mql.Ident, mql.EOF}},
		{`a >= b`, []mql.Kind{mql.Ident, mql.GtEq, mql.Ident, mql.EOF}},
		{`a < b`, []mql.Kind{mql.Ident, mql.Lt, mql.Ident, mql.EOF}},
		{`a > b`, []mql.Kind{mql.Ident, mql.Gt, mql.Ident, mql.EOF}},
		{`mode="aggressive"`, []mql.Kind{mql.Ident, mql.Assign, mql.String, mql.EOF}},
		{`a in b`, []mql.Kind{mql.Ident, mql.In, mql.Ident, mql.EOF}},
		{`a in~ b`, []mql.Kind{mql.Ident, mql.IIn, mql.Ident, mql.EOF}},
		{`a not in b`, []mql.Kind{mql.Ident, mql.Not, mql.In, mql.Ident, mql.EOF}},
		{`x is null`, []mql.Kind{mql.Ident, mql.Is, mql.Null, mql.EOF}},
		{`x is not null`, []mql.Kind{mql.Ident, mql.Is, mql.Not, mql.Null, mql.EOF}},
		{`2 of (a, b)`, []mql.Kind{mql.Int, mql.Of, mql.LParen, mql.Ident, mql.Comma, mql.Ident, mql.RParen, mql.EOF}},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			got := kinds(lex(t, tc.src))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestNumbersVersusFieldAccess(t *testing.T) {
	// A dot only continues a number when a digit follows. Otherwise it is field access,
	// which is what attachments[0].file_type depends on.
	toks := lex(t, `attachments[0].file_type`)
	want := []mql.Kind{mql.Ident, mql.LBracket, mql.Int, mql.RBracket, mql.Dot, mql.Ident, mql.EOF}
	got := kinds(toks)
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	if toks := lex(t, `5 / 2.0`); toks[2].Kind != mql.Float || toks[2].Text != "2.0" {
		t.Errorf("2.0 lexed as %s %q, want float", toks[2].Kind, toks[2].Text)
	}
	if toks := lex(t, `0.5`); toks[0].Kind != mql.Float {
		t.Errorf("0.5 lexed as %s, want float", toks[0].Kind)
	}
}

func TestCommentsAndNewlines(t *testing.T) {
	// Expressions span lines freely, including inside a call's arguments, so newlines carry
	// no meaning and comments may appear anywhere.
	src := `type.inbound
// check the sender's TLD
and sender.email.domain.tld != 'ru' // trailing comment
and length(
    body.links
) > 0`
	toks := lex(t, src)
	if toks[len(toks)-1].Kind != mql.EOF {
		t.Fatal("input did not lex to EOF")
	}
	for _, tok := range toks {
		if tok.Kind == mql.Invalid {
			t.Errorf("invalid token %v", tok)
		}
	}

	// A comment running to end of input, with no trailing newline, must terminate.
	if got := kinds(lex(t, `a // done`)); len(got) != 2 {
		t.Errorf("got %v, want [identifier EOF]", got)
	}
}

func TestListSigil(t *testing.T) {
	toks := lex(t, `sender.email.domain.domain in $org_domains`)
	last := toks[len(toks)-2]
	if last.Kind != mql.List {
		t.Fatalf("kind = %s, want list", last.Kind)
	}
	if last.Value != "org_domains" {
		t.Errorf("value = %q, want %q (the sigil is not part of the name)", last.Value, "org_domains")
	}

	l := mql.NewLexer(`x in $`)
	l.Tokens()
	if len(l.Errors()) == 0 {
		t.Error("a bare $ lexed without error")
	}
}

func TestPositionsCountRunes(t *testing.T) {
	// Columns count runes, not bytes, so a caret lands correctly in rules that match on
	// homoglyphs or emoji — which is most of the interesting ones in this domain.
	toks := lex(t, "'é🙂' == x")
	eq := toks[1]
	if eq.Kind != mql.Eq {
		t.Fatalf("second token is %s, want ==", eq.Kind)
	}
	if eq.Pos.Column != 6 {
		t.Errorf("column = %d, want 6 (runes, not bytes)", eq.Pos.Column)
	}

	toks = lex(t, "a\nb\nc")
	if got := toks[2].Pos.Line; got != 3 {
		t.Errorf("line = %d, want 3", got)
	}
	if got := toks[2].Pos.Column; got != 1 {
		t.Errorf("column = %d, want 1 after a newline", got)
	}
}

func TestScopeDotsLexIndividually(t *testing.T) {
	// The parser distinguishes scope climbing from field access by counting leading dots,
	// so the lexer must not merge them.
	got := kinds(lex(t, `...email.email`))
	want := []mql.Kind{mql.Dot, mql.Dot, mql.Dot, mql.Ident, mql.Dot, mql.Ident, mql.EOF}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestEmptyInput(t *testing.T) {
	for _, src := range []string{"", "   ", "\n\n", "// only a comment"} {
		toks := lex(t, src)
		if len(toks) != 1 || toks[0].Kind != mql.EOF {
			t.Errorf("lexing %q gave %v, want just EOF", src, kinds(toks))
		}
	}
}

func FuzzLexer(f *testing.F) {
	// The lexer consumes rule text, which in a multi-tenant deployment is untrusted input.
	// It must never panic and must always terminate at EOF.
	seeds := []string{
		`type.inbound and any(body.links, .href_url.domain.root_domain in $org_domains)`,
		`'\'`, `"\u{1f4ec}"`, `a in~ ('x','y')`, `2 of (a, b, c)`, `x is not null`,
		`attachments[0].file_type`, `ml.link_analysis(., mode="aggressive")`,
		`// comment`, `$`, `"unterminated`, `'`, `\`, `=~`, `!`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		l := mql.NewLexer(src)
		toks := l.Tokens()
		if len(toks) == 0 {
			t.Fatal("no tokens returned")
		}
		if toks[len(toks)-1].Kind != mql.EOF {
			t.Fatal("token stream does not end at EOF")
		}
		// Rendering diagnostics must also survive arbitrary input, since it indexes lines
		// and columns derived from that input.
		_ = l.Errors().Render(src)
	})
}
