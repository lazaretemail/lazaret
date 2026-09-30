// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"fmt"
	"strconv"
)

// Parse compiles MQL source into an expression tree.
//
// Parsing is best-effort: on a syntax error the parser records a diagnostic, skips to a
// token it can resume from, and carries on, so that one mistake does not mask every later
// one in the same rule. A non-nil error means the tree is incomplete and must not be
// evaluated; it is still useful for editor tooling.
func Parse(src string) (Expr, error) {
	p := newParser(src)
	e := p.parseExpr()
	if p.tok.Kind != EOF {
		p.errorf(p.tok.Pos, "unexpected %s after the end of the expression", describe(p.tok))
	}
	return e, p.errs.Sorted().Err()
}

// MustParse is Parse for tests and for expressions built into the program.
func MustParse(src string) Expr {
	e, err := Parse(src)
	if err != nil {
		panic(fmt.Sprintf("mql: parsing %q: %v", src, err))
	}
	return e
}

type parser struct {
	lx   *Lexer
	tok  Token // the token under the cursor
	peek Token // one token of lookahead

	errs ErrorList

	// depth guards against stack exhaustion on deeply nested or adversarial input. The
	// corpus nests four levels of array functions; the limit is far above that.
	depth int
}

// maxDepth bounds recursion. Rule text is untrusted in a multi-tenant deployment, and
// "(((((..." should produce a diagnostic rather than a stack overflow.
const maxDepth = 200

func newParser(src string) *parser {
	p := &parser{lx: NewLexer(src)}
	p.tok = p.lx.Next()
	p.peek = p.lx.Next()
	return p
}

func (p *parser) advance() {
	p.tok, p.peek = p.peek, p.lx.Next()
}

// lexErrors folds in the lexer's diagnostics. Called once at the end, because the lexer
// runs lazily just ahead of the parser.
func (p *parser) lexErrors() {
	p.errs = append(p.errs, p.lx.Errors()...)
}

func (p *parser) errorf(pos Pos, format string, args ...any) {
	// One diagnostic per position: error recovery can otherwise report the same token
	// repeatedly as it tries to resynchronise.
	if n := len(p.errs); n > 0 && p.errs[n-1].Pos == pos {
		return
	}
	p.errs = append(p.errs, &Error{Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

// expect consumes a token of the given kind, or reports and returns false.
func (p *parser) expect(k Kind) bool {
	if p.tok.Kind == k {
		p.advance()
		return true
	}
	p.errorf(p.tok.Pos, "expected %s, found %s", k, describe(p.tok))
	return false
}

func describe(t Token) string {
	if t.Kind == EOF {
		return "end of input"
	}
	if t.Text != "" {
		return fmt.Sprintf("%q", t.Text)
	}
	return t.Kind.String()
}

// ---------------------------------------------------------------------------
// Precedence
//
// From the published table, loosest first:
//
//	or
//	and
//	not
//	of
//	comparisons: < <= == =~ != !~ >= > in   (plus the undocumented `is null`)
//	+ -
//	* / %
//	unary -
//	postfix: .field  [index]  (call)
//
// `not` binding more loosely than comparison is unusual and deliberate: `not a == b` is
// `not (a == b)`. `and` binding more tightly than `or` is the trap Sublime's own docs warn
// about, which is why Paren nodes are preserved rather than discarded.
// ---------------------------------------------------------------------------

func (p *parser) parseExpr() Expr {
	if p.depth > maxDepth {
		p.errorf(p.tok.Pos, "expression nested too deeply (limit %d)", maxDepth)
		p.skipToRecovery()
		return &NullLit{P: p.tok.Pos}
	}
	p.depth++
	defer func() { p.depth-- }()

	e := p.parseOr()
	p.lexErrors()
	return e
}

func (p *parser) parseOr() Expr {
	x := p.parseAnd()
	for p.tok.Kind == Or {
		pos := p.tok.Pos
		p.advance()
		y := p.parseAnd()
		x = &Binary{Op: Or, X: x, Y: y, P: pos}
	}
	return x
}

func (p *parser) parseAnd() Expr {
	x := p.parseNot()
	for p.tok.Kind == And {
		pos := p.tok.Pos
		p.advance()
		y := p.parseNot()
		x = &Binary{Op: And, X: x, Y: y, P: pos}
	}
	return x
}

func (p *parser) parseNot() Expr {
	if p.tok.Kind == Not {
		pos := p.tok.Pos
		p.advance()
		return &Unary{Op: Not, X: p.parseNot(), P: pos}
	}
	return p.parseOf()
}

// parseOf handles the threshold operator in both its numeric and word forms.
func (p *parser) parseOf() Expr {
	x := p.parseComparison()

	if p.tok.Kind != Of {
		return x
	}
	pos := p.tok.Pos
	p.advance()

	of := &Threshold{P: pos}
	switch n := x.(type) {
	case *Name:
		// The undocumented word forms. They appear in the corpus alongside the numeric one.
		switch n.Name {
		case "any":
			of.Form = OfAny
		case "all":
			of.Form = OfAll
		case "none":
			of.Form = OfNone
		default:
			p.errorf(x.Pos(), "%q is not a valid threshold; use a number, or any, all or none", n.Name)
			of.Form = OfCount
			of.Count = x
		}
	default:
		of.Form = OfCount
		of.Count = x
	}

	if !p.expect(LParen) {
		p.skipToRecovery()
		return of
	}
	of.Clauses = p.parseExprList(RParen)
	p.expect(RParen)
	return of
}

// comparisonOps are the operators at the comparison level. They are non-associative:
// `a == b == c` is a mistake, not a chain, and is reported as one. The exception is the
// documented `lo < x <= hi` range form, handled below.
func isComparison(k Kind) bool {
	switch k {
	case Eq, NotEq, IEq, INotEq, Lt, LtEq, Gt, GtEq:
		return true
	}
	return false
}

func (p *parser) parseComparison() Expr {
	x := p.parseAdditive()

	for {
		switch {
		case p.tok.Kind == Is:
			x = p.parseIsNull(x)
			continue

		case p.tok.Kind == In || p.tok.Kind == IIn:
			x = p.parseIn(x, false)
			continue

		case p.tok.Kind == Not && (p.peek.Kind == In || p.peek.Kind == IIn):
			p.advance() // consume `not`, leaving `in` under the cursor
			x = p.parseIn(x, true)
			continue

		case isComparison(p.tok.Kind):
			op, pos := p.tok.Kind, p.tok.Pos
			p.advance()
			y := p.parseAdditive()

			// Range chaining. Only < and <= chain, and the middle operand is evaluated
			// once — it is typically an expensive call such as strings.levenshtein.
			if (op == Lt || op == LtEq) && (p.tok.Kind == Lt || p.tok.Kind == LtEq) {
				op2 := p.tok.Kind
				p.advance()
				hi := p.parseAdditive()
				x = &Range{Lo: x, OpLo: op, X: y, OpHi: op2, Hi: hi, P: pos}
				continue
			}
			x = &Binary{Op: op, X: x, Y: y, P: pos}

			if isComparison(p.tok.Kind) {
				p.errorf(p.tok.Pos,
					"comparisons do not chain; only `lo < x <= hi` is allowed, so parenthesise or split this")
				p.advance()
				p.parseAdditive()
			}
			continue
		}
		return x
	}
}

func (p *parser) parseIsNull(x Expr) Expr {
	pos := p.tok.Pos
	p.advance() // `is`

	negated := false
	if p.tok.Kind == Not {
		negated = true
		p.advance()
	}
	if !p.expect(Null) {
		return x
	}
	return &IsNull{X: x, Negated: negated, P: pos}
}

func (p *parser) parseIn(x Expr, negated bool) Expr {
	pos := p.tok.Pos
	insensitive := p.tok.Kind == IIn
	p.advance()

	// The right side is a parenthesised value set, a named list, or any expression that
	// yields an array — `x in arr` being shorthand for `any(arr, . == x)`.
	var set Expr
	if p.tok.Kind == LParen {
		lp := p.tok.Pos
		p.advance()
		elems := p.parseExprList(RParen)
		p.expect(RParen)
		set = &TupleLit{P: lp, Elems: elems}
	} else {
		set = p.parseAdditive()
	}
	return &Membership{X: x, Set: set, Negated: negated, Insensitive: insensitive, P: pos}
}

func (p *parser) parseAdditive() Expr {
	x := p.parseMultiplicative()
	for p.tok.Kind == Plus || p.tok.Kind == Minus {
		op, pos := p.tok.Kind, p.tok.Pos
		p.advance()
		x = &Binary{Op: op, X: x, Y: p.parseMultiplicative(), P: pos}
	}
	return x
}

func (p *parser) parseMultiplicative() Expr {
	x := p.parseUnary()
	for p.tok.Kind == Star || p.tok.Kind == Slash || p.tok.Kind == Percent {
		op, pos := p.tok.Kind, p.tok.Pos
		p.advance()
		x = &Binary{Op: op, X: x, Y: p.parseUnary(), P: pos}
	}
	return x
}

func (p *parser) parseUnary() Expr {
	if p.tok.Kind == Minus {
		pos := p.tok.Pos
		p.advance()
		return &Unary{Op: Minus, X: p.parseUnary(), P: pos}
	}
	return p.parsePostfix(p.parsePrimary())
}

// parsePostfix applies field access, subscripting and calls to an already-parsed operand.
//
// These are handled uniformly on an arbitrary expression rather than only on names, because
// real rules chain them: network.whois(d).registrant_email, file.explode(.)[0].scan, and so
// on. A parser that treated field access as a flat dotted path could not read those at all.
func (p *parser) parsePostfix(x Expr) Expr {
	for {
		switch p.tok.Kind {
		case Dot:
			pos := p.tok.Pos
			p.advance()
			if p.tok.Kind != Ident {
				p.errorf(p.tok.Pos, "expected a field name after \".\", found %s", describe(p.tok))
				return x
			}
			x = &Field{X: x, Name: p.tok.Text, P: pos}
			p.advance()

		case LBracket:
			x = p.parseSubscript(x)

		case LParen:
			x = p.parseCall(x)

		default:
			return x
		}
	}
}

// parseSubscript handles both `x[i]` and the slice forms `x[lo:hi]`, `x[lo:]`, `x[:hi]`.
func (p *parser) parseSubscript(x Expr) Expr {
	pos := p.tok.Pos
	p.advance() // '['

	var lo Expr
	if p.tok.Kind != Colon {
		lo = p.parseSliceBound()
	}

	if p.tok.Kind == Colon {
		p.advance()
		var hi Expr
		if p.tok.Kind != RBracket {
			hi = p.parseSliceBound()
		}
		p.expect(RBracket)
		return &Slice{X: x, Lo: lo, Hi: hi, P: pos}
	}

	p.expect(RBracket)
	if lo == nil {
		p.errorf(pos, "empty subscript; use [i] to index or [lo:hi] to slice")
		return x
	}
	return &Index{X: x, Index: lo, P: pos}
}

// parseSliceBound parses an index expression. Bounds are arithmetic, not full expressions,
// since `length(body.previous_threads) - 1` is the idiom and a comparison here would be a
// mistake.
func (p *parser) parseSliceBound() Expr { return p.parseAdditive() }

func (p *parser) parseCall(fn Expr) Expr {
	pos := p.tok.Pos
	p.advance() // '('

	call := &Call{Fn: fn, P: pos}
	for p.tok.Kind != RParen && p.tok.Kind != EOF {
		// A keyword argument is an identifier followed by '='. Everything the corpus passes
		// this way is documented as a defaulted parameter: mode=, format=, ignore_padding=.
		if p.tok.Kind == Ident && p.peek.Kind == Assign {
			name, npos := p.tok.Text, p.tok.Pos
			p.advance()
			p.advance()
			call.Keywords = append(call.Keywords, KeywordArg{P: npos, Name: name, Value: p.parseArgument()})
		} else {
			if len(call.Keywords) > 0 {
				p.errorf(p.tok.Pos, "positional arguments must come before keyword arguments")
			}
			call.Args = append(call.Args, p.parseArgument())
		}

		if p.tok.Kind != Comma {
			break
		}
		p.advance()
	}
	p.expect(RParen)
	return call
}

// parseArgument parses one argument. Arguments are full expressions: array functions take a
// predicate, as in any(attachments, .file_extension == "xls").
func (p *parser) parseArgument() Expr { return p.parseOr() }

func (p *parser) parsePrimary() Expr {
	if p.depth > maxDepth {
		p.errorf(p.tok.Pos, "expression nested too deeply (limit %d)", maxDepth)
		p.skipToRecovery()
		return &NullLit{P: p.tok.Pos}
	}
	p.depth++
	defer func() { p.depth-- }()

	tok := p.tok
	switch tok.Kind {
	case String:
		p.advance()
		return &StringLit{P: tok.Pos, Value: tok.Value, Raw: len(tok.Text) > 0 && tok.Text[0] == '\''}

	case Int:
		p.advance()
		n, err := strconv.ParseInt(tok.Text, 10, 64)
		if err != nil {
			p.errorf(tok.Pos, "integer %s is out of range", tok.Text)
		}
		return &IntLit{P: tok.Pos, Value: n, Text: tok.Text}

	case Float:
		p.advance()
		f, err := strconv.ParseFloat(tok.Text, 64)
		if err != nil {
			p.errorf(tok.Pos, "invalid number %s", tok.Text)
		}
		return &FloatLit{P: tok.Pos, Value: f, Text: tok.Text}

	case True, False:
		p.advance()
		return &BoolLit{P: tok.Pos, Value: tok.Kind == True}

	case Null:
		p.advance()
		return &NullLit{P: tok.Pos}

	case Ident:
		p.advance()
		return &Name{P: tok.Pos, Name: tok.Text}

	case List:
		p.advance()
		return &ListRef{P: tok.Pos, Name: tok.Value}

	case Dot:
		return p.parseScopeRef()

	case LParen:
		p.advance()
		inner := p.parseOr()
		p.expect(RParen)
		return &Paren{X: inner, P: tok.Pos}

	case LBracket:
		p.advance()
		elems := p.parseExprList(RBracket)
		p.expect(RBracket)
		return &ArrayLit{P: tok.Pos, Elems: elems}
	}

	p.errorf(tok.Pos, "expected an expression, found %s", describe(tok))
	p.skipToRecovery()
	return &NullLit{P: tok.Pos}
}

// parseScopeRef reads a run of leading dots and the field name that may follow.
//
// `.` is the innermost loop item, `..` its parent, `...` the grandparent. The dots and the
// field name are not separated, so `..email` is the parent's `email` field — which is why
// the lexer emits dots individually and the count is made here.
func (p *parser) parseScopeRef() Expr {
	pos := p.tok.Pos
	dots := 0
	for p.tok.Kind == Dot {
		dots++
		p.advance()
	}

	var x Expr = &ScopeRef{P: pos, Up: dots - 1}

	// A field name immediately after the dots belongs to the scope reference: the last dot
	// serves both as the scope marker and as the access.
	if p.tok.Kind == Ident {
		x = &Field{X: x, Name: p.tok.Text, P: pos}
		p.advance()
	}
	return x
}

// parseExprList reads comma-separated expressions up to (not including) end.
func (p *parser) parseExprList(end Kind) []Expr {
	var list []Expr
	for p.tok.Kind != end && p.tok.Kind != EOF {
		before := p.tok.Pos
		list = append(list, p.parseOr())

		if p.tok.Kind != Comma {
			break
		}
		p.advance()

		// A trailing comma before the closing bracket is accepted rather than reported:
		// rules are hand-edited and this is never ambiguous.
		if p.tok.Kind == end {
			break
		}
		if p.tok.Pos == before {
			// The element made no progress; bail out instead of looping forever.
			p.advance()
		}
	}
	return list
}

// skipToRecovery advances to a token that can plausibly start or separate the next element,
// so that one syntax error yields one diagnostic rather than a cascade.
func (p *parser) skipToRecovery() {
	for {
		switch p.tok.Kind {
		case EOF, Comma, RParen, RBracket, And, Or:
			return
		}
		p.advance()
	}
}
