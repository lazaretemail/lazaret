// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"fmt"
	"strings"
)

// Expr is any MQL expression.
//
// MQL has no statements. A rule is one expression, which for detection rules evaluates to a
// boolean and for insight queries evaluates to whatever the author wanted — an array of
// attachment names, a string, a count. The evaluator is therefore value-returning, with a
// boolean interpretation layered on top, rather than a predicate engine.
type Expr interface {
	// Pos is the position of the expression's first token.
	Pos() Pos

	// String renders the expression back to MQL. It is used by the formatter and in
	// diagnostics, and round-trips: parsing the output yields an equivalent tree.
	String() string

	exprNode()
}

// ---------------------------------------------------------------------------
// Literals and names
// ---------------------------------------------------------------------------

// StringLit is a quoted string. Raw records whether it was written with single quotes, so
// the formatter can preserve the author's choice — it matters for readability, since
// regexes are conventionally written raw to avoid doubling every backslash.
type StringLit struct {
	P     Pos
	Value string
	Raw   bool
}

// IntLit is an integer literal.
type IntLit struct {
	P     Pos
	Value int64
	Text  string
}

// FloatLit is a floating-point literal.
type FloatLit struct {
	P     Pos
	Value float64
	Text  string
}

// BoolLit is true or false.
type BoolLit struct {
	P     Pos
	Value bool
}

// NullLit is the null literal.
type NullLit struct{ P Pos }

// Name is a bare name resolved against the message data model, such as `sender`, or the
// head of a qualified function name, such as the `strings` in `strings.icontains`.
type Name struct {
	P    Pos
	Name string
}

// ListRef is a named list reference, written `$org_domains`.
type ListRef struct {
	P    Pos
	Name string
}

// ScopeRef is the loop item of an enclosing scope, written as a run of leading dots.
//
// Up counts how far to climb: `.` is the innermost item (Up 0), `..` its parent (Up 1),
// `...` the grandparent (Up 2). The docs describe only `.` and `..`, but real rules nest
// three deep and use `...`, so the rule generalises rather than stopping at two.
type ScopeRef struct {
	P  Pos
	Up int
}

// ---------------------------------------------------------------------------
// Composite and postfix
// ---------------------------------------------------------------------------

// ArrayLit is an inline array, `["a", "b"]`.
type ArrayLit struct {
	P     Pos
	Elems []Expr
}

// TupleLit is a parenthesised value set, as on the right of `in ("a", "b")` or in the
// clause list of `2 of (...)`. It is syntactically distinct from an array literal and only
// legal in those positions, so it keeps its own node rather than being folded into one.
type TupleLit struct {
	P     Pos
	Elems []Expr
}

// Field is member access, `X.name`.
type Field struct {
	X    Expr
	Name string
	P    Pos
}

// Index is subscripting, `X[i]`.
type Index struct {
	X     Expr
	Index Expr
	P     Pos
}

// Slice is `X[lo:hi]`. Either bound may be nil for an open end.
type Slice struct {
	X      Expr
	Lo, Hi Expr
	P      Pos
}

// KeywordArg is a named argument, `mode="aggressive"`.
//
// The published function signatures show these as defaulted parameters, and the corpus uses
// them heavily, but no syntax page documents the form.
type KeywordArg struct {
	P     Pos
	Name  string
	Value Expr
}

// Call applies a function. Fn is an arbitrary expression rather than a name, because calls
// are first-class postfix: rules chain them, as in
// strings.parse_email(network.whois(d).registrant_email).domain.root_domain.
type Call struct {
	Fn       Expr
	Args     []Expr
	Keywords []KeywordArg
	P        Pos
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

// Unary is `not X` or `-X`.
type Unary struct {
	Op Kind
	X  Expr
	P  Pos
}

// Binary is any infix operator: arithmetic, comparison, `and`, `or`.
type Binary struct {
	Op   Kind
	X, Y Expr
	P    Pos
}

// Range is a chained comparison, `lo < x <= hi`.
//
// Only `<` and `<=` chain. It is not sugar for two Binary nodes because the middle operand
// must be evaluated once — it is routinely an expensive call such as
// `4 < strings.levenshtein(a, b) <= 7`.
type Range struct {
	Lo   Expr
	OpLo Kind
	X    Expr
	OpHi Kind
	Hi   Expr
	P    Pos
}

// Membership is membership: `x in (...)`, `x in~ (...)`, `x not in $list`, `x in array_field`.
//
// The right side may be a tuple of literals, a named list, or any expression yielding an
// array — `x in arr` is defined as shorthand for `any(arr, . == x)`.
type Membership struct {
	X           Expr
	Set         Expr
	Negated     bool
	Insensitive bool
	P           Pos
}

// IsNull is `x is null` or `x is not null`.
//
// Undocumented — it appears in no published syntax reference — but used 421 times in the
// public corpus, so it is not optional.
type IsNull struct {
	X       Expr
	Negated bool
	P       Pos
}

// OfForm distinguishes the surface syntaxes of the threshold operator.
type OfForm uint8

const (
	// OfCount is `N of (...)`.
	OfCount OfForm = iota
	// OfAny is `any of (...)`, equivalent to a threshold of 1.
	OfAny
	// OfAll is `all of (...)`, equivalent to a threshold of every clause.
	OfAll
	// OfNone is `none of (...)`: true when no clause is true.
	OfNone
)

// Threshold is the threshold operator, true when at least Count of its clauses are true.
//
// The docs describe only the numeric form. The word forms appear in the corpus and mean the
// same thing with the threshold implied, so they are kept as distinct surface forms rather
// than rewritten, to let the formatter preserve what the author wrote.
type Threshold struct {
	Form    OfForm
	Count   Expr // non-nil only for OfCount
	Clauses []Expr
	P       Pos
}

// Paren preserves explicit grouping so that formatting round-trips.
//
// Parentheses are not merely cosmetic in MQL: `not` binds more loosely than comparison, and
// `and` more tightly than `or`, which Sublime's own documentation calls out as a common
// source of silently wrong rules. Dropping the author's grouping when reformatting would
// make that trap worse.
type Paren struct {
	X Expr
	P Pos
}

// ---------------------------------------------------------------------------

func (e *StringLit) Pos() Pos  { return e.P }
func (e *IntLit) Pos() Pos     { return e.P }
func (e *FloatLit) Pos() Pos   { return e.P }
func (e *BoolLit) Pos() Pos    { return e.P }
func (e *NullLit) Pos() Pos    { return e.P }
func (e *Name) Pos() Pos       { return e.P }
func (e *ListRef) Pos() Pos    { return e.P }
func (e *ScopeRef) Pos() Pos   { return e.P }
func (e *ArrayLit) Pos() Pos   { return e.P }
func (e *TupleLit) Pos() Pos   { return e.P }
func (e *Field) Pos() Pos      { return e.P }
func (e *Index) Pos() Pos      { return e.P }
func (e *Slice) Pos() Pos      { return e.P }
func (e *Call) Pos() Pos       { return e.P }
func (e *Unary) Pos() Pos      { return e.P }
func (e *Binary) Pos() Pos     { return e.P }
func (e *Range) Pos() Pos      { return e.P }
func (e *Membership) Pos() Pos { return e.P }
func (e *IsNull) Pos() Pos     { return e.P }
func (e *Threshold) Pos() Pos  { return e.P }
func (e *Paren) Pos() Pos      { return e.P }

func (*StringLit) exprNode()  {}
func (*IntLit) exprNode()     {}
func (*FloatLit) exprNode()   {}
func (*BoolLit) exprNode()    {}
func (*NullLit) exprNode()    {}
func (*Name) exprNode()       {}
func (*ListRef) exprNode()    {}
func (*ScopeRef) exprNode()   {}
func (*ArrayLit) exprNode()   {}
func (*TupleLit) exprNode()   {}
func (*Field) exprNode()      {}
func (*Index) exprNode()      {}
func (*Slice) exprNode()      {}
func (*Call) exprNode()       {}
func (*Unary) exprNode()      {}
func (*Binary) exprNode()     {}
func (*Range) exprNode()      {}
func (*Membership) exprNode() {}
func (*IsNull) exprNode()     {}
func (*Threshold) exprNode()  {}
func (*Paren) exprNode()      {}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

func (e *StringLit) String() string {
	if e.Raw {
		return "'" + strings.ReplaceAll(e.Value, "'", "''") + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range e.Value {
		switch r {
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (e *IntLit) String() string   { return e.Text }
func (e *FloatLit) String() string { return e.Text }

func (e *BoolLit) String() string {
	if e.Value {
		return "true"
	}
	return "false"
}

func (e *NullLit) String() string { return "null" }
func (e *Name) String() string    { return e.Name }
func (e *ListRef) String() string { return "$" + e.Name }

func (e *ScopeRef) String() string { return strings.Repeat(".", e.Up+1) }

func (e *ArrayLit) String() string { return "[" + joinExprs(e.Elems) + "]" }
func (e *TupleLit) String() string { return "(" + joinExprs(e.Elems) + ")" }

func (e *Field) String() string {
	// A field on a scope reference has no separating dot of its own: the scope reference is
	// already written as dots, so `.` plus `href_url` is ".href_url", not "..href_url".
	if s, ok := e.X.(*ScopeRef); ok {
		return s.String() + e.Name
	}
	return e.X.String() + "." + e.Name
}

func (e *Index) String() string { return fmt.Sprintf("%s[%s]", e.X, e.Index) }

func (e *Slice) String() string {
	var lo, hi string
	if e.Lo != nil {
		lo = e.Lo.String()
	}
	if e.Hi != nil {
		hi = e.Hi.String()
	}
	return fmt.Sprintf("%s[%s:%s]", e.X, lo, hi)
}

func (e *Call) String() string {
	parts := make([]string, 0, len(e.Args)+len(e.Keywords))
	for _, a := range e.Args {
		parts = append(parts, a.String())
	}
	for _, k := range e.Keywords {
		parts = append(parts, k.Name+"="+k.Value.String())
	}
	return e.Fn.String() + "(" + strings.Join(parts, ", ") + ")"
}

func (e *Unary) String() string {
	if e.Op == Not {
		return "not " + e.X.String()
	}
	return "-" + e.X.String()
}

func (e *Binary) String() string {
	return e.X.String() + " " + operatorText(e.Op) + " " + e.Y.String()
}

func (e *Range) String() string {
	return fmt.Sprintf("%s %s %s %s %s",
		e.Lo, operatorText(e.OpLo), e.X, operatorText(e.OpHi), e.Hi)
}

func (e *Membership) String() string {
	op := "in"
	if e.Insensitive {
		op = "in~"
	}
	if e.Negated {
		op = "not " + op
	}
	return e.X.String() + " " + op + " " + e.Set.String()
}

func (e *IsNull) String() string {
	if e.Negated {
		return e.X.String() + " is not null"
	}
	return e.X.String() + " is null"
}

func (e *Threshold) String() string {
	var head string
	switch e.Form {
	case OfAny:
		head = "any"
	case OfAll:
		head = "all"
	case OfNone:
		head = "none"
	default:
		head = e.Count.String()
	}
	return head + " of (" + joinExprs(e.Clauses) + ")"
}

func (e *Paren) String() string { return "(" + e.X.String() + ")" }

func joinExprs(list []Expr) string {
	parts := make([]string, len(list))
	for i, e := range list {
		parts[i] = e.String()
	}
	return strings.Join(parts, ", ")
}

// operatorText renders an operator token without the quotes that Kind.String adds.
func operatorText(k Kind) string {
	switch k {
	case Eq:
		return "=="
	case NotEq:
		return "!="
	case IEq:
		return "=~"
	case INotEq:
		return "!~"
	case Lt:
		return "<"
	case LtEq:
		return "<="
	case Gt:
		return ">"
	case GtEq:
		return ">="
	case Plus:
		return "+"
	case Minus:
		return "-"
	case Star:
		return "*"
	case Slash:
		return "/"
	case Percent:
		return "%"
	case And:
		return "and"
	case Or:
		return "or"
	case Not:
		return "not"
	}
	return k.String()
}

// Walk calls fn for every node in the tree, depth-first, parents before children. If fn
// returns false the node's children are skipped.
func Walk(e Expr, fn func(Expr) bool) {
	if e == nil || !fn(e) {
		return
	}
	switch n := e.(type) {
	case *ArrayLit:
		walkAll(n.Elems, fn)
	case *TupleLit:
		walkAll(n.Elems, fn)
	case *Field:
		Walk(n.X, fn)
	case *Index:
		Walk(n.X, fn)
		Walk(n.Index, fn)
	case *Slice:
		Walk(n.X, fn)
		Walk(n.Lo, fn)
		Walk(n.Hi, fn)
	case *Call:
		Walk(n.Fn, fn)
		walkAll(n.Args, fn)
		for _, k := range n.Keywords {
			Walk(k.Value, fn)
		}
	case *Unary:
		Walk(n.X, fn)
	case *Binary:
		Walk(n.X, fn)
		Walk(n.Y, fn)
	case *Range:
		Walk(n.Lo, fn)
		Walk(n.X, fn)
		Walk(n.Hi, fn)
	case *Membership:
		Walk(n.X, fn)
		Walk(n.Set, fn)
	case *IsNull:
		Walk(n.X, fn)
	case *Threshold:
		Walk(n.Count, fn)
		walkAll(n.Clauses, fn)
	case *Paren:
		Walk(n.X, fn)
	}
}

func walkAll(list []Expr, fn func(Expr) bool) {
	for _, e := range list {
		Walk(e, fn)
	}
}
