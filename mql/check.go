// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
)

// Checking resolves every name a rule uses against the data model and every call against
// the function registry, before the rule ever sees a message.
//
// The value of doing it at all is that `sender.emial` becomes an error with a caret under
// it rather than a silent null that makes the rule quietly never fire. A detection that
// fails closed and says nothing is worse than no detection, because someone believes it is
// working.
//
// The checker is deliberately lenient where MQL is dynamic. Rejecting a rule Sublime
// accepts breaks a detection someone depends on; accepting one we might have rejected only
// means the mistake surfaces at evaluation as null. Those costs are not symmetric, so
// anything genuinely ambiguous is allowed through.

// Checked is a rule that has passed the checker.
type Checked struct {
	// Expr is the type-checked expression tree.
	Expr Expr

	// Type is what the rule evaluates to. Detection rules yield a boolean; insight
	// queries legitimately yield arrays, strings or numbers.
	Type *mdm.Type

	// Capabilities are the enrichments this rule needs. A deployment that cannot provide
	// one of them will report the rule as indeterminate rather than as no-match, so this
	// is knowable before the rule is ever run.
	Capabilities []enrich.Capability

	// Lists are the named lists the rule references.
	Lists []string
}

// NeedsEnrichment reports whether the rule depends on anything beyond the message itself.
func (c *Checked) NeedsEnrichment() bool { return len(c.Capabilities) > 0 }

// CheckOptions configure a check.
type CheckOptions struct {
	// Registry is the function set. Nil means the standard one.
	Registry *Registry

	// Root is the type a bare name resolves against. Nil means the Message Data Model.
	Root *mdm.Type

	// RequireBoolean rejects a rule that does not evaluate to a boolean. Detection rules
	// want this; insight queries, whose whole purpose is to return a value, do not.
	RequireBoolean bool

	// KnownLists, when non-empty, restricts $list references to these names. A typo in a
	// list name is otherwise indistinguishable from an empty list, which silently turns a
	// detection off.
	KnownLists []string
}

// Check resolves and type-checks a parsed expression.
func Check(expr Expr, opts *CheckOptions) (*Checked, error) {
	if opts == nil {
		opts = &CheckOptions{}
	}
	c := &checker{
		reg:   opts.Registry,
		root:  opts.Root,
		opts:  opts,
		caps:  map[enrich.Capability]bool{},
		lists: map[string]bool{},
	}
	if c.reg == nil {
		c.reg = NewRegistry()
	}
	if c.root == nil {
		c.root = mdm.Root()
	}
	if len(opts.KnownLists) > 0 {
		c.knownLists = make(map[string]bool, len(opts.KnownLists))
		for _, n := range opts.KnownLists {
			c.knownLists[n] = true
		}
	}

	typ := c.expr(expr)

	if opts.RequireBoolean && typ != nil &&
		typ.Kind != mdm.KindBool && typ.Kind != mdm.KindAny &&
		typ.Kind != mdm.KindNull && typ.Kind != mdm.KindJSON {
		c.errorf(expr.Pos(), "a detection rule must evaluate to a boolean, but this is %s", typ.Describe())
	}

	out := &Checked{Expr: expr, Type: typ}
	for cap := range c.caps {
		out.Capabilities = append(out.Capabilities, cap)
	}
	sort.Slice(out.Capabilities, func(i, j int) bool { return out.Capabilities[i] < out.Capabilities[j] })
	for name := range c.lists {
		out.Lists = append(out.Lists, name)
	}
	sort.Strings(out.Lists)

	return out, c.errs.Sorted().Err()
}

// Compile parses and checks in one step.
func Compile(src string, opts *CheckOptions) (*Checked, error) {
	expr, err := Parse(src)
	if err != nil {
		return nil, err
	}
	return Check(expr, opts)
}

type checker struct {
	reg        *Registry
	root       *mdm.Type
	opts       *CheckOptions
	errs       ErrorList
	caps       map[enrich.Capability]bool
	lists      map[string]bool
	knownLists map[string]bool

	// scopes is the stack of loop item types. The innermost is last, so `.` reads the
	// end, `..` one before it, and so on for as many dots as the author wrote.
	scopes []*mdm.Type
}

func (c *checker) errorf(pos Pos, format string, args ...any) {
	if n := len(c.errs); n > 0 && c.errs[n-1].Pos == pos {
		return
	}
	c.errs = append(c.errs, &Error{Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

// expr returns the type of an expression, reporting any problems along the way.
func (c *checker) expr(e Expr) *mdm.Type {
	switch n := e.(type) {
	case *StringLit:
		return mdm.String
	case *IntLit:
		return mdm.Int
	case *FloatLit:
		return mdm.Float
	case *BoolLit:
		return mdm.Bool
	case *NullLit:
		return mdm.Null

	case *Name:
		return c.name(n)
	case *ListRef:
		return c.listRef(n)
	case *ScopeRef:
		return c.scopeRef(n)

	case *Paren:
		return c.expr(n.X)

	case *ArrayLit:
		return c.arrayLit(n)
	case *TupleLit:
		return c.tupleLit(n)

	case *Field:
		return c.field(n)
	case *Index:
		return c.index(n)
	case *Slice:
		return c.slice(n)
	case *Call:
		return c.call(n)

	case *Unary:
		return c.unary(n)
	case *Binary:
		return c.binary(n)
	case *Range:
		return c.rangeExpr(n)
	case *Membership:
		return c.membership(n)
	case *IsNull:
		// `is null` is a question about any value at all, so the operand's type is
		// irrelevant — but it still has to resolve, or a typo hides inside it.
		c.expr(n.X)
		return mdm.Bool
	case *Threshold:
		return c.threshold(n)
	}
	return mdm.Any
}

// name resolves a bare identifier against the model root.
//
// A name that is not a model field may still be the first segment of a function name, as
// in the `strings` of `strings.icontains`. Those are resolved by the call path instead, so
// an unresolvable name here is only an error if nothing later claims it.
func (c *checker) name(n *Name) *mdm.Type {
	if f, ok := c.root.Field(n.Name); ok {
		return f.Type
	}
	if c.isNamespace(n.Name) {
		// A function namespace used as a value. The call path handles the real case; this
		// keeps the error message useful if someone writes `strings` on its own.
		return mdm.Any
	}
	c.errorf(n.P, "no field %q on the message%s", n.Name, suggest(n.Name, c.root.FieldNames()))
	return mdm.Any
}

func (c *checker) isNamespace(name string) bool {
	prefix := name + "."
	for _, fn := range c.reg.Names() {
		if strings.HasPrefix(fn, prefix) {
			return true
		}
	}
	return false
}

func (c *checker) listRef(n *ListRef) *mdm.Type {
	c.lists[n.Name] = true
	if c.knownLists != nil && !c.knownLists[n.Name] {
		// A misspelled list is indistinguishable from an empty one at evaluation, which
		// silently turns a detection off. Worth catching when the caller knows the set.
		c.errorf(n.P, "no list named $%s", n.Name)
	}
	// Not every list holds strings. $org_vips holds people, and the corpus reads
	// `.display_name` and `.email` off its elements 75 times. Typing lists as strings
	// rejected all of those, so the element type is left open: what a list contains is a
	// property of the list, and the provider is what knows it.
	return mdm.AnyArray
}

// scopeRef resolves a run of leading dots to an enclosing loop item.
func (c *checker) scopeRef(n *ScopeRef) *mdm.Type {
	if len(c.scopes) == 0 {
		c.errorf(n.P, "%q refers to a loop item, but this is not inside any(), all(), filter() or map()", n.String())
		return mdm.Any
	}
	idx := len(c.scopes) - 1 - n.Up
	if idx < 0 {
		c.errorf(n.P, "%q climbs %d scopes but only %d %s open here",
			n.String(), n.Up, len(c.scopes), plural(len(c.scopes), "is", "are"))
		return mdm.Any
	}
	return c.scopes[idx]
}

func (c *checker) arrayLit(n *ArrayLit) *mdm.Type {
	if len(n.Elems) == 0 {
		return mdm.AnyArray
	}
	elem := c.expr(n.Elems[0])
	for _, e := range n.Elems[1:] {
		t := c.expr(e)
		if elem != nil && t != nil && !t.AssignableTo(elem) && !elem.AssignableTo(t) {
			// A heterogeneous array is legal — rules write [body.plain.raw,
			// body.html.raw] and also mix in nulls — so widen rather than complain.
			elem = mdm.Any
		}
	}
	return mdm.ArrayOf(elem)
}

func (c *checker) tupleLit(n *TupleLit) *mdm.Type {
	for _, e := range n.Elems {
		c.expr(e)
	}
	return mdm.AnyArray
}

// field resolves member access.
func (c *checker) field(n *Field) *mdm.Type {
	base := c.expr(n.X)

	// A call target such as `strings.icontains` is a Field over a Name. It is resolved by
	// the call path, so nothing is reported here.
	if name, ok := n.X.(*Name); ok && c.isNamespace(name.Name) {
		return mdm.Any
	}

	switch {
	case base == nil, base.Kind == mdm.KindAny, base.Kind == mdm.KindJSON, base.Kind == mdm.KindNull:
		// Nothing known about the base, so nothing can be said about the member.
		return mdm.Any

	case base.Kind == mdm.KindArray:
		// Reading a field off an array is how a rule says "this field, for every element".
		// MQL does not have that, and accepting it silently would hide a missing any().
		c.errorf(n.P, "%q is an array; use any(), all(), map() or an index to reach %q",
			exprText(n.X), n.Name)
		return mdm.Any

	case base.Kind != mdm.KindObject:
		c.errorf(n.P, "%s is %s and has no field %q", exprText(n.X), base.Describe(), n.Name)
		return mdm.Any
	}

	f, ok := base.Field(n.Name)
	if !ok {
		c.errorf(n.P, "no field %q on %s%s", n.Name, base.Describe(), suggest(n.Name, base.FieldNames()))
		return mdm.Any
	}
	return f.Type
}

func (c *checker) index(n *Index) *mdm.Type {
	base := c.expr(n.X)
	idx := c.expr(n.Index)

	switch base.KindOr(mdm.KindAny) {
	case mdm.KindArray:
		if idx != nil && !idx.Kind.Numeric() && idx.Kind != mdm.KindAny && idx.Kind != mdm.KindNull {
			c.errorf(n.Index.Pos(), "an array index must be a number, not %s", idx.Describe())
		}
		return base.Elem_()
	case mdm.KindMap:
		return base.Elem_()
	case mdm.KindJSON, mdm.KindAny, mdm.KindNull:
		// JSON traversal: `.json["key"]` yields another dynamic value.
		return mdm.JSON
	case mdm.KindString:
		c.errorf(n.P, "cannot index a string; use a slice such as [0:10] to take part of it")
		return mdm.Any
	}
	c.errorf(n.P, "cannot index %s", base.Describe())
	return mdm.Any
}

func (c *checker) slice(n *Slice) *mdm.Type {
	base := c.expr(n.X)
	for _, bound := range []Expr{n.Lo, n.Hi} {
		if bound == nil {
			continue
		}
		if t := c.expr(bound); t != nil && !t.Kind.Numeric() && t.Kind != mdm.KindAny && t.Kind != mdm.KindNull {
			c.errorf(bound.Pos(), "a slice bound must be a number, not %s", t.Describe())
		}
	}
	switch base.KindOr(mdm.KindAny) {
	case mdm.KindString, mdm.KindArray, mdm.KindAny, mdm.KindNull, mdm.KindJSON, mdm.KindBytes:
		// Slicing yields the same kind of thing it was given.
		return base
	}
	c.errorf(n.P, "cannot slice %s", base.Describe())
	return mdm.Any
}

// call checks a function call: that the function exists, that the arguments fit, and that
// any scope it introduces is visible to the right arguments.
func (c *checker) call(n *Call) *mdm.Type {
	name := callName(n.Fn)
	if name == "" {
		c.errorf(n.P, "this is not something that can be called")
		for _, a := range n.Args {
			c.expr(a)
		}
		return mdm.Any
	}

	fn, ok := c.reg.Lookup(name)
	if !ok {
		c.errorf(n.Fn.Pos(), "no function %q%s", name, suggest(name, c.reg.Names()))
		for _, a := range n.Args {
			c.expr(a)
		}
		return mdm.Any
	}

	if fn.Capability != "" {
		c.caps[fn.Capability] = true
	}

	argTypes := c.callArgs(n, fn)
	c.callKeywords(n, fn)

	switch {
	case fn.Returns != nil:
		return fn.Returns(argTypes)
	case fn.Return != nil:
		return fn.Return
	}
	return mdm.Any
}

// callArgs checks positional arguments, opening a loop scope for the array functions.
func (c *checker) callArgs(n *Call, fn *Func) []*mdm.Type {
	minArgs, maxArgs := fn.Arity()
	if got := len(n.Args); got < minArgs || (maxArgs >= 0 && got > maxArgs) {
		c.errorf(n.P, "%s takes %s, but got %d", fn.Name, arityText(minArgs, maxArgs), got)
	}

	types := make([]*mdm.Type, 0, len(n.Args))

	for i, arg := range n.Args {
		// The array functions bind `.` to an element of their first argument for every
		// argument after it. This is the only place the language introduces a scope.
		if fn.Scope == ScopeElement && i == 1 {
			elem := elemOfType(types)
			c.scopes = append(c.scopes, elem)
		}

		t := c.expr(arg)
		types = append(types, t)

		if want := paramType(fn, i); want != nil && t != nil && !t.AssignableTo(want) {
			c.errorf(arg.Pos(), "%s expects %s for %s, but got %s",
				fn.Name, want.Describe(), paramName(fn, i), t.Describe())
		}
	}

	if fn.Scope == ScopeElement && len(n.Args) > 1 {
		c.scopes = c.scopes[:len(c.scopes)-1]
	}
	return types
}

// elemOfType gives the loop item type for an array function's first argument.
func elemOfType(types []*mdm.Type) *mdm.Type {
	if len(types) == 0 {
		return mdm.Any
	}
	if e := types[0].Elem_(); e != nil {
		return e
	}
	// Iterating something that is not an array is an error the first argument's own check
	// already reported; Any keeps the body of the loop checkable regardless.
	return mdm.Any
}

func (c *checker) callKeywords(n *Call, fn *Func) {
	for _, kwArg := range n.Keywords {
		var want *Param
		for i := range fn.Keywords {
			if fn.Keywords[i].Name == kwArg.Name {
				want = &fn.Keywords[i]
				break
			}
		}
		t := c.expr(kwArg.Value)
		if want == nil {
			c.errorf(kwArg.P, "%s has no argument named %q%s", fn.Name, kwArg.Name, suggestKeywords(kwArg.Name, fn.Keywords))
			continue
		}
		if want.Type != nil && t != nil && !t.AssignableTo(want.Type) {
			c.errorf(kwArg.Value.Pos(), "%s expects %s for %s, but got %s",
				fn.Name, want.Type.Describe(), kwArg.Name, t.Describe())
		}
	}
}

func (c *checker) unary(n *Unary) *mdm.Type {
	t := c.expr(n.X)
	switch n.Op {
	case Not:
		if t != nil && t.Kind != mdm.KindBool && t.Kind != mdm.KindAny && t.Kind != mdm.KindNull {
			// MQL has no truthiness: the docs are explicit that JSON booleans need an
			// explicit == true, and the same applies everywhere else.
			c.errorf(n.P, "`not` needs a boolean, but this is %s", t.Describe())
		}
		return mdm.Bool
	case Minus:
		if t != nil && !t.Kind.Numeric() && t.Kind != mdm.KindAny && t.Kind != mdm.KindNull {
			c.errorf(n.P, "cannot negate %s", t.Describe())
			return mdm.Any
		}
		return t
	}
	return mdm.Any
}

func (c *checker) binary(n *Binary) *mdm.Type {
	left := c.expr(n.X)
	right := c.expr(n.Y)

	switch n.Op {
	case And, Or:
		for _, side := range []struct {
			t *mdm.Type
			e Expr
		}{{left, n.X}, {right, n.Y}} {
			if side.t != nil && side.t.Kind != mdm.KindBool &&
				side.t.Kind != mdm.KindAny && side.t.Kind != mdm.KindNull && side.t.Kind != mdm.KindJSON {
				c.errorf(side.e.Pos(), "`%s` needs a boolean, but this is %s", operatorText(n.Op), side.t.Describe())
			}
		}
		return mdm.Bool

	case Eq, NotEq, IEq, INotEq, Lt, LtEq, Gt, GtEq:
		if left != nil && right != nil && !left.Comparable(right) {
			c.errorf(n.P, "cannot compare %s with %s", left.Describe(), right.Describe())
		}
		if n.Op == IEq || n.Op == INotEq {
			// The case-insensitive operators are defined on strings only.
			c.requireTextual(n.X, left, operatorText(n.Op))
			c.requireTextual(n.Y, right, operatorText(n.Op))
		}
		return mdm.Bool

	case Plus, Minus, Star, Slash, Percent:
		// `+` is arithmetic only: string joining is strings.concat.
		result := mdm.Int
		for _, side := range []struct {
			t *mdm.Type
			e Expr
		}{{left, n.X}, {right, n.Y}} {
			if side.t == nil || side.t.Kind == mdm.KindAny || side.t.Kind == mdm.KindNull || side.t.Kind == mdm.KindJSON {
				result = mdm.Any
				continue
			}
			if !side.t.Kind.Numeric() {
				c.errorf(side.e.Pos(), "`%s` needs numbers, but this is %s", operatorText(n.Op), side.t.Describe())
				result = mdm.Any
				continue
			}
			if side.t.Kind == mdm.KindFloat && result == mdm.Int {
				result = mdm.Float
			}
		}
		return result
	}
	return mdm.Any
}

func (c *checker) requireTextual(e Expr, t *mdm.Type, op string) {
	if t == nil {
		return
	}
	switch t.Kind {
	case mdm.KindString, mdm.KindBytes, mdm.KindAny, mdm.KindNull, mdm.KindJSON:
		return
	}
	c.errorf(e.Pos(), "`%s` compares strings, but this is %s", op, t.Describe())
}

func (c *checker) rangeExpr(n *Range) *mdm.Type {
	lo := c.expr(n.Lo)
	mid := c.expr(n.X)
	hi := c.expr(n.Hi)
	for _, pair := range []struct {
		a, b *mdm.Type
		at   Expr
	}{{lo, mid, n.Lo}, {mid, hi, n.Hi}} {
		if pair.a != nil && pair.b != nil && !pair.a.Comparable(pair.b) {
			c.errorf(pair.at.Pos(), "cannot compare %s with %s in a range", pair.a.Describe(), pair.b.Describe())
		}
	}
	return mdm.Bool
}

// membership checks `x in y` in each of its three forms: a tuple of literals, a named
// list, or any expression yielding an array.
func (c *checker) membership(n *Membership) *mdm.Type {
	value := c.expr(n.X)
	set := c.expr(n.Set)

	if n.Insensitive {
		c.requireTextual(n.X, value, "in~")
	}

	switch set.KindOr(mdm.KindAny) {
	case mdm.KindArray, mdm.KindAny, mdm.KindNull, mdm.KindJSON:
		// Fine. Element compatibility is checked leniently below.
	case mdm.KindMap:
		c.errorf(n.Set.Pos(), "`in` needs a list or array; use keys() or values() on a map")
		return mdm.Bool
	default:
		c.errorf(n.Set.Pos(), "`in` needs a list or array, but this is %s", set.Describe())
		return mdm.Bool
	}

	if elem := set.Elem_(); elem != nil && value != nil && !value.Comparable(elem) {
		c.errorf(n.P, "cannot look for %s in a list of %s", value.Describe(), elem.Describe())
	}
	return mdm.Bool
}

func (c *checker) threshold(n *Threshold) *mdm.Type {
	if n.Count != nil {
		t := c.expr(n.Count)
		if t != nil && t.Kind != mdm.KindInt && t.Kind != mdm.KindAny {
			c.errorf(n.Count.Pos(), "the threshold before `of` must be a whole number, not %s", t.Describe())
		}
		if lit, ok := n.Count.(*IntLit); ok {
			switch {
			case lit.Value < 1:
				c.errorf(n.Count.Pos(), "a threshold of %d always holds; `of` needs at least 1", lit.Value)
			case lit.Value > int64(len(n.Clauses)):
				// Not merely useless: a threshold above the clause count can never be met,
				// so the rule is dead and nobody would notice.
				c.errorf(n.Count.Pos(), "a threshold of %d can never be met with %d clause%s",
					lit.Value, len(n.Clauses), plural(len(n.Clauses), "", "s"))
			}
		}
	}
	if len(n.Clauses) == 0 {
		c.errorf(n.P, "`of` needs at least one clause")
	}
	for _, clause := range n.Clauses {
		t := c.expr(clause)
		if t != nil && t.Kind != mdm.KindBool && t.Kind != mdm.KindAny && t.Kind != mdm.KindNull && t.Kind != mdm.KindJSON {
			c.errorf(clause.Pos(), "every clause of `of` must be a boolean, but this is %s", t.Describe())
		}
	}
	return mdm.Bool
}

// ---------------------------------------------------------------------------

// callName flattens a call target into a function name. Only a bare name or a dotted path
// of names can be one; anything else is a call on a computed value, which MQL does not
// have.
func callName(fn Expr) string {
	switch n := fn.(type) {
	case *Name:
		return n.Name
	case *Field:
		if base := callName(n.X); base != "" {
			return base + "." + n.Name
		}
	}
	return ""
}

// exprText renders an expression for a diagnostic, shortened so that a message about one
// field does not quote a whole rule back at the reader.
func exprText(e Expr) string {
	s := e.String()
	if len(s) > 48 {
		return s[:45] + "..."
	}
	return s
}

func arityText(minArgs, maxArgs int) string {
	switch {
	case maxArgs < 0:
		return fmt.Sprintf("at least %d argument%s", minArgs, plural(minArgs, "", "s"))
	case minArgs == maxArgs:
		return fmt.Sprintf("%d argument%s", minArgs, plural(minArgs, "", "s"))
	default:
		return fmt.Sprintf("between %d and %d arguments", minArgs, maxArgs)
	}
}

func paramType(fn *Func, i int) *mdm.Type {
	if i < len(fn.Params) {
		return fn.Params[i].Type
	}
	if fn.Variadic != nil {
		return fn.Variadic.Type
	}
	return nil
}

func paramName(fn *Func, i int) string {
	if i < len(fn.Params) {
		return fn.Params[i].Name
	}
	if fn.Variadic != nil {
		return fmt.Sprintf("%s %d", fn.Variadic.Name, i-len(fn.Params)+1)
	}
	return fmt.Sprintf("argument %d", i+1)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// suggest offers the closest known name, when there is one close enough to be worth
// offering. A wrong suggestion is worse than none: it sends the reader looking in the
// wrong place.
func suggest(got string, candidates []string) string {
	best, bestDist := "", 0
	limit := len(got)/3 + 1
	for _, cand := range candidates {
		d := editDistance(strings.ToLower(got), strings.ToLower(cand))
		if d <= limit && (best == "" || d < bestDist) {
			best, bestDist = cand, d
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf("; did you mean %q?", best)
}

func suggestKeywords(got string, params []Param) string {
	names := make([]string, len(params))
	for i, p := range params {
		names[i] = p.Name
	}
	if s := suggest(got, names); s != "" {
		return s
	}
	if len(names) > 0 {
		return fmt.Sprintf(" (it accepts %s)", strings.Join(names, ", "))
	}
	return ""
}

// editDistance is Levenshtein, used only for suggestions.
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, min(curr[j-1]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(br)]
}

// Portability warnings: things this engine accepts that Sublime's own validator does
// not.
//
// Not errors. The corpus contains roughly fourteen files using these forms, and
// rejecting real rules people run would be the wrong kind of strictness. But a rule
// author writing new content should be told, because the divergence is invisible
// until it reaches an engine that refuses it — and "compatible implementation" stops
// being true the moment someone writes MQL that only works here.
type Portability struct {
	Pos     Pos
	Form    string
	Message string
}

// PortabilityWarnings walks a compiled expression for constructs the reference
// implementation rejects.
func PortabilityWarnings(c *Checked) []Portability {
	if c == nil || c.Expr == nil {
		return nil
	}
	var out []Portability
	Walk(c.Expr, func(e Expr) bool {
		t, ok := e.(*Threshold)
		if !ok {
			return true
		}
		var form string
		switch t.Form {
		case OfAny:
			form = "any of"
		case OfAll:
			form = "all of"
		case OfNone:
			form = "none of"
		default:
			return true
		}
		out = append(out, Portability{
			Pos:  t.P,
			Form: form,
			Message: fmt.Sprintf("%q is accepted here but rejected by Sublime's validator; "+
				"the numeric form is portable", form),
		})
		return true
	})
	return out
}
