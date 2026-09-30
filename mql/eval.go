// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"context"
	"fmt"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
)

// Evaluation walks a checked expression against one message.
//
// This is an interpreter for MQL, not a host-language eval: nothing here compiles or runs
// Go, and a rule can only read the message and call functions from the registry. What it
// can still do is spend unbounded time, since rule text is attacker-influenced in a
// multi-tenant deployment and the corpus already contains a 242 KB expression. So every
// step decrements a budget and periodically honours context cancellation, and the
// capability boundary keeps anything that touches the network or the filesystem behind an
// interface the caller supplies.

// Verdict is the outcome of evaluating a rule against a message.
type Verdict uint8

const (
	// NoMatch: the rule ran to completion and did not fire.
	NoMatch Verdict = iota

	// Match: the rule fired.
	Match

	// Indeterminate: the rule could not be decided, because something it depends on was
	// unavailable.
	//
	// This is the verdict that makes a partial engine honest. Collapsing it into NoMatch
	// would turn "the model is offline" into "this message is fine", which is how an
	// outage becomes a missed attack.
	Indeterminate
)

func (v Verdict) String() string {
	switch v {
	case Match:
		return "match"
	case Indeterminate:
		return "indeterminate"
	default:
		return "no-match"
	}
}

// Result is what one evaluation produced.
type Result struct {
	Verdict Verdict

	// Value is what the expression evaluated to. Detection rules yield a boolean; insight
	// queries yield whatever they were written to return.
	Value Value

	// Missing lists the capabilities the rule asked for and could not get.
	Missing []enrich.Capability

	// Err is set only for a failure that is not about a missing capability — a regular
	// expression that will not compile, for instance.
	Err error
}

// EvalOptions configure an evaluation.
type EvalOptions struct {
	// Registry is the function set. Nil means the standard one.
	Registry *Registry

	// Enricher provides everything the message alone cannot answer. Nil means none is
	// available, and every such call reports its capability as missing.
	Enricher Enricher

	// Lists resolves named lists. Nil means none are configured, and a membership test
	// against one yields null rather than false — an unconfigured list is not an empty
	// list, and treating it as one silently disables rules.
	Lists ListResolver

	// MaxSteps bounds the work one rule may do. Rule text can be attacker-influenced in a
	// multi-tenant deployment, and a rule that never finishes is a denial of service.
	MaxSteps int
}

// DefaultMaxSteps bounds evaluation. The largest rule in the public corpus is a 242 KB
// expression, so the ceiling has to be generous; it is here to stop runaway work, not to
// police complexity.
const DefaultMaxSteps = 50_000_000

// ListResolver answers membership questions about named lists.
type ListResolver interface {
	// Contains reports whether a list holds a value. The third result is false when the
	// list is not configured at all, which is different from it not containing the value.
	Contains(ctx context.Context, list string, value Value, fold bool) (found, known bool)

	// Elements returns a list's contents, for rules that iterate one directly.
	Elements(ctx context.Context, list string) ([]Value, bool)
}

// Enricher is the runtime half of the capability boundary declared in package enrich.
//
// It is one method rather than an interface per capability so that the evaluator does not
// need to know which service answers what: it asks for a capability and gets a value or a
// reason it cannot have one.
type Enricher interface {
	Enrich(ctx context.Context, cap enrich.Capability, args []Value, kwargs map[string]Value) (Value, error)
}

// Eval evaluates a checked rule against a message.
func Eval(ctx context.Context, checked *Checked, msg *mdm.MessageDataModel, opts *EvalOptions) *Result {
	if opts == nil {
		opts = &EvalOptions{}
	}
	e := &evaluator{
		ctx:     ctx,
		reg:     opts.Registry,
		enrich:  opts.Enricher,
		lists:   opts.Lists,
		budget:  opts.MaxSteps,
		tracker: &enrich.Tracker{},
	}
	if e.reg == nil {
		e.reg = NewRegistry()
	}
	if e.budget <= 0 {
		e.budget = DefaultMaxSteps
	}
	e.root = FromGo(msg)

	value, err := e.eval(checked.Expr)

	res := &Result{Value: value, Missing: e.tracker.Missing(), Err: err}
	switch {
	case err != nil:
		res.Verdict = Indeterminate
	case len(res.Missing) > 0 && !value.Truthy():
		// A rule that did not fire, but could not see everything it asked for, has not
		// actually cleared the message. Only a positive match is trustworthy here: the
		// rule found what it was looking for despite the gap.
		res.Verdict = Indeterminate
	case value.Truthy():
		res.Verdict = Match
	default:
		res.Verdict = NoMatch
	}
	return res
}

// evaluator walks a checked expression against one message.
type evaluator struct {
	ctx    context.Context
	reg    *Registry
	enrich Enricher
	lists  ListResolver
	root   Value

	// scopes is the stack of loop items, innermost last, mirroring the checker's.
	scopes []Value

	tracker *enrich.Tracker
	budget  int
}

// errBudget is returned when a rule exceeds its step budget.
var errBudget = fmt.Errorf("mql: evaluation exceeded its step budget")

func (e *evaluator) step() error {
	if e.budget--; e.budget <= 0 {
		return errBudget
	}
	if e.budget%4096 == 0 {
		// Cancellation is checked periodically rather than every step: a message being
		// analysed after its request has gone away is wasted work.
		select {
		case <-e.ctx.Done():
			return e.ctx.Err()
		default:
		}
	}
	return nil
}

func (e *evaluator) eval(expr Expr) (Value, error) {
	if err := e.step(); err != nil {
		return NullValue, err
	}

	switch n := expr.(type) {
	case *StringLit:
		return StringValue(n.Value), nil
	case *IntLit:
		return IntValue(n.Value), nil
	case *FloatLit:
		return FloatValue(n.Value), nil
	case *BoolLit:
		return BoolValue(n.Value), nil
	case *NullLit:
		return NullValue, nil
	case *Paren:
		return e.eval(n.X)

	case *Name:
		return e.recordUnavailable(e.root.Field(n.Name)), nil

	case *ScopeRef:
		idx := len(e.scopes) - 1 - n.Up
		if idx < 0 || idx >= len(e.scopes) {
			return NullValue, nil
		}
		return e.scopes[idx], nil

	case *ListRef:
		return e.listElements(n.Name)

	case *Field:
		base, err := e.eval(n.X)
		if err != nil {
			return NullValue, err
		}
		return e.recordUnavailable(base.Field(n.Name)), nil

	case *Index:
		return e.evalIndex(n)
	case *Slice:
		return e.evalSlice(n)
	case *ArrayLit:
		return e.evalList(n.Elems)
	case *TupleLit:
		return e.evalList(n.Elems)
	case *Call:
		return e.evalCall(n)
	case *Unary:
		return e.evalUnary(n)
	case *Binary:
		return e.evalBinary(n)
	case *Range:
		return e.evalRange(n)
	case *Membership:
		return e.evalMembership(n)
	case *IsNull:
		v, err := e.eval(n.X)
		if err != nil {
			return NullValue, err
		}
		return BoolValue(v.IsNull() != n.Negated), nil
	case *Threshold:
		return e.evalThreshold(n)
	}
	return NullValue, nil
}

func (e *evaluator) evalList(exprs []Expr) (Value, error) {
	out := make([]Value, 0, len(exprs))
	for _, ex := range exprs {
		v, err := e.eval(ex)
		if err != nil {
			return NullValue, err
		}
		out = append(out, v)
	}
	return ArrayValue(out), nil
}

func (e *evaluator) evalIndex(n *Index) (Value, error) {
	base, err := e.eval(n.X)
	if err != nil {
		return NullValue, err
	}
	idx, err := e.eval(n.Index)
	if err != nil {
		return NullValue, err
	}

	// A string key indexes a map or a JSON object; a number indexes an array.
	if key, ok := idx.AsString(); ok && base.Kind() != mdm.KindArray {
		return e.recordUnavailable(base.Field(key)), nil
	}
	i, ok := idx.AsInt()
	if !ok {
		return NullValue, nil
	}
	return base.Index(i), nil
}

func (e *evaluator) evalSlice(n *Slice) (Value, error) {
	base, err := e.eval(n.X)
	if err != nil {
		return NullValue, err
	}
	if base.IsNull() {
		// Documented: "If the string, start position, or end position is null, the slice
		// returns null." Falling through to the array path would answer [] instead, which
		// is a different claim — that there was a collection and it was empty.
		return NullValue, nil
	}

	bound := func(ex Expr, def int64) (int64, bool, error) {
		if ex == nil {
			return def, true, nil
		}
		v, err := e.eval(ex)
		if err != nil {
			return 0, false, err
		}
		i, ok := v.AsInt()
		return i, ok, nil
	}

	if s, ok := base.AsString(); ok {
		runes := []rune(s)
		lo, okLo, err := bound(n.Lo, 0)
		if err != nil {
			return NullValue, err
		}
		hi, okHi, err := bound(n.Hi, int64(len(runes)))
		if err != nil {
			return NullValue, err
		}
		// Documented: a null operand anywhere in a slice makes the whole slice null.
		if !okLo || !okHi {
			return NullValue, nil
		}
		lo, hi = clamp(lo, 0, int64(len(runes))), clamp(hi, 0, int64(len(runes)))
		if lo >= hi {
			return StringValue(""), nil
		}
		return StringValue(string(runes[lo:hi])), nil
	}

	elems := base.Elements()
	lo, okLo, err := bound(n.Lo, 0)
	if err != nil {
		return NullValue, err
	}
	hi, okHi, err := bound(n.Hi, int64(len(elems)))
	if err != nil {
		return NullValue, err
	}
	if !okLo || !okHi {
		return NullValue, nil
	}
	// Out-of-range array bounds clamp, which is what the documentation says, and is
	// different from an out-of-range index, which is null.
	lo, hi = clamp(lo, 0, int64(len(elems))), clamp(hi, 0, int64(len(elems)))
	if lo >= hi {
		return ArrayValue(nil), nil
	}
	return ArrayValue(elems[lo:hi]), nil
}

func clamp(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (e *evaluator) evalUnary(n *Unary) (Value, error) {
	v, err := e.eval(n.X)
	if err != nil {
		return NullValue, err
	}
	switch n.Op {
	case Not:
		if b, ok := v.AsBool(); ok {
			return BoolValue(!b), nil
		}
		// not null is null: Kleene logic, recorded as inferred in docs/SEMANTICS.md.
		return NullValue, nil
	case Minus:
		if i, ok := v.AsInt(); ok && v.Kind() == mdm.KindInt {
			return IntValue(-i), nil
		}
		if f, ok := v.AsFloat(); ok {
			return FloatValue(-f), nil
		}
	}
	return NullValue, nil
}

func (e *evaluator) evalBinary(n *Binary) (Value, error) {
	switch n.Op {
	case And, Or:
		return e.evalLogical(n)
	}

	left, err := e.eval(n.X)
	if err != nil {
		return NullValue, err
	}
	right, err := e.eval(n.Y)
	if err != nil {
		return NullValue, err
	}

	switch n.Op {
	case Eq:
		return left.Equal(right, false), nil
	case NotEq:
		return negate(left.Equal(right, false)), nil
	case IEq:
		return left.Equal(right, true), nil
	case INotEq:
		return negate(left.Equal(right, true)), nil

	case Lt, LtEq, Gt, GtEq:
		cmp, ok := left.Compare(right)
		if !ok {
			return NullValue, nil
		}
		switch n.Op {
		case Lt:
			return BoolValue(cmp < 0), nil
		case LtEq:
			return BoolValue(cmp <= 0), nil
		case Gt:
			return BoolValue(cmp > 0), nil
		default:
			return BoolValue(cmp >= 0), nil
		}
	}
	return arithmetic(n.Op, left, right), nil
}

// evalLogical implements `and` and `or` with Kleene three-valued logic.
//
// Short-circuiting is not merely an optimisation here. A rule written as
// `type.inbound and ml.link_analysis(...)` expects the expensive half not to run on
// outbound mail, and evaluating it anyway would turn a cheap rule into a slow one and
// report a capability as missing that the rule never actually needed.
func (e *evaluator) evalLogical(n *Binary) (Value, error) {
	left, err := e.eval(n.X)
	if err != nil {
		return NullValue, err
	}
	lb, lok := left.AsBool()

	if n.Op == And && lok && !lb {
		// false and anything is false, even null.
		return FalseValue, nil
	}
	if n.Op == Or && lok && lb {
		return TrueValue, nil
	}

	right, err := e.eval(n.Y)
	if err != nil {
		return NullValue, err
	}
	rb, rok := right.AsBool()

	if n.Op == And {
		switch {
		case rok && !rb:
			return FalseValue, nil
		case lok && rok:
			return BoolValue(lb && rb), nil
		}
		return NullValue, nil
	}
	switch {
	case rok && rb:
		return TrueValue, nil
	case lok && rok:
		return BoolValue(lb || rb), nil
	}
	return NullValue, nil
}

func negate(v Value) Value {
	if b, ok := v.AsBool(); ok {
		return BoolValue(!b)
	}
	return NullValue
}

func arithmetic(op Kind, left, right Value) Value {
	// Integer arithmetic stays integral, including division: 5 / 2 is 2, and 5 / 2.0 is
	// 2.5. That distinction is documented and rules rely on it.
	if left.Kind() == mdm.KindInt && right.Kind() == mdm.KindInt {
		a, _ := left.AsInt()
		b, _ := right.AsInt()
		switch op {
		case Plus:
			return IntValue(a + b)
		case Minus:
			return IntValue(a - b)
		case Star:
			return IntValue(a * b)
		case Slash:
			if b == 0 {
				return NullValue
			}
			return IntValue(a / b)
		case Percent:
			if b == 0 {
				return NullValue
			}
			return IntValue(a % b)
		}
		return NullValue
	}

	a, aok := left.AsFloat()
	b, bok := right.AsFloat()
	if !aok || !bok {
		return NullValue
	}
	switch op {
	case Plus:
		return FloatValue(a + b)
	case Minus:
		return FloatValue(a - b)
	case Star:
		return FloatValue(a * b)
	case Slash:
		if b == 0 {
			return NullValue
		}
		return FloatValue(a / b)
	case Percent:
		if b == 0 {
			return NullValue
		}
		return FloatValue(float64(int64(a) % int64(b)))
	}
	return NullValue
}

// evalRange evaluates `lo < x <= hi`, taking care to evaluate the middle operand once.
// It is routinely an expensive call such as strings.levenshtein.
func (e *evaluator) evalRange(n *Range) (Value, error) {
	mid, err := e.eval(n.X)
	if err != nil {
		return NullValue, err
	}
	lo, err := e.eval(n.Lo)
	if err != nil {
		return NullValue, err
	}

	lower, ok := compareOp(lo, mid, n.OpLo)
	if !ok {
		return NullValue, nil
	}
	if !lower {
		return FalseValue, nil
	}

	hi, err := e.eval(n.Hi)
	if err != nil {
		return NullValue, err
	}
	upper, ok := compareOp(mid, hi, n.OpHi)
	if !ok {
		return NullValue, nil
	}
	return BoolValue(upper), nil
}

func compareOp(a, b Value, op Kind) (bool, bool) {
	cmp, ok := a.Compare(b)
	if !ok {
		return false, false
	}
	if op == LtEq {
		return cmp <= 0, true
	}
	return cmp < 0, true
}

func (e *evaluator) evalMembership(n *Membership) (Value, error) {
	value, err := e.eval(n.X)
	if err != nil {
		return NullValue, err
	}

	// A named list is asked directly rather than materialised: the resolver may be backed
	// by a million-row feed, and pulling it into memory to answer one question would be
	// absurd.
	if ref, ok := n.Set.(*ListRef); ok {
		if e.lists == nil {
			e.tracker.Record(enrich.ListCapability(ref.Name))
			return NullValue, nil
		}
		found, known := e.lists.Contains(e.ctx, ref.Name, value, n.Insensitive)
		if !known {
			// An unconfigured list is not an empty list. Answering false would silently
			// switch off every rule that depends on it — and recording the list is what
			// makes that visible, because a bare null reads as a clean no-match at the
			// top level. $high_trust_sender_root_domains alone gates 683 corpus rules.
			e.tracker.Record(enrich.ListCapability(ref.Name))
			return NullValue, nil
		}
		return BoolValue(found != n.Negated), nil
	}

	set, err := e.eval(n.Set)
	if err != nil {
		return NullValue, err
	}
	if value.IsNull() {
		return NullValue, nil
	}

	// `x in arr` is defined as shorthand for `any(arr, . == x)`, so it inherits that
	// function's null behaviour: an unknown comparison does not decide the answer, but a
	// true one does.
	sawNull := false
	for _, elem := range set.Elements() {
		switch eq := value.Equal(elem, n.Insensitive); {
		case eq.Truthy():
			return BoolValue(!n.Negated), nil
		case eq.IsNull():
			sawNull = true
		}
	}
	if sawNull {
		return NullValue, nil
	}
	return BoolValue(n.Negated), nil
}

func (e *evaluator) listElements(name string) (Value, error) {
	if e.lists == nil {
		e.tracker.Record(enrich.ListCapability(name))
		return NullValue, nil
	}
	elems, known := e.lists.Elements(e.ctx, name)
	if !known {
		e.tracker.Record(enrich.ListCapability(name))
		return NullValue, nil
	}
	return ArrayValue(elems), nil
}

// evalThreshold counts how many clauses hold.
//
// Null clauses make `of` three-valued, the same way they do `and` and `or`: reaching the
// threshold on true clauses alone answers true whatever the undecided ones would have
// said, and otherwise an undecided clause means the answer is unknown rather than false,
// because it could have been the one that reached the threshold.
//
//	1 of (null, true)  -> true      the threshold is met without needing the null
//	1 of (null, false) -> null      the null could have met it
//	1 of (false, false) -> false    nothing undecided, and the threshold is not met
//
// Confirmed against Sublime's analyzer on 2026-09-18; see docs/SEMANTICS.md. This was
// originally implemented as a plain count in which a null simply failed to contribute,
// which answered false for the middle case.
func (e *evaluator) evalThreshold(n *Threshold) (Value, error) {
	need := 1
	switch n.Form {
	case OfAll:
		need = len(n.Clauses)
	case OfNone:
		need = 0
	case OfCount:
		v, err := e.eval(n.Count)
		if err != nil {
			return NullValue, err
		}
		i, ok := v.AsInt()
		if !ok {
			return NullValue, nil
		}
		need = int(i)
	}

	matched, unknown := 0, 0
	for _, clause := range n.Clauses {
		v, err := e.eval(clause)
		if err != nil {
			return NullValue, err
		}
		switch {
		case v.IsNull():
			unknown++
		case v.Truthy():
			matched++
			// Both short circuits stay sound under the three-valued rule: each returns a
			// verdict that no remaining clause, decided or not, could change.
			if n.Form == OfNone {
				return FalseValue, nil
			}
			if matched >= need {
				return TrueValue, nil
			}
		}
	}
	if n.Form == OfNone {
		if unknown > 0 {
			return NullValue, nil
		}
		return TrueValue, nil
	}
	if matched >= need {
		return TrueValue, nil
	}
	if unknown > 0 {
		return NullValue, nil
	}
	return FalseValue, nil
}

// recordUnavailable notes a capability whose answer was read and was not there.
//
// Called on every field access, and almost always does nothing: only a null produced
// by an enrichment that declared the field unanswerable carries a capability name.
//
// This is what makes partial availability reportable at the right grain. A service
// that answers ml.nlu_classifier's .entities but not its .intents used to make the
// whole capability look missing on every rule that touched it, including the ones
// that only read .entities and were answered perfectly well. Recording at the point
// of use means a rule is reported degraded when, and only when, it actually reached
// for something that was not there.
func (e *evaluator) recordUnavailable(v Value) Value {
	if cap := v.Unavailable(); cap != "" {
		e.tracker.Record(enrich.Capability(cap))
	}
	return v
}
