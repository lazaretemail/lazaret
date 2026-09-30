// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
)

// Value is a runtime MQL value.
//
// Null is a value here rather than an absence, and that is the single most important thing
// about this type. MQL's null rules are load-bearing and deliberately irregular —
// length(null) on a string is null but on an array is 0 — so every operation below states
// what it does with null, and the ones the documentation leaves open are decided in
// docs/SEMANTICS.md rather than by whatever the Go zero value happens to be.
type Value struct {
	kind mdm.Kind

	b bool
	i int64
	f float64
	s string

	// ref carries composites: []Value for arrays, map[string]Value for maps,
	// reflect.Value for a struct from the data model, and any for decoded JSON.
	ref any

	// unavail names the capability this null stands in for, when the null exists
	// because something could not be answered rather than because the data says so.
	//
	// Null either way — every operator treats it identically and no rule can tell
	// the difference, which is the point. What it adds is the ability to report
	// *why* a rule came out indeterminate, and to report it only for the rules that
	// actually read the missing part. A capability that answers .entities but not
	// .intents should not make a rule reading only .entities look degraded.
	unavail string
}

// UnavailableValue is a null that remembers which capability could not answer it.
func UnavailableValue(capability string) Value {
	return Value{kind: mdm.KindNull, unavail: capability}
}

// Unavailable returns the capability this null stands in for, or "".
func (v Value) Unavailable() string { return v.unavail }

// NullValue is the null value. Most operations on it produce it again.
var NullValue = Value{kind: mdm.KindNull}

// TrueValue and FalseValue save a constructor call in the hot path of boolean evaluation.
var (
	TrueValue  = Value{kind: mdm.KindBool, b: true}
	FalseValue = Value{kind: mdm.KindBool}
)

func BoolValue(b bool) Value {
	if b {
		return TrueValue
	}
	return FalseValue
}

func IntValue(i int64) Value      { return Value{kind: mdm.KindInt, i: i} }
func FloatValue(f float64) Value  { return Value{kind: mdm.KindFloat, f: f} }
func StringValue(s string) Value  { return Value{kind: mdm.KindString, s: s} }
func ArrayValue(vs []Value) Value { return Value{kind: mdm.KindArray, ref: vs} }

// BytesValue wraps binary content — an attachment's bytes, a rendered screenshot.
//
// Distinct from a string, and the distinction matters to callers rather than to the
// evaluator: AsBytes deliberately succeeds on a string too, so anything deciding
// "is this an image or some text" by calling AsBytes gets the wrong answer for every
// string. Kind is what answers that question.
func BytesValue(b []byte) Value { return Value{kind: mdm.KindBytes, ref: b} }

func MapValue(m map[string]Value) Value { return Value{kind: mdm.KindMap, ref: m} }

// JSONValue wraps a decoded JSON document. Its shape is not known until traversed, and a
// mismatched comparison against it yields null rather than false.
func JSONValue(v any) Value {
	if v == nil {
		return NullValue
	}
	return Value{kind: mdm.KindJSON, ref: v}
}

// Kind reports what sort of value this is.
func (v Value) Kind() mdm.Kind { return v.kind }

// IsNull reports whether the value is null.
func (v Value) IsNull() bool { return v.kind == mdm.KindNull }

// Truthy reports whether the value is exactly boolean true.
//
// MQL has no truthiness, so this is not a coercion: it is the question "did this rule
// fire?", and null and false both answer no. A rule that could not be evaluated must never
// read as a clean no-match, which is why indeterminate is tracked separately.
func (v Value) Truthy() bool { return v.kind == mdm.KindBool && v.b }

// AsBool returns the boolean and whether the value was one.
func (v Value) AsBool() (bool, bool) { return v.b, v.kind == mdm.KindBool }

// AsString returns the text and whether the value was textual.
func (v Value) AsString() (string, bool) {
	switch v.kind {
	case mdm.KindString:
		return v.s, true
	case mdm.KindBytes:
		if b, ok := v.ref.([]byte); ok {
			return string(b), true
		}
	case mdm.KindJSON:
		if s, ok := v.ref.(string); ok {
			return s, true
		}
	}
	return "", false
}

// AsBytes returns the raw bytes and whether the value carried any.
//
// Attachment content is bytes, and handing it to a scanner through AsString would copy a
// potentially large payload twice for no reason.
func (v Value) AsBytes() ([]byte, bool) {
	switch v.kind {
	case mdm.KindBytes:
		if b, ok := v.ref.([]byte); ok {
			return b, true
		}
	case mdm.KindString:
		return []byte(v.s), true
	}
	return nil, false
}

// AsFloat returns the value as a float and whether it was numeric. Integers promote, as
// the documentation requires.
func (v Value) AsFloat() (float64, bool) {
	switch v.kind {
	case mdm.KindInt:
		return float64(v.i), true
	case mdm.KindFloat:
		return v.f, true
	case mdm.KindJSON:
		if f, ok := v.ref.(float64); ok {
			return f, true
		}
	}
	return 0, false
}

// AsInt returns the value as an integer and whether it was one.
func (v Value) AsInt() (int64, bool) {
	switch v.kind {
	case mdm.KindInt:
		return v.i, true
	case mdm.KindFloat:
		return int64(v.f), v.f == float64(int64(v.f))
	case mdm.KindJSON:
		if f, ok := v.ref.(float64); ok {
			return int64(f), f == float64(int64(f))
		}
	}
	return 0, false
}

// Elements returns the value as a slice, materialising a data-model array on demand.
//
// A null array yields nothing rather than an error: length(null array) is documented as 0,
// and iterating one has to agree with that.
func (v Value) Elements() []Value {
	switch v.kind {
	case mdm.KindArray:
		if vs, ok := v.ref.([]Value); ok {
			return vs
		}
		if rv, ok := v.ref.(reflect.Value); ok {
			out := make([]Value, rv.Len())
			for i := range out {
				out[i] = fromReflect(rv.Index(i))
			}
			return out
		}
	case mdm.KindJSON:
		if list, ok := v.ref.([]any); ok {
			out := make([]Value, len(list))
			for i, e := range list {
				out[i] = JSONValue(e)
			}
			return out
		}
	}
	return nil
}

// Len returns the length of an array or map, and whether the value had one.
func (v Value) Len() (int, bool) {
	switch v.kind {
	case mdm.KindArray:
		if vs, ok := v.ref.([]Value); ok {
			return len(vs), true
		}
		if rv, ok := v.ref.(reflect.Value); ok {
			return rv.Len(), true
		}
	case mdm.KindMap:
		return len(v.Entries()), true
	case mdm.KindJSON:
		switch t := v.ref.(type) {
		case []any:
			return len(t), true
		case map[string]any:
			return len(t), true
		case string:
			return len([]rune(t)), true
		}
	}
	return 0, false
}

// Entries returns a map value's contents.
func (v Value) Entries() map[string]Value {
	switch v.kind {
	case mdm.KindMap:
		if m, ok := v.ref.(map[string]Value); ok {
			return m
		}
		if rv, ok := v.ref.(reflect.Value); ok {
			out := make(map[string]Value, rv.Len())
			iter := rv.MapRange()
			for iter.Next() {
				out[fmt.Sprint(iter.Key().Interface())] = fromReflect(iter.Value())
			}
			return out
		}
	case mdm.KindJSON:
		if m, ok := v.ref.(map[string]any); ok {
			out := make(map[string]Value, len(m))
			for k, e := range m {
				out[k] = JSONValue(e)
			}
			return out
		}
	}
	return nil
}

// Field reads a member from an object, a map or a JSON document.
//
// Anything unreadable yields null rather than an error. The checker has already ruled out
// the field not existing; what remains at run time is the field being absent from this
// particular message, which is exactly what null is for.
func (v Value) Field(name string) Value {
	switch v.kind {
	case mdm.KindObject:
		rv, ok := v.ref.(reflect.Value)
		if !ok {
			return NullValue
		}
		for rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return NullValue
			}
			rv = rv.Elem()
		}
		if rv.Kind() != reflect.Struct {
			return NullValue
		}
		t := mdm.TypeOfReflect(rv.Type())
		f, found := t.Field(name)
		if !found || f.GoName == "" {
			return NullValue
		}
		return fromReflect(rv.FieldByName(f.GoName))

	case mdm.KindMap:
		if m := v.Entries(); m != nil {
			if got, ok := m[name]; ok {
				return got
			}
		}
	case mdm.KindJSON:
		if m, ok := v.ref.(map[string]any); ok {
			if got, ok := m[name]; ok {
				return JSONValue(got)
			}
			// An enrichment result can say which of its own fields it could not
			// answer. Reading one of those is still null, but a null that knows why
			// — see UnavailableValue.
			if cap := unavailableField(m, name); cap != "" {
				return UnavailableValue(cap)
			}
		}
	}
	return NullValue
}

// unavailableField reports whether an enrichment result declared this field
// unanswerable, returning the fully qualified capability name if so.
//
// The convention is a sibling "unavailable" array holding qualified names such as
// "ml.nlu_classifier.intents". Qualified rather than bare, because the value has
// travelled from another service by then and nothing else here knows which
// capability produced it.
func unavailableField(m map[string]any, name string) string {
	list, ok := m["unavailable"].([]any)
	if !ok {
		return ""
	}
	for _, it := range list {
		s, ok := it.(string)
		if !ok {
			continue
		}
		if s == name || strings.HasSuffix(s, "."+name) {
			return s
		}
	}
	return ""
}

// Index reads one element of an array.
//
// Negative and out-of-range indexes yield null, which is documented: "negative indexes
// will always return null".
func (v Value) Index(i int64) Value {
	elems := v.Elements()
	if i < 0 || i >= int64(len(elems)) {
		return NullValue
	}
	return elems[i]
}

// Equal compares two values for MQL equality.
//
// The three-valued result matters: comparing anything with null is null, not false, and a
// mismatched JSON comparison is documented to be null as well. Returning a plain bool here
// would quietly collapse "unknown" into "no".
func (v Value) Equal(other Value, fold bool) Value {
	if v.IsNull() || other.IsNull() {
		return NullValue
	}

	if a, ok := v.AsString(); ok {
		b, ok := other.AsString()
		if !ok {
			return mismatch(v, other)
		}
		if fold {
			return BoolValue(strings.EqualFold(a, b))
		}
		return BoolValue(a == b)
	}
	if a, ok := v.AsBool(); ok {
		b, ok := other.AsBool()
		if !ok {
			return mismatch(v, other)
		}
		return BoolValue(a == b)
	}
	if a, ok := v.AsFloat(); ok {
		b, ok := other.AsFloat()
		if !ok {
			return mismatch(v, other)
		}
		// Documented promotion: 3 == 3.14 is false because the integer widens first.
		return BoolValue(a == b)
	}
	return mismatch(v, other)
}

// mismatch is what a comparison between incompatible types produces. The docs specify null
// for JSON; the same answer is used throughout, since "these are not comparable" is closer
// to unknown than to false.
func mismatch(a, b Value) Value { return NullValue }

// Compare orders two values, returning -1, 0 or 1, and whether they were comparable.
func (v Value) Compare(other Value) (int, bool) {
	if v.IsNull() || other.IsNull() {
		return 0, false
	}
	if a, ok := v.AsString(); ok {
		if b, ok := other.AsString(); ok {
			return strings.Compare(a, b), true
		}
		return 0, false
	}
	if a, ok := v.AsFloat(); ok {
		if b, ok := other.AsFloat(); ok {
			switch {
			case a < b:
				return -1, true
			case a > b:
				return 1, true
			}
			return 0, true
		}
	}
	return 0, false
}

// String renders a value for diagnostics and for insight query output.
func (v Value) String() string {
	switch v.kind {
	case mdm.KindNull:
		return "null"
	case mdm.KindBool:
		return strconv.FormatBool(v.b)
	case mdm.KindInt:
		return strconv.FormatInt(v.i, 10)
	case mdm.KindFloat:
		return strconv.FormatFloat(v.f, 'g', -1, 64)
	case mdm.KindString:
		return v.s
	case mdm.KindBytes:
		if b, ok := v.ref.([]byte); ok {
			return fmt.Sprintf("<%d bytes>", len(b))
		}
	case mdm.KindArray:
		elems := v.Elements()
		parts := make([]string, len(elems))
		for i, e := range elems {
			parts[i] = e.String()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case mdm.KindMap:
		return fmt.Sprintf("<map of %d>", len(v.Entries()))
	case mdm.KindObject:
		if rv, ok := v.ref.(reflect.Value); ok {
			t := rv.Type()
			for t.Kind() == reflect.Pointer {
				t = t.Elem()
			}
			return "<" + t.Name() + ">"
		}
	case mdm.KindJSON:
		return fmt.Sprint(v.ref)
	}
	return "<" + v.kind.String() + ">"
}

// Interface returns the value as ordinary Go data, for JSON output of query results.
func (v Value) Interface() any {
	switch v.kind {
	case mdm.KindNull:
		return nil
	case mdm.KindBool:
		return v.b
	case mdm.KindInt:
		return v.i
	case mdm.KindFloat:
		return v.f
	case mdm.KindString:
		return v.s
	case mdm.KindArray:
		elems := v.Elements()
		out := make([]any, len(elems))
		for i, e := range elems {
			out[i] = e.Interface()
		}
		return out
	case mdm.KindMap:
		entries := v.Entries()
		out := make(map[string]any, len(entries))
		for k, e := range entries {
			out[k] = e.Interface()
		}
		return out
	case mdm.KindObject, mdm.KindBytes:
		if rv, ok := v.ref.(reflect.Value); ok && rv.IsValid() && rv.CanInterface() {
			return rv.Interface()
		}
	case mdm.KindJSON:
		return v.ref
	}
	return nil
}

// FromGo wraps a Go value from the data model.
func FromGo(v any) Value {
	if v == nil {
		return NullValue
	}
	return fromReflect(reflect.ValueOf(v))
}

// fromReflect converts a reflected field of the data model into a Value.
//
// A nil pointer becomes null, which is the whole reason the generated structs use pointers
// for optional scalars: it is what lets `headers.in_reply_to is null` mean what it says.
func fromReflect(rv reflect.Value) Value {
	if !rv.IsValid() {
		return NullValue
	}
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return NullValue
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Bool:
		return BoolValue(rv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return IntValue(rv.Int())
	case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return IntValue(int64(rv.Uint()))
	case reflect.Float32, reflect.Float64:
		return FloatValue(rv.Float())
	case reflect.String:
		return StringValue(rv.String())

	case reflect.Slice:
		if rv.IsNil() {
			// A missing array reads as empty, matching length(null array) being 0.
			return Value{kind: mdm.KindArray, ref: []Value(nil)}
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return Value{kind: mdm.KindBytes, ref: rv.Bytes()}
		}
		return Value{kind: mdm.KindArray, ref: rv}

	case reflect.Map:
		if rv.IsNil() {
			return Value{kind: mdm.KindMap, ref: map[string]Value(nil)}
		}
		return Value{kind: mdm.KindMap, ref: rv}

	case reflect.Struct:
		if rv.Type() == timeType {
			// Timestamps compare as RFC 3339 text: MQL has no date type of its own, and
			// that ordering happens to be both lexical and chronological.
			return StringValue(rv.Interface().(time.Time).Format(time.RFC3339))
		}
		return Value{kind: mdm.KindObject, ref: rv}
	}
	return NullValue
}

var timeType = reflect.TypeOf(time.Time{})
