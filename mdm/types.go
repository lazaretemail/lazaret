// SPDX-License-Identifier: AGPL-3.0-only

package mdm

import (
	"reflect"
	"sync"
)

// The singletons and helpers below let the type checker talk about types that are not
// fields of the data model: the result of length(), the element of an inline array, the
// dynamic value behind a JSON key.

var (
	Bool   = &Type{Kind: KindBool}
	Int    = &Type{Kind: KindInt}
	Float  = &Type{Kind: KindFloat}
	String = &Type{Kind: KindString}
	Bytes  = &Type{Kind: KindBytes}
	Time   = &Type{Kind: KindTime, Name: "Time"}
	Null   = &Type{Kind: KindNull}
	JSON   = &Type{Kind: KindJSON}
	Any    = &Type{Kind: KindAny}

	// StringArray and the others are common enough to be worth naming.
	StringArray = ArrayOf(String)
	AnyArray    = ArrayOf(Any)
)

// ArrayOf returns the type of an array with elements of type elem.
func ArrayOf(elem *Type) *Type { return &Type{Kind: KindArray, Elem: elem} }

// MapOf returns the type of a map with values of type elem.
func MapOf(elem *Type) *Type { return &Type{Kind: KindMap, Elem: elem} }

var typeOfMu sync.Mutex

// TypeOf describes the type of a Go value's type, for naming MDM structs in function
// signatures — TypeOf(WhoisOutput{}) is the return type of network.whois.
//
// Results are cached and shared with the field table built by Root, so two references to
// the same struct are the same *Type and can be compared by pointer.
func TypeOf(v any) *Type {
	Root() // ensure the cache exists and the model is described
	typeOfMu.Lock()
	defer typeOfMu.Unlock()
	return describe(reflect.TypeOf(v))
}

// TypeOfReflect describes a reflect.Type directly, for the evaluator, which walks real
// values and needs the field table for whatever struct it is standing on.
func TypeOfReflect(rt reflect.Type) *Type {
	Root()
	typeOfMu.Lock()
	defer typeOfMu.Unlock()
	return describe(rt)
}

// Elem returns the element type of an array or map, or nil for anything else.
//
// An array of unknown element type yields Any rather than nil, so that callers walking
// into an under-described value keep working instead of stopping at a nil pointer.
func (t *Type) Elem_() *Type {
	if t == nil {
		return nil
	}
	switch t.Kind {
	case KindArray, KindMap:
		if t.Elem == nil {
			return Any
		}
		return t.Elem
	}
	return nil
}

// KindOr returns the type's kind, or def when the type is unknown. It saves every caller
// that switches on a kind from writing the same nil check first.
func (t *Type) KindOr(def Kind) Kind {
	if t == nil {
		return def
	}
	return t.Kind
}

// Describe renders a type the way a diagnostic should name it.
func (t *Type) Describe() string {
	if t == nil {
		return "unknown"
	}
	switch t.Kind {
	case KindArray:
		return "[" + t.Elem_().Describe() + "]"
	case KindMap:
		return "{string: " + t.Elem_().Describe() + "}"
	case KindObject:
		if t.Name != "" {
			return t.Name
		}
		return "object"
	case KindString:
		if t.Name != "" {
			// A generated enumeration. Naming it helps, but it is still a string.
			return t.Name
		}
		return "string"
	}
	return t.Kind.String()
}

// AssignableTo reports whether a value of type t can be used where want is expected.
//
// The rules are deliberately permissive, because the cost of the two mistakes is not
// symmetric. Rejecting a rule that Sublime accepts breaks a detection someone is relying
// on; accepting one we could have rejected merely means a mistake surfaces at evaluation
// as null instead of at compile time. So anything genuinely ambiguous is allowed.
func (t *Type) AssignableTo(want *Type) bool {
	if t == nil || want == nil {
		return true
	}
	switch {
	case t.Kind == KindAny || want.Kind == KindAny:
		return true
	case t.Kind == KindNull || want.Kind == KindNull:
		// Null is a member of every type: that is what makes null propagation work
		// without every signature having to mention it.
		return true
	case t.Kind == KindJSON || want.Kind == KindJSON:
		// JSON is dynamic by definition, and a mismatch is documented to produce null at
		// evaluation rather than an error.
		return true
	}

	switch want.Kind {
	case KindFloat:
		// Documented promotion: an integer is usable wherever a float is.
		return t.Kind == KindFloat || t.Kind == KindInt
	case KindInt:
		return t.Kind == KindInt
	case KindString:
		// Raw file bytes are accepted where text is wanted: rules pass attachment content
		// straight to the string functions, and refusing would reject real rules over a
		// distinction MQL does not make.
		return t.Kind == KindString || t.Kind == KindBytes
	case KindArray:
		return t.Kind == KindArray && t.Elem_().AssignableTo(want.Elem_())
	case KindMap:
		return t.Kind == KindMap && t.Elem_().AssignableTo(want.Elem_())
	case KindObject:
		// Objects are nominal: the same described type, compared by identity.
		return t == want || (t.Kind == KindObject && t.Name == want.Name)
	}
	return t.Kind == want.Kind
}

// Comparable reports whether two types can appear on either side of a comparison.
func (t *Type) Comparable(other *Type) bool {
	if t == nil || other == nil {
		return true
	}
	if t.Kind == KindAny || other.Kind == KindAny ||
		t.Kind == KindNull || other.Kind == KindNull ||
		t.Kind == KindJSON || other.Kind == KindJSON {
		return true
	}
	if t.Kind.Numeric() && other.Kind.Numeric() {
		return true
	}
	// Strings, enumerations and raw bytes all compare as text.
	if t.textual() && other.textual() {
		return true
	}
	return t.Kind == other.Kind
}

func (t *Type) textual() bool {
	return t.Kind == KindString || t.Kind == KindBytes
}
