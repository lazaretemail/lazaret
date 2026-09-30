// SPDX-License-Identifier: AGPL-3.0-only

// Package mdm holds the Message Data Model: the structured form of an email that MQL rules
// are written against.
//
// The Go types in types.gen.go are generated from Sublime's published OpenAPI schema. The
// field table in this file is derived from those types by reflection. That indirection is
// the point: the schema, the structs and the type checker cannot drift apart, because there
// is only one description of the data model and everything else is computed from it.
//
// # Optionality
//
// Optional scalars are pointers. MQL distinguishes an absent value from an empty one —
// length("") is 0 while length(null) is null, and the public rule corpus tests
// `... is null` several hundred times — so a representation that collapsed the two would
// silently change rule verdicts.
package mdm

import (
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

// Kind classifies an MDM type the way MQL sees it, which is coarser than Go's view. Rules
// cannot tell an int32 from an int64, so neither can this.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindBool
	KindInt
	KindFloat
	KindString
	KindTime
	KindBytes
	KindObject
	KindArray
	KindMap

	// KindNull is the type of the null literal. It is assignable to everything, which is
	// what makes null propagation work without every signature mentioning it.
	KindNull

	// KindJSON is a value parsed from arbitrary JSON, whose shape is not known until it is
	// traversed. MQL treats it dynamically: a mismatched comparison yields null rather
	// than an error.
	KindJSON

	// KindAny is the type of something we cannot describe. It is deliberately permissive
	// in both directions — an over-strict checker would reject valid rules, which is a
	// worse failure than missing a mistake, because a rejected rule protects nobody.
	KindAny
)

var kindNames = [...]string{
	KindInvalid: "invalid",
	KindBool:    "boolean",
	KindInt:     "integer",
	KindFloat:   "float",
	KindString:  "string",
	KindTime:    "datetime",
	KindBytes:   "bytes",
	KindObject:  "object",
	KindArray:   "array",
	KindMap:     "map",
	KindNull:    "null",
	KindJSON:    "json",
	KindAny:     "any",
}

func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return "unknown"
}

// Numeric reports whether values of this kind take part in arithmetic and ordering.
func (k Kind) Numeric() bool { return k == KindInt || k == KindFloat }

// Type describes one node of the data model.
type Type struct {
	Kind Kind

	// Name is the Go type name for objects and enumerations, empty otherwise. It exists for
	// diagnostics: "no field .foo on Domain" is a more useful message than "no field .foo".
	Name string

	// Elem is the element type of an array, or the value type of a map. Nil otherwise.
	Elem *Type

	// Fields are an object's members, keyed by the name MQL uses — the JSON tag, not the Go
	// field name. Nil for every other kind.
	Fields map[string]*Field

	// Enum lists the documented values for a string type, or nil if unconstrained. It is
	// advisory: unknown values are accepted, because a message that arrives with an
	// unrecognised value still has to be evaluated.
	Enum []string
}

// Field is one member of an object type.
type Field struct {
	// Name is the MQL-visible name, taken from the JSON tag.
	Name string

	// GoName is the struct field name, used to read the value by reflection.
	GoName string

	// Type describes the field's value.
	Type *Type

	// Optional reports whether the field can be absent. Optional scalars are pointers in
	// the generated structs; composites are optional by being nil.
	Optional bool

	// Doc is the upstream description, surfaced in editor tooling and error messages.
	Doc string
}

// Field looks up a member by its MQL name.
func (t *Type) Field(name string) (*Field, bool) {
	if t == nil || t.Fields == nil {
		return nil, false
	}
	f, ok := t.Fields[name]
	return f, ok
}

// FieldNames lists an object's members in declaration-independent (sorted) order. Used to
// suggest alternatives when a rule names a field that does not exist.
func (t *Type) FieldNames() []string {
	if t == nil {
		return nil
	}
	names := make([]string, 0, len(t.Fields))
	for n := range t.Fields {
		names = append(names, n)
	}
	// Fields are already inserted from a sorted generated struct, but callers should not
	// have to rely on that.
	slices.Sort(names)
	return names
}

var (
	schemaOnce sync.Once
	rootType   *Type
	typeCache  map[reflect.Type]*Type
)

// Root returns the type of the Message Data Model, the scope in which every rule is
// evaluated. Building it is deferred to first use and done once.
func Root() *Type {
	schemaOnce.Do(func() {
		typeCache = make(map[reflect.Type]*Type)
		rootType = describe(reflect.TypeOf(MessageDataModel{}))
	})
	return rootType
}

// Lookup resolves a dotted MQL path such as "sender.email.domain.root_domain" against the
// model, returning the field it names.
//
// Traversal steps through arrays transparently, so "attachments.file_name" resolves to the
// attachment's field. That mirrors how rules read: inside any(attachments, .file_name) the
// path continues through the element, and the checker should not need a different code path
// for it.
func Lookup(path string) (*Field, bool) {
	cur := Root()
	var found *Field
	for _, part := range strings.Split(path, ".") {
		for cur != nil && cur.Kind == KindArray {
			cur = cur.Elem
		}
		f, ok := cur.Field(part)
		if !ok {
			return nil, false
		}
		found, cur = f, f.Type
	}
	return found, found != nil
}

var timeType = reflect.TypeOf(time.Time{})

// supplements are fields the public rule corpus reads but the published schema does not
// declare.
//
// Sublime's OpenAPI document is authoritative for what it contains, but it is not
// complete: rules in their own corpus reach for fields that appear nowhere in it. Rather
// than editing the vendored document — which would make the next upstream refresh a merge
// conflict and quietly hide the divergence — the extras are declared here, where the gap
// between what is published and what is real stays visible.
//
// Each entry names the rule that proves the field exists.
var supplements = map[string][]*Field{
	"Domain": {
		// strings.parse_domain(...).error is null
		//   — detection-rules/link_multiple_http_protocols_in_single_url.yml
		{Name: "error", GoName: "", Type: String, Optional: true,
			Doc: "why the domain could not be parsed; observed in the corpus, absent from the published schema"},
	},
}

// JSONValue is the generated name for a dynamically-typed JSON payload. It carries no
// fields of its own, so it is described as JSON rather than as an empty object — an empty
// object would make every traversal into it an error.
const jsonValueTypeName = "JSONValue"

// describe builds the Type for a Go type, memoised so that shared components such as Domain
// are described once and so that a recursive model would terminate.
func describe(rt reflect.Type) *Type {
	// Dereference before consulting the cache, so that Domain and *Domain share one entry.
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if t, ok := typeCache[rt]; ok {
		return t
	}

	switch {
	case rt == timeType:
		return &Type{Kind: KindTime, Name: "Time"}

	case rt.Kind() == reflect.Slice && rt.Elem().Kind() == reflect.Uint8:
		return &Type{Kind: KindBytes, Name: "bytes"}

	case rt.Kind() == reflect.Slice:
		return &Type{Kind: KindArray, Elem: describe(rt.Elem())}

	case rt.Kind() == reflect.Map:
		return &Type{Kind: KindMap, Elem: describe(rt.Elem())}

	case rt.Kind() == reflect.Struct && rt.Name() == jsonValueTypeName:
		return &Type{Kind: KindJSON, Name: jsonValueTypeName}

	case rt.Kind() == reflect.Struct:
		// Insert before recursing so that a self-referential model resolves to the same
		// node instead of recursing forever.
		t := &Type{Kind: KindObject, Name: rt.Name(), Fields: make(map[string]*Field, rt.NumField())}
		typeCache[rt] = t
		for i := range rt.NumField() {
			sf := rt.Field(i)
			if !sf.IsExported() {
				continue
			}
			name := jsonName(sf)
			if name == "" || name == "-" {
				continue
			}
			t.Fields[name] = &Field{
				Name:     name,
				GoName:   sf.Name,
				Type:     describe(sf.Type),
				Optional: isOptional(sf.Type),
			}
		}
		for _, extra := range supplements[rt.Name()] {
			if _, declared := t.Fields[extra.Name]; !declared {
				t.Fields[extra.Name] = extra
			}
		}
		return t

	case rt.Kind() == reflect.Interface:
		// map[string]any values from the schema's free-form objects.
		return &Type{Kind: KindMap, Name: "any"}
	}

	k := KindInvalid
	switch rt.Kind() {
	case reflect.Bool:
		k = KindBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		k = KindInt
	case reflect.Float32, reflect.Float64:
		k = KindFloat
	case reflect.String:
		k = KindString
	}

	t := &Type{Kind: k}
	// Named string types are the generated enumerations; keep the name for diagnostics.
	if k == KindString && rt.Name() != "string" {
		t.Name = rt.Name()
	}
	return t
}

// isOptional reports whether a struct field can be absent. Pointers and nil-able composites
// can; a bare scalar cannot, and the generator only emits those for schema-required fields.
func isOptional(rt reflect.Type) bool {
	switch rt.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
		return true
	default:
		return false
	}
}

func jsonName(sf reflect.StructField) string {
	tag, ok := sf.Tag.Lookup("json")
	if !ok {
		return strings.ToLower(sf.Name)
	}
	name, _, _ := strings.Cut(tag, ",")
	return name
}
