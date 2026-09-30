// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"sort"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// The editor's view of MQL.
//
// Served from the engine's own registry and the generated MDM schema rather than
// written down in the front end. An editor that autocompletes a field the checker
// does not know, or omits one it does, teaches people the wrong language — and with
// the rdap.* extensions it would be wrong per deployment as well. This is the same
// argument as generating the console's TypeScript from the Go wire types: one source
// of truth, and the copy cannot drift because there is no copy.
//
// The type *graph* is sent, not a flattened list of paths. The MDM is recursive —
// file.parse_eml returns another Message — so flattening has no natural end, and at
// any useful depth it is tens of thousands of strings. The graph is a few hundred
// entries and lets the editor resolve `sender.email.domain.` locally, which is the
// difference between completion that feels instant and completion that waits on a
// round trip per keystroke.

type mqlSchema struct {
	Root      string                `json:"root"`
	Types     map[string]schemaType `json:"types"`
	Functions []schemaFunc          `json:"functions"`
	Lists     []string              `json:"lists"`
	Keywords  []string              `json:"keywords"`
}

type schemaType struct {
	Fields map[string]schemaField `json:"fields,omitempty"`
}

type schemaField struct {
	// Kind is the MQL kind: string, integer, boolean, object, array…
	Kind string `json:"kind"`
	// Type names the object type to descend into, for an object or an array of
	// objects. Empty for a primitive.
	Type     string   `json:"type,omitempty"`
	Doc      string   `json:"doc,omitempty"`
	Optional bool     `json:"optional,omitempty"`
	Enum     []string `json:"enum,omitempty"`
}

type schemaFunc struct {
	Name       string   `json:"name"`
	Params     []string `json:"params,omitempty"`
	Keywords   []string `json:"keywords,omitempty"`
	Variadic   bool     `json:"variadic,omitempty"`
	Doc        string   `json:"doc,omitempty"`
	Returns    string   `json:"returns,omitempty"`
	Capability string   `json:"capability,omitempty"`
}

// mqlKeywords are the operators and literals the language has that are not
// functions. `is null` earns its place here: it is used 421 times across the corpus
// and appears nowhere in the published operator list, so an editor that does not
// offer it is missing one of the most common things anyone writes.
var mqlKeywords = []string{
	"and", "or", "not", "in", "in~", "not in", "is null", "is not null",
	"any", "all", "none", "of", "true", "false", "null",
}

func (a *API) mqlSchema(w http.ResponseWriter, r *http.Request) {
	reg := a.pipeline.Registry()
	if reg == nil {
		reg = mql.NewRegistry()
	}

	out := mqlSchema{
		Types:    map[string]schemaType{},
		Keywords: mqlKeywords,
		Lists:    a.knownLists(r),
	}

	root := mdm.Root()
	out.Root = typeName(root, "Message")
	walkType(root, out.Root, out.Types)

	for _, name := range reg.Names() {
		f, ok := reg.Lookup(name)
		if !ok {
			continue
		}
		fn := schemaFunc{Name: name, Doc: f.Doc, Capability: string(f.Capability)}
		for _, p := range f.Params {
			fn.Params = append(fn.Params, p.Name)
		}
		for _, k := range f.Keywords {
			label := k.Name
			if k.Default != "" {
				label += "=" + k.Default
			}
			fn.Keywords = append(fn.Keywords, label)
		}
		fn.Variadic = f.Variadic != nil
		if f.Return != nil {
			fn.Returns = f.Return.Kind.String()
			if f.Return.Name != "" {
				fn.Returns = f.Return.Name
			}
		}
		out.Functions = append(out.Functions, fn)
	}
	sort.Slice(out.Functions, func(i, j int) bool { return out.Functions[i].Name < out.Functions[j].Name })

	writeJSON(w, http.StatusOK, out)
}

// knownLists is every $list this deployment can resolve, so the editor offers the
// ones that exist here rather than every name in somebody's documentation.
func (a *API) knownLists(r *http.Request) []string {
	configs, err := a.store.Lists(r.Context(), a.tenantOf(r))
	if err != nil {
		// A schema without list names is still a useful schema; refusing the whole
		// request because one query failed would take the editor down with it.
		return nil
	}
	names := make([]string, 0, len(configs))
	for _, c := range configs {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}

// typeName gives an object type a stable name, inventing one for the anonymous
// structs the generated schema contains.
func typeName(t *mdm.Type, fallback string) string {
	if t == nil {
		return ""
	}
	if t.Name != "" {
		return t.Name
	}
	return fallback
}

// walkType records t and everything reachable from it.
//
// Keyed by type name, so the recursion through file.parse_eml back to Message
// terminates on the second visit rather than unrolling forever.
func walkType(t *mdm.Type, name string, into map[string]schemaType) {
	if t == nil || name == "" {
		return
	}
	if _, seen := into[name]; seen {
		return
	}
	if t.Kind != mdm.KindObject || len(t.Fields) == 0 {
		return
	}

	entry := schemaType{Fields: map[string]schemaField{}}
	into[name] = entry // before recursing, so a cycle stops here

	for fname, f := range t.Fields {
		if f == nil || f.Type == nil {
			continue
		}
		sf := schemaField{Kind: f.Type.Kind.String(), Doc: f.Doc, Optional: f.Optional, Enum: f.Type.Enum}

		// An array of objects completes as its element type: `body.links[0].` and
		// `any(body.links, .` both want Link's fields.
		target := f.Type
		if target.Kind == mdm.KindArray && target.Elem != nil {
			target = target.Elem
		}
		if target.Kind == mdm.KindObject && len(target.Fields) > 0 {
			child := typeName(target, name+"_"+fname)
			sf.Type = child
			walkType(target, child, into)
		}
		entry.Fields[fname] = sf
	}
}
