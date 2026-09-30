// SPDX-License-Identifier: AGPL-3.0-only

package mdm_test

import (
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
)

// TestHotPathsResolve checks the field paths the public rule corpus actually leans on,
// ordered by how often they appear in it. If any of these stops resolving, a large share of
// real rules stops type-checking, so this is the canary for schema regressions.
func TestHotPathsResolve(t *testing.T) {
	paths := []struct {
		path string
		kind mdm.Kind
		uses int // occurrences across sublime-security/sublime-rules
	}{
		{"body.current_thread.text", mdm.KindString, 2409},
		{"sender.email.domain.root_domain", mdm.KindString, 1341},
		{"type.inbound", mdm.KindBool, 1293},
		{"subject.subject", mdm.KindString, 752},
		{"headers.auth_summary.dmarc.pass", mdm.KindBool, 609},
		{"sender.display_name", mdm.KindString, 415},
		{"body.html.raw", mdm.KindString, 366},
		{"sender.email.email", mdm.KindString, 256},
		{"subject.base", mdm.KindString, 224},
		{"body.html.inner_text", mdm.KindString, 212},
		{"sender.email.domain.domain", mdm.KindString, 207},
		{"headers.auth_summary.spf.pass", mdm.KindBool, 75},
		{"headers.message_id", mdm.KindString, 63},
		{"sender.email.domain.sld", mdm.KindString, 46},
		{"subject.is_reply", mdm.KindBool, 44},
		{"sender.email.domain.tld", mdm.KindString, 25},
		{"headers.return_path.domain.root_domain", mdm.KindString, 25},
		{"sender.email.local_part", mdm.KindString, 84},
		{"sender.email.domain.valid", mdm.KindBool, 12},

		// Paths that traverse an array element, as rules do inside any(...).
		{"body.links", mdm.KindArray, 931},
		{"recipients.to", mdm.KindArray, 517},
		{"body.links.href_url.domain.root_domain", mdm.KindString, 1315},
		{"body.links.href_url.query_params_decoded", mdm.KindMap, 68},
		{"attachments.file_extension", mdm.KindString, 413},
		{"attachments.file_name", mdm.KindString, 165},
		{"attachments.size", mdm.KindInt, 49},
		{"attachments.sha256", mdm.KindString, 10},
		{"headers.hops", mdm.KindArray, 139},
		{"body.previous_threads.sender.display_name", mdm.KindString, 0},
		{"recipients.to.email.domain.domain", mdm.KindString, 0},
	}

	for _, tc := range paths {
		t.Run(tc.path, func(t *testing.T) {
			f, ok := mdm.Lookup(tc.path)
			if !ok {
				t.Fatalf("%s does not resolve (%d uses in the public corpus)", tc.path, tc.uses)
			}
			if f.Type.Kind != tc.kind {
				t.Errorf("%s is %s, want %s", tc.path, f.Type.Kind, tc.kind)
			}
		})
	}
}

func TestUnknownFieldDoesNotResolve(t *testing.T) {
	// A typo must be a compile error rather than a silent null, which is the whole reason
	// the checker resolves against this table.
	for _, path := range []string{
		"sender.emial",
		"sender.email.domain.root_doman",
		"nonexistent",
		"body.current_thread.text.nonsense", // traversing into a scalar
	} {
		if _, ok := mdm.Lookup(path); ok {
			t.Errorf("%s resolved, want failure", path)
		}
	}
}

func TestOptionalityMatchesSchema(t *testing.T) {
	// Domain.domain and URL.url are the only required scalars on their types; everything
	// around them is optional and must be able to report null.
	required, ok := mdm.Lookup("sender.email.domain.domain")
	if !ok {
		t.Fatal("sender.email.domain.domain does not resolve")
	}
	if required.Optional {
		t.Error("domain.domain is optional, want required per the schema")
	}

	optional, ok := mdm.Lookup("sender.email.domain.root_domain")
	if !ok {
		t.Fatal("sender.email.domain.root_domain does not resolve")
	}
	if !optional.Optional {
		t.Error("domain.root_domain is required, want optional so that `is null` works")
	}
}

func TestRootIsStableAndPopulated(t *testing.T) {
	root := mdm.Root()
	if root.Kind != mdm.KindObject {
		t.Fatalf("root kind is %s, want object", root.Kind)
	}
	// The roots a rule can name. `triage` is deliberately absent: it exists only for
	// automations and is not part of the message model.
	for _, name := range []string{
		"sender", "recipients", "headers", "subject", "body", "attachments", "type",
		"external", "mailbox",
	} {
		if _, ok := root.Field(name); !ok {
			t.Errorf("root has no field %q; have %v", name, root.FieldNames())
		}
	}

	if mdm.Root() != root {
		t.Error("Root() returned a different instance on the second call")
	}
}

func TestSharedComponentsAreDescribedOnce(t *testing.T) {
	// Domain appears under sender, return_path, links and elsewhere. Describing it once
	// keeps the table small and lets the checker compare types by pointer.
	a, _ := mdm.Lookup("sender.email.domain")
	b, _ := mdm.Lookup("headers.return_path.domain")
	if a == nil || b == nil {
		t.Fatal("a domain path failed to resolve")
	}
	if a.Type != b.Type {
		t.Error("the same component was described twice")
	}
}
