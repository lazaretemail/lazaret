// SPDX-License-Identifier: AGPL-3.0-only

package lists_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lazaretemail/lazaret/lists"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
)

func TestUnconfiguredIsNotEmpty(t *testing.T) {
	// The property the whole package is built around. A list nobody configured must
	// answer "I do not know", never "no": treating it as empty switches off every rule
	// that uses it, silently.
	r := lists.NewResolver()
	r.Add(lists.NewSet("known", []string{"a.test"}))

	if _, known := r.Contains(context.Background(), "unknown", mql.StringValue("a.test"), false); known {
		t.Error("an unconfigured list reported itself known")
	}
	found, known := r.Contains(context.Background(), "known", mql.StringValue("b.test"), false)
	if !known {
		t.Error("a configured list reported itself unknown")
	}
	if found {
		t.Error("a value that is not in the list was found")
	}
}

func TestMembershipIsCaseInsensitive(t *testing.T) {
	// Domains, file extensions and addresses are all case-insensitive in practice, and
	// every rule in the corpus compares them that way.
	r := lists.NewResolver()
	r.Add(lists.NewSet("domains", []string{"Example.COM"}))

	for _, probe := range []string{"example.com", "EXAMPLE.COM", "Example.com"} {
		found, known := r.Contains(context.Background(), "domains", mql.StringValue(probe), false)
		if !known || !found {
			t.Errorf("%q not found in the list", probe)
		}
	}
}

func TestSetSkipsBlanksAndComments(t *testing.T) {
	s := lists.NewSet("x", []string{"a.test", "", "  ", "# a comment", "b.test"})
	if s.Len() != 2 {
		t.Errorf("Len() = %d, want 2", s.Len())
	}
	if s.Has("# a comment") {
		t.Error("a comment became an entry")
	}
}

func TestElementsForIteration(t *testing.T) {
	r := lists.NewResolver()
	r.Add(lists.NewSet("x", []string{"a", "b"}))

	got, known := r.Elements(context.Background(), "x")
	if !known || len(got) != 2 {
		t.Fatalf("Elements = %v, known = %v", got, known)
	}
	if got[0].String() != "a" {
		t.Errorf("entries are not in file order: %v", got)
	}
	if _, known := r.Elements(context.Background(), "nope"); known {
		t.Error("an unconfigured list reported itself known")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "free_email_providers.txt"),
		[]byte("gmail.com\n# comment\noutlook.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The ranked lists are CSV with the rank first; only the domain is the value.
	if err := os.WriteFile(filepath.Join(dir, "tranco_1m.csv"),
		[]byte("1,google.com\n2,youtube.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a list"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := lists.NewResolver()
	if err := r.LoadDir(dir); err != nil {
		t.Fatal(err)
	}

	if names := r.Names(); len(names) != 2 {
		t.Errorf("loaded %v, want just the two list files", names)
	}
	if found, _ := r.Contains(context.Background(), "free_email_providers", mql.StringValue("gmail.com"), false); !found {
		t.Error("gmail.com not found")
	}
	if found, _ := r.Contains(context.Background(), "tranco_1m", mql.StringValue("google.com"), false); !found {
		t.Error("the rank column was not stripped from the CSV")
	}
	if found, _ := r.Contains(context.Background(), "tranco_1m", mql.StringValue("1"), false); found {
		t.Error("the rank column became an entry")
	}
}

func TestOrgLists(t *testing.T) {
	// $org_domains alone appears in 211 corpus rules, and only the deployment knows it.
	cfg := &orgconfig.Config{
		Domains: []string{"example.com"},
		VIPs:    []orgconfig.VIP{{Email: "ceo@example.com", DisplayName: "Dana Reed"}},
	}
	cfg.Normalize()

	r := lists.NewResolver()
	r.AddOrgLists(cfg)

	for _, name := range []string{"org_domains", "org_slds", "org_vips", "org_display_names", "tenant_domains"} {
		if !r.Known(name) {
			t.Errorf("$%s was not registered", name)
		}
	}
	if found, _ := r.Contains(context.Background(), "org_domains", mql.StringValue("example.com"), false); !found {
		t.Error("example.com is not in $org_domains")
	}
	if found, _ := r.Contains(context.Background(), "org_vips", mql.StringValue("ceo@example.com"), false); !found {
		t.Error("the VIP is not in $org_vips")
	}
	// A VIP's display name belongs in $org_display_names too.
	if found, _ := r.Contains(context.Background(), "org_display_names", mql.StringValue("Dana Reed"), false); !found {
		t.Error("the VIP's display name is not in $org_display_names")
	}
}

func TestNullValueIsNotInAnyList(t *testing.T) {
	// A null value is definitely not in a list we do have — that is a real answer, not
	// an unknown one.
	r := lists.NewResolver()
	r.Add(lists.NewSet("x", []string{"a"}))
	found, known := r.Contains(context.Background(), "x", mql.NullValue, false)
	if !known {
		t.Error("the list reported itself unknown")
	}
	if found {
		t.Error("null was found in a list")
	}
}
