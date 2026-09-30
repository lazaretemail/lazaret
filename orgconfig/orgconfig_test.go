// SPDX-License-Identifier: AGPL-3.0-only

package orgconfig_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/orgconfig"
)

func TestLoadAndNormalize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "org.yaml")
	if err := os.WriteFile(path, []byte(`
domains:
  - Example.com
  - mail.example.co.uk
  - ""
display_names:
  - Alice Smith
vips:
  - email: CEO@example.com
    display_name: Dana Reed
`), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := orgconfig.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Configured() {
		t.Fatal("config reports itself unconfigured")
	}

	// Case and blank entries are normalised away, so a typo in the config cannot turn into
	// a domain that never matches.
	if got := c.DomainList(); !slices.Equal(got, []string{"example.com", "mail.example.co.uk"}) {
		t.Errorf("domains = %v", got)
	}
	if got := c.RootDomainList(); !slices.Equal(got, []string{"example.co.uk", "example.com"}) {
		t.Errorf("root domains = %v", got)
	}
	if got := c.SLDList(); !slices.Equal(got, []string{"example"}) {
		t.Errorf("slds = %v", got)
	}

	// A VIP's display name belongs in the display-name list too: impersonation rules
	// compare a sender's display name against staff, and listing a VIP twice by hand is
	// exactly the sort of thing people forget.
	if got := c.DisplayNameList(); !slices.Equal(got, []string{"alice smith", "dana reed"}) {
		t.Errorf("display names = %v", got)
	}
	if got := c.VIPEmailList(); !slices.Equal(got, []string{"ceo@example.com"}) {
		t.Errorf("vip emails = %v", got)
	}
}

func TestIsOrgDomain(t *testing.T) {
	c := &orgconfig.Config{Domains: []string{"example.com"}}
	c.Normalize()

	tests := map[string]bool{
		"example.com":           true,
		"EXAMPLE.COM":           true,
		"mail.example.com":      true, // a subdomain of ours is still us
		"a.b.example.com":       true,
		"example.com.":          true, // fully qualified
		"notexample.com":        false,
		"example.com.evil.test": false, // suffix confusion must not match
		"example.org":           false,
		"":                      false,
	}
	for host, want := range tests {
		if got := c.IsOrgDomain(host); got != want {
			t.Errorf("IsOrgDomain(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestIsOrgAddress(t *testing.T) {
	c := &orgconfig.Config{Domains: []string{"example.com"}}
	c.Normalize()

	if !c.IsOrgAddress(mdm.ParseEmailAddress("bob@example.com")) {
		t.Error("an address on our own domain is not recognised")
	}
	if c.IsOrgAddress(mdm.ParseEmailAddress("bob@other.test")) {
		t.Error("an external address was treated as ours")
	}
	if c.IsOrgAddress(nil) {
		t.Error("a nil address was treated as ours")
	}
	// An address with no domain at all cannot be ours.
	if c.IsOrgAddress(mdm.ParseEmailAddress("bob")) {
		t.Error("a domainless address was treated as ours")
	}
}

func TestUnconfiguredIsInert(t *testing.T) {
	// An empty config is legitimate — analysing a lone message with no organisation in
	// mind — and must not claim anything belongs to it.
	var nilConfig *orgconfig.Config
	if nilConfig.Configured() {
		t.Error("a nil config reports itself configured")
	}
	if nilConfig.IsOrgDomain("example.com") {
		t.Error("a nil config claimed a domain")
	}

	empty := &orgconfig.Config{}
	empty.Normalize()
	if empty.Configured() {
		t.Error("an empty config reports itself configured")
	}
	if empty.IsOrgDomain("example.com") {
		t.Error("an empty config claimed a domain")
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	if _, err := orgconfig.Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("loading a missing file succeeded")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("domains: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := orgconfig.Load(path); err == nil {
		t.Error("loading malformed YAML succeeded")
	}
}
