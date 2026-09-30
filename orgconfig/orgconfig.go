// SPDX-License-Identifier: AGPL-3.0-only

// Package orgconfig describes the organisation a message was received by.
//
// Some of the model is not a property of the message at all. Whether mail is inbound,
// outbound or internal is defined relative to your verified message-source domains, and
// `type.inbound` gates most of the public rule corpus — 1,293 uses — so without this
// configuration almost nothing evaluates correctly. The same settings back the org-scoped
// lists: $org_domains, $org_vips, $org_display_names, $org_slds, $recipient_emails.
//
// Nothing here needs the network. It is configuration, supplied by hand as a YAML file in
// the standalone engine and synced from the mail provider once the ingest service exists.
package orgconfig

import (
	"fmt"
	"os"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/lazaretemail/lazaret/mdm"
)

// Config is one organisation's view of its own mail.
type Config struct {
	// Domains are the verified message-source domains. Mail from outside them is inbound;
	// mail from inside them is outbound or internal depending on the recipients.
	Domains []string `yaml:"domains" json:"domains"`

	// VIPs are the people worth impersonating: executives, finance, anyone with authority
	// over payments. Backs $org_vips.
	VIPs []VIP `yaml:"vips" json:"vips"`

	// DisplayNames are the display names of people in the organisation, used by
	// impersonation rules that compare a sender's display name against staff. Backs
	// $org_display_names. Names from VIPs are included automatically.
	DisplayNames []string `yaml:"display_names" json:"display_names"`

	// derived state, built by Normalize.
	domainSet map[string]bool
	rootSet   map[string]bool
	sldSet    map[string]bool
	nameSet   map[string]bool
	vipEmails map[string]bool
}

// VIP is a person whose impersonation matters.
type VIP struct {
	Email       string `yaml:"email" json:"email"`
	DisplayName string `yaml:"display_name" json:"display_name"`
}

// The json tags matter as much as the yaml ones: this is stored as jsonb and read
// back, and Go would otherwise marshal the fields as Domains/VIPs/DisplayNames while
// the reader looks for the lowercase spellings. The round trip would return an empty
// configuration and nothing would report an error.

// Load reads a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading org config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	c.Normalize()
	if len(c.Domains) == 0 {
		// Not an error — an empty config is legitimate for analysing a lone .eml with no
		// organisation in mind — but the caller should understand what it costs.
		return &c, nil
	}
	return &c, nil
}

// Normalize builds the lookup sets. It is idempotent, and safe to call on a Config built
// in code rather than loaded from disk.
func (c *Config) Normalize() {
	c.domainSet = make(map[string]bool, len(c.Domains))
	c.rootSet = make(map[string]bool, len(c.Domains))
	c.sldSet = make(map[string]bool, len(c.Domains))
	c.nameSet = make(map[string]bool, len(c.DisplayNames)+len(c.VIPs))
	c.vipEmails = make(map[string]bool, len(c.VIPs))

	for _, d := range c.Domains {
		d = strings.ToLower(strings.TrimSpace(strings.Trim(d, ".")))
		if d == "" {
			continue
		}
		c.domainSet[d] = true
		if parsed := mdm.ParseDomain(d); parsed != nil {
			if parsed.RootDomain != nil {
				c.rootSet[*parsed.RootDomain] = true
			}
			if parsed.SLD != nil {
				c.sldSet[*parsed.SLD] = true
			}
		}
	}
	for _, n := range c.DisplayNames {
		if n = strings.TrimSpace(n); n != "" {
			c.nameSet[strings.ToLower(n)] = true
		}
	}
	for _, v := range c.VIPs {
		if e := strings.ToLower(strings.TrimSpace(v.Email)); e != "" {
			c.vipEmails[e] = true
		}
		if n := strings.TrimSpace(v.DisplayName); n != "" {
			c.nameSet[strings.ToLower(n)] = true
		}
	}
}

// Configured reports whether the organisation is known. When it is not, message direction
// cannot be determined and the caller should say so rather than guess.
func (c *Config) Configured() bool { return c != nil && len(c.domainSet) > 0 }

// IsOrgDomain reports whether a hostname belongs to the organisation.
//
// A subdomain of a verified domain counts: mail from mail.example.com is not external to an
// organisation that owns example.com.
func (c *Config) IsOrgDomain(host string) bool {
	if !c.Configured() || host == "" {
		return false
	}
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if c.domainSet[host] {
		return true
	}
	for d := range c.domainSet {
		if strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// IsOrgAddress reports whether an address belongs to the organisation.
func (c *Config) IsOrgAddress(addr *mdm.EmailAddress) bool {
	if addr == nil || addr.Domain == nil {
		return false
	}
	return c.IsOrgDomain(addr.Domain.Domain)
}

// Domains, roots, SLDs and display names, for the org-scoped $lists.
func (c *Config) DomainList() []string      { return sortedKeys(c.domainSet) }
func (c *Config) RootDomainList() []string  { return sortedKeys(c.rootSet) }
func (c *Config) SLDList() []string         { return sortedKeys(c.sldSet) }
func (c *Config) DisplayNameList() []string { return sortedKeys(c.nameSet) }
func (c *Config) VIPEmailList() []string    { return sortedKeys(c.vipEmails) }

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
