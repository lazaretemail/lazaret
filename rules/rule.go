// SPDX-License-Identifier: AGPL-3.0-only

// Package rules loads detection content and runs it over messages.
//
// The YAML schema here follows what the public corpus actually contains rather than what
// is documented. Sublime publishes a JSON schema in their VSCode extension that allows two
// entity types; the corpus uses five, and several fields that appear in real rule files
// are in neither the schema nor the prose.
package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Kind is what a YAML file declares itself to be.
type Kind string

const (
	// KindRule is a detection rule: it evaluates to a boolean and fires.
	KindRule Kind = "rule"

	// KindQuery is an insight: it evaluates to a *value*, which is why the engine is
	// value-returning rather than a predicate engine.
	KindQuery Kind = "query"

	// KindDLP is a data-loss rule. Structurally a detection rule.
	KindDLP Kind = "dlp"

	// KindExclusion suppresses other rules: a message it matches is not flagged, however
	// many detections fired. Phishing-simulation traffic is the usual reason.
	KindExclusion Kind = "exclusion"

	// KindTriageRule is an automation. It runs over triage state rather than over a
	// message, so it is loaded but not evaluated here.
	KindTriageRule Kind = "triage_rule"
)

// Severity ranks a detection.
type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

// rank orders severities so that the most serious detection on a message can be reported.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	}
	return 0
}

// Author is one credited author. The corpus writes these as single-key maps
// (`- twitter: name`), not as plain strings, which the prose documentation does not say.
type Author struct {
	Name     string `yaml:"name,omitempty"`
	Twitter  string `yaml:"twitter,omitempty"`
	GitHub   string `yaml:"github,omitempty"`
	Email    string `yaml:"email,omitempty"`
	LinkedIn string `yaml:"linkedin,omitempty"`
}

// String renders an author for display, preferring whichever identity was given.
func (a Author) String() string {
	for _, v := range []string{a.Name, a.Twitter, a.GitHub, a.LinkedIn, a.Email} {
		if v != "" {
			return v
		}
	}
	return "unknown"
}

// Entity is one YAML file of detection content.
type Entity struct {
	Name        string `yaml:"name"`
	Type        Kind   `yaml:"type"`
	Source      string `yaml:"source"`
	ID          string `yaml:"id,omitempty"`
	Description string `yaml:"description,omitempty"`

	Severity Severity `yaml:"severity,omitempty"`
	Label    string   `yaml:"label,omitempty"`
	Maturity string   `yaml:"maturity,omitempty"`

	// Active defaults to true. The corpus ships a handful of automations disabled, and a
	// rule that is off should stay off when it is loaded.
	Active *bool `yaml:"active,omitempty"`

	Tags                 []string `yaml:"tags,omitempty"`
	UserProvidedTags     []string `yaml:"user_provided_tags,omitempty"`
	References           []string `yaml:"references,omitempty"`
	FalsePositives       []string `yaml:"false_positives,omitempty"`
	Authors              []Author `yaml:"authors,omitempty"`
	AttackTypes          []string `yaml:"attack_types,omitempty"`
	TacticsAndTechniques []string `yaml:"tactics_and_techniques,omitempty"`
	DetectionMethods     []string `yaml:"detection_methods,omitempty"`
	ActionIDs            []string `yaml:"action_ids,omitempty"`
	DefaultActions       []string `yaml:"default_actions,omitempty"`

	// Path is where the entity was loaded from, for diagnostics.
	Path string `yaml:"-"`
}

// Enabled reports whether the entity should run. Absent means yes.
func (e *Entity) Enabled() bool { return e.Active == nil || *e.Active }

// Validate checks the fields a loader can check without compiling the MQL.
func (e *Entity) Validate() error {
	var problems []string
	if strings.TrimSpace(e.Name) == "" {
		problems = append(problems, "name is required")
	}
	if strings.TrimSpace(e.Source) == "" {
		problems = append(problems, "source is required")
	}
	switch e.Type {
	case KindRule, KindQuery, KindDLP, KindExclusion, KindTriageRule:
	case "":
		problems = append(problems, "type is required")
	default:
		problems = append(problems, fmt.Sprintf("unknown type %q", e.Type))
	}
	if e.Severity != "" {
		switch e.Severity {
		case SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		default:
			problems = append(problems, fmt.Sprintf("unknown severity %q", e.Severity))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s: %s", e.displayPath(), strings.Join(problems, "; "))
	}
	return nil
}

func (e *Entity) displayPath() string {
	if e.Path != "" {
		return e.Path
	}
	return e.Name
}

// UnmarshalYAML accepts the shapes the corpus actually uses.
//
// Two of them are not in any schema: `source` is usually a block scalar but is sometimes a
// plain one (including a literal `source: true`), and `authors` is a list of single-key
// maps rather than strings. A loader that assumed the documented shapes would reject real
// files.
func (e *Entity) UnmarshalYAML(node *yaml.Node) error {
	type plain struct {
		Name        string    `yaml:"name"`
		Type        Kind      `yaml:"type"`
		Source      yaml.Node `yaml:"source"`
		ID          string    `yaml:"id"`
		Description string    `yaml:"description"`

		Severity Severity `yaml:"severity"`
		Label    string   `yaml:"label"`
		Maturity string   `yaml:"maturity"`
		Active   *bool    `yaml:"active"`

		Tags                 []string `yaml:"tags"`
		UserProvidedTags     []string `yaml:"user_provided_tags"`
		References           []string `yaml:"references"`
		FalsePositives       []string `yaml:"false_positives"`
		Authors              []Author `yaml:"authors"`
		AttackTypes          []string `yaml:"attack_types"`
		TacticsAndTechniques []string `yaml:"tactics_and_techniques"`
		DetectionMethods     []string `yaml:"detection_methods"`
		ActionIDs            []string `yaml:"action_ids"`
		DefaultActions       []string `yaml:"default_actions"`
	}

	var p plain
	if err := node.Decode(&p); err != nil {
		return err
	}

	*e = Entity{
		Name: p.Name, Type: p.Type, ID: p.ID, Description: p.Description,
		Severity: p.Severity, Label: p.Label, Maturity: p.Maturity, Active: p.Active,
		Tags: p.Tags, UserProvidedTags: p.UserProvidedTags, References: p.References,
		FalsePositives: p.FalsePositives, Authors: p.Authors,
		AttackTypes: p.AttackTypes, TacticsAndTechniques: p.TacticsAndTechniques,
		DetectionMethods: p.DetectionMethods, ActionIDs: p.ActionIDs,
		DefaultActions: p.DefaultActions,
	}

	// A scalar node holds the MQL whether it was written as a block or inline; decoding
	// into a string would fail on `source: true`, which YAML reads as a boolean.
	if p.Source.Kind == yaml.ScalarNode {
		e.Source = p.Source.Value
	} else if p.Source.Kind != 0 {
		var s string
		if err := p.Source.Decode(&s); err == nil {
			e.Source = s
		}
	}
	return nil
}

// LoadFile reads one entity.
func LoadFile(path string) (*Entity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Entity
	if err := yaml.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	e.Path = path
	return &e, nil
}

// LoadDir reads every entity under a directory tree.
//
// Files that are not entities are skipped rather than reported. A rule feed is a git
// repository, and git repositories contain CI workflows, raw .eml samples and .yar
// signatures, none of which are detection content.
func LoadDir(root string) ([]*Entity, error) {
	var out []*Entity

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".github", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}

		e, err := LoadFile(path)
		if err != nil {
			return nil // not YAML we understand; not ours
		}
		if e.Source == "" || e.Type == "" {
			return nil
		}
		if rel, err := filepath.Rel(root, path); err == nil {
			e.Path = filepath.ToSlash(rel)
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Stable order, so that two runs over the same feed report in the same sequence.
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
