// SPDX-License-Identifier: AGPL-3.0-only

// Package yara scans bytes with YARA signatures and shapes the result the way MQL
// expects to read it.
//
// # Where this fits
//
// In Sublime's model, YARA runs inside file.explode and rules read the result at
// `.scan.yara.matches`. That shape is published — it is Strelka's, and looks like
// `{flags: [...], matches: [{name, meta}]}` — so this package produces exactly it, and
// will drop into the file-analysis module unchanged when that lands.
//
// Until then it is directly useful anyway: attachments carry their bytes in the model
// already, so signatures can be run over them without recursive extraction. What is
// missing is the recursion — a signature that would have matched a file inside a zip will
// not, because nothing has opened the zip yet — and that limitation is reported rather
// than glossed over.
//
// # Why a build tag
//
// The scanner is YARA-X, VirusTotal's Rust rewrite, reached through cgo. That means a
// native library at build time, which would otherwise make the whole engine unbuildable
// for anyone who only wants to lint a rule. So the core is cgo-free by default and YARA
// support is opt-in:
//
//	go build -tags yara ./...
//
// Without the tag, Available reports false and scanning yields no matches rather than
// pretending a file was checked.
package yara

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lazaretemail/lazaret/mdm"
)

// ErrUnsupported is returned when the binary was built without YARA support.
//
// It is deliberately distinct from "no signatures matched". A build that cannot scan has
// not cleared a file, and a caller that cannot tell those apart will eventually report
// the wrong thing.
var ErrUnsupported = errors.New("yara: this build has no YARA support; rebuild with -tags yara")

// Match is one signature that fired.
type Match struct {
	// Name is the rule identifier, which is what MQL compares against in
	// `.scan.yara.matches, .name == "..."`.
	Name string

	// Namespace groups signatures from one source.
	Namespace string

	// Tags are the rule's tags.
	Tags []string

	// Meta is the rule's metadata. Rules match on it — `.meta['author']` and
	// `.meta['severity']` are both documented patterns — so it is carried through as
	// strings rather than being reduced to a description.
	Meta map[string]string
}

// Result is a whole scan.
type Result struct {
	Matches []Match

	// Flags records anything notable about the scan itself, following Strelka's
	// convention. A timeout appears here rather than as an error, because a partial scan
	// still found what it found.
	Flags []string
}

// MDM converts a result into the value MQL reads at `.scan.yara`.
func (r *Result) MDM() *mdm.StrelkaYARA {
	out := &mdm.StrelkaYARA{Flags: r.Flags}
	for _, m := range r.Matches {
		match := &mdm.StrelkaYARAMatch{Name: mdm.Ptr(m.Name)}
		if len(m.Meta) > 0 {
			meta := make(map[string]string, len(m.Meta))
			for k, v := range m.Meta {
				meta[k] = v
			}
			match.Meta = meta
		}
		out.Matches = append(out.Matches, match)
	}
	return out
}

// Scanner runs compiled signatures over bytes.
//
// Implementations are safe for concurrent use: one compiled rule set serves every message
// in a deployment, and recompiling per message would dominate the cost of scanning.
type Scanner interface {
	// Scan runs every signature over data.
	Scan(data []byte) (*Result, error)

	// Count reports how many signatures are loaded.
	Count() int

	// Close releases the compiled rules.
	Close() error
}

// Compile builds a scanner from YARA source.
func Compile(sources map[string]string) (Scanner, error) { return compile(sources) }

// Available reports whether this build can scan. False means the binary was built without
// the yara tag.
func Available() bool { return available() }

// LoadDir reads every signature file under a directory.
//
// The glob follows the convention rule feeds use: `.yar` and `.yara` files, anywhere in
// the tree. Each file becomes its own namespace, named after its path, so that two feeds
// defining a rule with the same identifier do not collide.
func LoadDir(root string) (map[string]string, error) {
	sources := map[string]string{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == ".github" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yar", ".yara":
		default:
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name := path
		if rel, err := filepath.Rel(root, path); err == nil {
			name = filepath.ToSlash(rel)
		}
		sources[name] = string(raw)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no YARA signatures found under %s", root)
	}
	return sources, nil
}

// CompileDir loads and compiles a directory of signatures.
func CompileDir(root string) (Scanner, error) {
	sources, err := LoadDir(root)
	if err != nil {
		return nil, err
	}
	return Compile(sources)
}

// sortedNames orders the sources so that compilation and any diagnostics are
// reproducible rather than depending on map iteration.
func sortedNames(sources map[string]string) []string {
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ScanAttachments runs a scanner over every attachment in a message.
//
// This is the useful-today path: attachments carry their bytes in the model, so signatures
// can run without the file-analysis module. It does not recurse into archives — a
// signature that would match a file inside a zip will not fire — which is precisely the
// gap file.explode closes.
func ScanAttachments(s Scanner, msg *mdm.MessageDataModel) (map[string]*Result, error) {
	if s == nil {
		return nil, ErrUnsupported
	}
	out := make(map[string]*Result, len(msg.Attachments))
	for i, a := range msg.Attachments {
		if len(a.Raw) == 0 {
			continue
		}
		res, err := s.Scan(a.Raw)
		if err != nil {
			return out, fmt.Errorf("scanning attachment %d: %w", i, err)
		}
		name := mdm.Deref(a.FileName)
		if name == "" {
			name = fmt.Sprintf("attachment-%d", i)
		}
		out[name] = res
	}
	return out, nil
}
