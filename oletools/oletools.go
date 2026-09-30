// SPDX-License-Identifier: AGPL-3.0-only

// Package oletools analyses Office documents, answering file.oletools.
//
// The name is upstream's and describes the interface, not the implementation: this is
// a Go reimplementation of the parts of Philippe Lagadec's oletools that the rule
// corpus actually reads, not a wrapper around it. No Python, no service, no network —
// an Office document is a zip or a compound file, and everything the corpus asks about
// is in the bytes.
//
// # Why this exists rather than being mapped from Strelka
//
// Strelka runs the file explosion and reports what it extracted: stream counts, child
// records. What the corpus reads is different in kind — the OOXML relationship targets
// that remote template injection uses, whether a VBA project auto-executes, and
// oletools' own risk verdict. None of that is on Strelka's wire, and mapping it would
// have meant inventing `indicators.vba_macros.exists` from a stream count and
// `relationships` from nothing. Rules would appear to work while reading fields nobody
// populated, which is the failure this project is built to avoid.
//
// So it is implemented rather than approximated, and it is local because it can be:
// the analysis is pure parsing, it needs no model and no container, and a deployment
// with no file-analysis service at all still gets it.
//
// # What the corpus asks for
//
//	relationships                     7 uses   .target and .target_url
//	macros.keywords                   1        .type, notably "autoexec"
//	indicators.vba_macros.exists      1
//	indicators.vba_macros.risk        1
//	indicators.encryption.exists      1
//
// Those eleven calls are eleven rules that reported indeterminate on every message
// before this existed — including CVE-2021-40444 and the auto-exec macro rules, which
// are not obscure.
//
// # This code reads attacker-controlled bytes
//
// Every document it sees was chosen by someone trying to get through. It therefore
// never panics on malformed input, bounds everything it allocates from a header field,
// and refuses rather than guesses. Malformed input yields a partial result or none,
// never an error that stops a message being evaluated: a document that cannot be
// parsed is a document with no relationships, and that is a true statement.
package oletools

import (
	"github.com/lazaretemail/lazaret/mdm"
)

// Limits bound what one document may cost.
//
// A zip that claims a terabyte of content is a denial of service, not a document, and
// the numbers below are far above any real Office file. They exist so that refusing is
// cheap and the refusal happens before the allocation, not after.
type Limits struct {
	// MaxEntries caps how many members of a container are examined. A real
	// document has tens; a zip bomb has hundreds of thousands.
	MaxEntries int

	// MaxEntryBytes caps a single decompressed member.
	MaxEntryBytes int64

	// MaxTotalBytes caps everything decompressed from one document.
	MaxTotalBytes int64

	// MaxRelationships caps how many are reported. One corpus rule already guards
	// with `length(...) < 500`, which says what a reasonable ceiling looks like.
	MaxRelationships int
}

// DefaultLimits are generous for real documents and hostile to constructed ones.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:       4096,
		MaxEntryBytes:    64 << 20,
		MaxTotalBytes:    256 << 20,
		MaxRelationships: 4096,
	}
}

// Analyzer analyses documents. The zero value works and uses DefaultLimits.
type Analyzer struct {
	Limits Limits
}

func (a *Analyzer) limits() Limits {
	if a.Limits.MaxEntries == 0 {
		return DefaultLimits()
	}
	return a.Limits
}

// Analyze examines a document and reports what oletools would report.
//
// Never returns nil and never fails: a file that is not an Office document at all
// yields an output with nothing set, which is the honest answer rather than an error.
// Callers distinguish "no macros" from "not examined" by whether indicators is
// populated at all.
func (a *Analyzer) Analyze(raw []byte) *mdm.OleToolsOutput {
	out := &mdm.OleToolsOutput{}
	if len(raw) == 0 {
		return out
	}

	switch detectFormat(raw) {
	case formatOOXML:
		a.analyzeOOXML(raw, out)
	case formatOLE2:
		a.analyzeOLE2(raw, out)
	default:
		// Not an Office document. Nothing is reported, and in particular no
		// indicator is set to false: "this is a PNG" is not evidence that a
		// document has no macros.
		return out
	}
	return out
}
