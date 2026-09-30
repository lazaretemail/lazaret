// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"strings"

	"github.com/lazaretemail/lazaret/mdm"
)

// The legacy path: a document that is itself a compound file.
//
// Two quite different things arrive here. A real .doc or .xls, where the macros live
// in a storage beside the document body; and an *encrypted* .docx, which is an OOXML
// package wrapped in a compound file so that the zip inside can be ciphertext. The
// second is why encryption detection lives on this path rather than the other.

func (a *Analyzer) analyzeOLE2(raw []byte, out *mdm.OleToolsOutput) {
	out.Indicators = &mdm.OleIndicators{
		FileFormat: &mdm.OleIndicator{Value: mdm.Ptr(formatName(formatOLE2))},
	}

	c, err := parseCFB(raw)
	if err != nil {
		return
	}

	// An EncryptedPackage stream means the real document is ciphertext inside
	// this container. Nothing further can be said about its macros, and saying
	// "no macros" about a document nobody can read would be a lie that rules
	// would act on.
	if _, ok := c.Find("EncryptedPackage"); ok {
		out.Indicators.Encryption = &mdm.OleIndicator{Exists: mdm.Ptr(true), Risk: mdm.Ptr(riskMedium)}
		return
	}
	out.Indicators.Encryption = &mdm.OleIndicator{Exists: mdm.Ptr(false)}

	// In a legacy document the VBA streams sit in this same compound file rather
	// than in a nested vbaProject.bin, so the source is extracted directly.
	source := extractSource(c)
	if source == "" && hasVBAStorage(c) {
		// There is a macro project here and its source could not be read —
		// damaged, or deliberately malformed, which is itself a technique.
		// Reporting exists=false would be a guess in the dangerous direction,
		// so the indicator is left unset and rules report indeterminate.
		return
	}
	a.reportMacros(source, out)
}

// hasVBAStorage reports whether any stream looks like part of a VBA project, used
// to tell "a compound file with no macros" from "a compound file this could not
// read".
func hasVBAStorage(c *cfb) bool {
	for _, e := range c.dir {
		n := strings.ToLower(e.Name)
		if n == "vba" || n == "_vba_project" || n == "dir" || n == "thisdocument" {
			return true
		}
	}
	return false
}
