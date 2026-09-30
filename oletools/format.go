// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import "bytes"

// What kind of container a document is.
//
// Office has two, and they are unrelated: the modern formats are zip archives of XML,
// and the legacy ones are OLE2 compound files — a FAT filesystem in a file. A .docm
// is the first; a .doc is the second; and an encrypted .docx is, confusingly, the
// second wrapping the first.
type format int

const (
	formatUnknown format = iota
	formatOOXML
	formatOLE2
)

var (
	// "PK\x03\x04". Also matched by the empty and spanned variants, which are not
	// documents.
	zipMagic = []byte{'P', 'K', 0x03, 0x04}

	// The OLE2 compound file header signature, unchanged since 1992.
	ole2Magic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
)

func detectFormat(raw []byte) format {
	switch {
	case bytes.HasPrefix(raw, ole2Magic):
		return formatOLE2
	case bytes.HasPrefix(raw, zipMagic):
		return formatOOXML
	default:
		return formatUnknown
	}
}

// formatName is what oletools calls the container, for indicators.file_format.value.
func formatName(f format) string {
	switch f {
	case formatOOXML:
		return "OpenXML"
	case formatOLE2:
		return "OLE"
	default:
		return ""
	}
}
