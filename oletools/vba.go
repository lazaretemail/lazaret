// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"strings"
	"unicode"

	"github.com/lazaretemail/lazaret/mdm"
)

// Getting the VBA source out of a document.
//
// The source is not stored as text. Each module stream holds a binary performance
// cache followed by the source compressed with the run-length scheme in MS-OVBA, and
// the offset where the source begins is recorded in a separate `dir` stream that is
// itself compressed the same way.
//
// This finds the compressed regions by signature and decompresses them, which is the
// same fallback oletools uses and is markedly more robust on damaged files than
// trusting the offsets: a malformed `dir` stream is a common evasion, and a document
// whose directory lies about its own layout still has to hand real VBA to the VBA
// engine.

// analyzeVBA fills in the macro indicators from a VBA project, which is a compound
// file in its own right even when it came out of a zip.
func (a *Analyzer) analyzeVBA(project []byte, out *mdm.OleToolsOutput) {
	if out.Indicators == nil {
		out.Indicators = &mdm.OleIndicators{}
	}

	if len(project) == 0 {
		// No VBA project part. That is a definite absence, not an unknown: the
		// container was read and there was no macro storage in it.
		out.Indicators.VBAMacros = &mdm.OleIndicator{
			Exists: mdm.Ptr(false),
			Risk:   mdm.Ptr(riskNone),
		}
		return
	}

	c, err := parseCFB(project)
	if err != nil {
		// A vbaProject.bin that is not a compound file is malformed. Saying
		// "no macros" would be a guess in the dangerous direction, so nothing
		// is asserted.
		return
	}

	source := extractSource(c)
	a.reportMacros(source, out)
}

// reportMacros turns extracted source into the indicators and keywords the corpus
// reads.
func (a *Analyzer) reportMacros(source string, out *mdm.OleToolsOutput) {
	if out.Indicators == nil {
		out.Indicators = &mdm.OleIndicators{}
	}
	if strings.TrimSpace(source) == "" {
		out.Indicators.VBAMacros = &mdm.OleIndicator{
			Exists: mdm.Ptr(false),
			Risk:   mdm.Ptr(riskNone),
		}
		return
	}

	found := scanKeywords(source)
	out.Macros = &mdm.OleMacros{
		Keywords:          found,
		VBACodeAllModules: mdm.Ptr(source),
	}
	out.Indicators.VBAMacros = &mdm.OleIndicator{
		Exists: mdm.Ptr(true),
		Risk:   mdm.Ptr(riskOf(found)),
	}
}

// extractSource pulls the decompressed source out of every module stream.
//
// Streams that are part of the project's bookkeeping rather than its code are
// skipped by name; everything else is tried, because module streams are named by
// the author and can be called anything.
func extractSource(c *cfb) string {
	var b strings.Builder
	for _, e := range c.dir {
		if e.Type != objStream || isProjectMetadata(e.Name) {
			continue
		}
		data := c.Open(e)
		if len(data) == 0 {
			continue
		}
		if src := decompressSource(data); src != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(src)
		}
	}
	return b.String()
}

// isProjectMetadata names the streams that hold structure rather than code.
func isProjectMetadata(name string) bool {
	switch strings.ToLower(name) {
	case "dir", "_vba_project", "project", "projectwm", "projectlk", "compobj",
		"summaryinformation", "documentsummaryinformation":
		return true
	}
	return strings.HasPrefix(name, "\x01") || strings.HasPrefix(name, "\x05")
}

// decompressSource finds and decompresses the compressed region of a module stream.
//
// The source begins at an offset the stream does not state, so each plausible start
// is tried — a 0x01 signature byte — and the first that yields something that reads
// like source is taken. Bounded to a few attempts per stream so that a stream full
// of 0x01 bytes cannot turn into thousands of decompression attempts.
func decompressSource(stream []byte) string {
	const maxAttempts = 64
	attempts := 0
	for i, b := range stream {
		if b != 0x01 {
			continue
		}
		attempts++
		if attempts > maxAttempts {
			break
		}
		out := decompressOVBA(stream[i:])
		if looksLikeSource(out) {
			return string(out)
		}
	}
	return ""
}

// looksLikeSource distinguishes decompressed VBA from noise that happened to
// decompress. Real source is mostly printable and of some length.
func looksLikeSource(b []byte) bool {
	if len(b) < 16 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7F) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.9
}

// decompressOVBA implements the MS-OVBA compressed container format.
//
// The container is a signature byte followed by chunks. Each chunk has a two-byte
// header giving its compressed size and whether it is compressed at all; a
// compressed chunk is a sequence of groups, each an eight-bit flag byte saying which
// of the next eight items are literal bytes and which are copy tokens referring
// backwards into what has already been decompressed.
//
// The awkward part, and the part naive implementations get wrong, is that the split
// of a copy token into offset and length depends on how much has been decompressed
// in the current chunk — the bit widths move as the window grows.
func decompressOVBA(in []byte) []byte {
	if len(in) < 3 || in[0] != 0x01 {
		return nil
	}
	const maxOutput = 16 << 20

	var out []byte
	pos := 1

	for pos+1 < len(in) && len(out) < maxOutput {
		header := int(in[pos]) | int(in[pos+1])<<8
		pos += 2

		size := (header & 0x0FFF) + 3
		compressed := header&0x8000 != 0
		// A chunk claiming more than remains is a truncated or crafted stream.
		if size > len(in)-pos {
			size = len(in) - pos
		}
		if size <= 0 {
			break
		}
		chunk := in[pos : pos+size]
		pos += size

		if !compressed {
			out = append(out, chunk...)
			continue
		}

		start := len(out)
		i := 0
		for i < len(chunk) && len(out) < maxOutput {
			flags := chunk[i]
			i++
			for bit := 0; bit < 8 && i < len(chunk); bit++ {
				if flags&(1<<bit) == 0 {
					out = append(out, chunk[i])
					i++
					continue
				}
				if i+1 >= len(chunk) {
					i = len(chunk)
					break
				}
				token := int(chunk[i]) | int(chunk[i+1])<<8
				i += 2

				offset, length := unpackToken(token, len(out)-start)
				src := len(out) - offset
				if offset == 0 || src < 0 {
					// A token pointing before the start of the chunk is
					// malformed. Stop rather than read out of bounds.
					return out
				}
				for n := 0; n < length && len(out) < maxOutput; n++ {
					out = append(out, out[src+n])
				}
			}
		}
	}
	return out
}

// unpackToken splits a copy token, whose field widths depend on the position within
// the chunk being decompressed.
func unpackToken(token, decompressedSoFar int) (offset, length int) {
	// bitCount = max(4, ceiling(log2(difference))), bounded at 12.
	//
	// The comparison is strict, and that is the whole subtlety. At a difference of
	// exactly 16 the logarithm is exactly 4, so the width stays 4; a `<=` here — or
	// the `< difference+1` this used to say — widens it one step early, which moves
	// the boundary between the offset and length fields. Every back-reference after
	// that point in the chunk then decodes to the wrong bytes, and since real VBA is
	// almost all back-references the result is noise rather than source. It looked
	// right on fixtures built only from literal tokens.
	bits := 4
	for shift := 1 << 4; shift < decompressedSoFar && bits < 12; shift <<= 1 {
		bits++
	}
	lengthMask := 0xFFFF >> bits
	length = (token & lengthMask) + 3
	offset = (token &^ lengthMask) >> (16 - bits)
	offset++
	return offset, length
}

// trimNonPrintable is used on extracted source before keyword matching, so that a
// module padded with binary does not defeat a word-boundary match.
func trimNonPrintable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, s)
}
