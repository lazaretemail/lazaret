// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"strings"
	"testing"
)

// The copy-token bit widths, checked against MS-OVBA's CopyTokenHelp.
//
// The specification computes bitCount as max(4, ceiling(log2(difference))) where
// difference is how much of the current chunk has been decompressed. The boundary
// cases are the ones that matter: a width that is one too wide moves the split
// between offset and length, so every back-reference after that point in the chunk
// decodes to the wrong bytes — and real VBA is almost entirely back-references, so
// this is the difference between reading a macro and reading noise.
func TestCopyTokenBitWidths(t *testing.T) {
	cases := []struct {
		difference int
		wantBits   int
	}{
		{0, 4}, {1, 4}, {3, 4}, {15, 4},
		{16, 4}, // log2(16) is exactly 4 — not 5
		{17, 5},
		{31, 5}, {32, 5}, // log2(32) is exactly 5
		{33, 6},
		{4096, 12}, {8192, 12}, // capped at 12
	}
	for _, c := range cases {
		// unpackToken folds the width into its result, so it is probed with a
		// token whose length field is zero: length is then 3 and the offset is
		// whatever the width made of the high bits.
		_, length := unpackToken(0, c.difference)
		wantMask := 0xFFFF >> c.wantBits
		if got := length - 3; got != 0&wantMask {
			t.Errorf("difference %d: length decoded with the wrong mask", c.difference)
		}
		// The offset for a token of 0x1000 tells us the width directly.
		offset, _ := unpackToken(1<<(16-c.wantBits), c.difference)
		if offset != 2 {
			t.Errorf("difference %d: offset = %d, want 2 — bit width is not %d",
				c.difference, offset, c.wantBits)
		}
	}
}

// A hand-built chunk with a real back-reference, worked out from the specification
// rather than produced by a compressor of my own — a compressor written from the
// same misreading as the decompressor would agree with it and prove nothing.
//
// The chunk: literals 'a','b','c', then a copy token. At that point three bytes
// have been decompressed, so bitCount is 4, the length occupies the low twelve bits
// and the offset the high four. Offset 3 and length 3 encode as 0x2000, which
// copies "abc" again.
func TestCopyTokenExpandsABackReference(t *testing.T) {
	chunkBody := []byte{
		0x08,          // flags: items 0-2 literal, item 3 a copy token
		'a', 'b', 'c', //
		0x00, 0x20, //     token 0x2000: offset 3, length 3
	}
	header := 0x8000 | 0x3000 | ((len(chunkBody) - 3) & 0x0FFF)
	in := append([]byte{0x01, byte(header), byte(header >> 8)}, chunkBody...)

	got := string(decompressOVBA(in))
	if got != "abcabc" {
		t.Errorf("decompressOVBA = %q, want %q", got, "abcabc")
	}
}

// An overlapping copy, which the format allows and real compressors emit: the
// length may exceed the offset, so the copy reads bytes it is itself writing.
func TestOverlappingCopyRepeats(t *testing.T) {
	// One literal 'x', then offset 1 length 6 => "xxxxxxx".
	token := 0<<12 | (6 - 3) // offset 1 encodes as high bits 0; length 6 => 3
	chunkBody := []byte{0x02, 'x', byte(token), byte(token >> 8)}
	header := 0x8000 | 0x3000 | ((len(chunkBody) - 3) & 0x0FFF)
	in := append([]byte{0x01, byte(header), byte(header >> 8)}, chunkBody...)

	if got := string(decompressOVBA(in)); got != "xxxxxxx" {
		t.Errorf("overlapping copy = %q, want %q", got, "xxxxxxx")
	}
}

// Malformed input must stop, not read out of bounds or spin.
func TestDecompressRefusesMalformedInput(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":          {},
		"no signature":   {0x02, 0x00, 0x00},
		"truncated":      {0x01, 0xFF},
		"backref before": {0x01, 0x83, 0xB0, 0x02, 'x', 0xFF, 0xFF},
		"size overrun":   {0x01, 0xFF, 0xBF, 0x00},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v", name, r)
				}
			}()
			_ = decompressOVBA(in)
		}()
	}
}

// Keyword matching respects word boundaries. "Run" inside "Runtime" is not a call
// to Run, and counting it inflates the risk of every document that mentions one.
func TestKeywordsRespectWordBoundaries(t *testing.T) {
	found := scanKeywords("Dim Runtime As String\nDim OpenAIKey As String\n")
	for _, k := range found {
		switch strings.ToLower(derefStr(k.Keyword)) {
		case "run", "open":
			t.Errorf("%q matched inside a longer identifier", derefStr(k.Keyword))
		}
	}
}

// Risk grading: the judgement the high-risk rule depends on.
func TestRiskGrading(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{"nothing", "Sub Formatting()\nEnd Sub", riskNone},
		{"auto only", "Sub AutoOpen()\nMsgBox \"hi\"\nEnd Sub", riskMedium},
		{"auto plus capability", "Sub AutoOpen()\nShell \"cmd\"\nEnd Sub", riskHigh},
		{"capabilities without auto", "Sub Go()\nShell x\nCreateObject y\nURLDownloadToFile z\nEnd Sub", riskHigh},
	}
	for _, c := range cases {
		if got := riskOf(scanKeywords(c.source)); got != c.want {
			t.Errorf("%s: risk = %q, want %q", c.name, got, c.want)
		}
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
