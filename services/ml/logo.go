// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"math/bits"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// LogoDetect answers ml.logo_detect — 100 rules, second only to the NLU classifier.
//
// # Two signals, because brand logos are two different things
//
// Most of the brands the corpus asks about are *wordmarks*: PayPal, Netflix, Norton,
// McAfee, DocuSign, Geek Squad, eBay, AT&T. Their logo is their name set in a
// typeface. Those are found by reading the text in the image, and reading text in an
// image is OCR, which this platform already runs — Strelka's ocr scanner. So the
// caller passes the OCR text alongside the image and the match is a lexical one.
//
// The rest are *symbols*: the Dropbox box, the Meta loop, the Chase octagon. No amount
// of OCR finds those, and they need an image comparison. That is perceptual hashing
// against a reference pack of logo images.
//
// # Why no reference pack ships
//
// The pack is logos, which is to say other companies' trademarks. Using a mark to
// identify the mark-holder is nominative use and is exactly what a brand-impersonation
// detector is for — but bundling fifty companies' logos into an AGPL repository is a
// distribution question rather than a use question, and it is not one to answer by
// default on an operator's behalf. So the directory is empty, the symbol half reports
// unavailable, and `lazaret-ml fetch-models` will populate it on request.
//
// The wordmark half needs no pack and works out of the box.
type LogoDetect struct {
	mu   sync.RWMutex
	refs []logoRef

	// localWords are wordmark patterns derived from the names of brand directories
	// an operator supplied. The built-in patterns cover the built-in vocabulary;
	// without these, a brand somebody added would be matchable by its picture and
	// not by its name, which is a strange half of the thing to get.
	localWords map[string]*regexp.Regexp
}

type logoRef struct {
	Brand string
	Hash  uint64

	// group names the source logo this is a rendering of, so the pack builder can
	// tell renderings of one mark apart from a brand's several different marks.
	// Empty for a reference loaded from a pack, where the question is settled.
	group string
}

// logoMaxDistance is how many of the 64 bits may differ and still be the same mark.
//
// Measured against what actually arrives. Every reference was put through six things a
// logo picks up on its way into a mailbox — rescaled to half and to double, cropped
// four pixels in, padded, composited on a grey background, and JPEG-recompressed at
// quality 60 — giving 558 images to look up:
//
//	threshold   recall   variants reporting a brand that is not there
//	    < 8       89%              0 / 558
//	   < 10       91%              0 / 558
//	   < 12       93%              0 / 558
//	   < 14       94%              0 / 558
//	   < 16       96%              2 / 558
//
// Fourteen is the last threshold that never reports a brand that is not there. The
// matcher returns every brand inside the threshold rather than the closest one, so a
// spurious match is not outvoted by a better one — it is simply reported, and a
// brand-impersonation rule handed a brand that is not in the image is worse than one
// handed nothing.
//
// The number is only meaningful because the references are the brands' real logos, all
// of them. Two earlier packs failed here: one built from favicons put 37 of 47 brands
// inside the threshold of each other, and one built from a monochrome icon set was
// internally clean but matched the real logo it stood for in 1 case out of 31.
const logoMaxDistance = 14

// logoPackMargin is the bar a reference must clear to go into a pack, as opposed to
// the bar two images must clear to be called the same mark.
//
// Separate from logoMaxDistance on purpose, and larger. When the pack guards used the
// match threshold directly, tuning the threshold changed which references survived,
// which changed the measurement the threshold was tuned from. Fixing the margin breaks
// that loop: the pack is clean for any threshold up to this, so the threshold can be
// read off the recall curve without reshaping the thing being measured.
const logoPackMargin = 16

// flattenOnWhite composites a transparent image onto white.
//
// Not cosmetic. A brand logo is almost always distributed with a transparent
// background — 108 of the 111 reference images this pack was built from — and Go's
// image.At returns premultiplied values, so a transparent pixel reads as black.
// Hashing that gives the mark on black; the same logo in an email sits on the message
// background, which is white. Measured on one reference: mean luminance 9 unflattened
// against 179 flattened. dHash compares neighbours, so inverting the field inverts
// nearly every comparison, and a reference hashed the wrong way round is not merely
// weaker than its subject, it is close to its complement.
func flattenOnWhite(img image.Image) image.Image {
	b := img.Bounds()
	out := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA() // premultiplied, 16-bit
			inv := 0xffff - a
			out.SetRGBA64(x, y, color.RGBA64{
				R: uint16(r + inv),
				G: uint16(g + inv),
				B: uint16(bl + inv),
				A: 0xffff,
			})
		}
	}
	return out
}

// cropToInk trims the uniform border around a mark.
//
// A logo arrives in a message at whatever size and padding the sender chose, and a
// hash taken over the padding is a hash of the padding. Background is read from the
// corner pixel, which is what it is in every logo image and every screenshot crop.
func cropToInk(img image.Image) image.Image {
	sub, ok := img.(interface {
		SubImage(image.Rectangle) image.Image
	})
	if !ok {
		return img
	}
	b := img.Bounds()
	br, bg, bb, _ := img.At(b.Min.X, b.Min.Y).RGBA()
	inked := func(x, y int) bool {
		r, g, bl, a := img.At(x, y).RGBA()
		if a < 0x4000 {
			return false // transparent is background whatever colour it claims
		}
		const tol = 24 << 8
		return abs32(int32(r)-int32(br)) > tol ||
			abs32(int32(g)-int32(bg)) > tol ||
			abs32(int32(bl)-int32(bb)) > tol
	}

	minX, minY, maxX, maxY := b.Max.X, b.Max.Y, b.Min.X, b.Min.Y
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if !inked(x, y) {
				continue
			}
			if x < minX {
				minX = x
			}
			if y < minY {
				minY = y
			}
			if x > maxX {
				maxX = x
			}
			if y > maxY {
				maxY = y
			}
		}
	}
	if minX > maxX || minY > maxY {
		return img // all one colour; nothing to crop to
	}
	return sub.SubImage(image.Rect(minX, minY, maxX+1, maxY+1))
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

func (l *LogoDetect) Capability() string { return "ml.logo_detect" }
func (l *LogoDetect) Close() error       { return nil }

type logoResult struct {
	Brands []jsonBrand `json:"brands"`

	// Unavailable is set when neither signal could run, so the client can report the
	// capability missing rather than the image containing no brands.
	Unavailable bool `json:"unavailable,omitempty"`
}

type jsonBrand struct {
	Name       string   `json:"name"`
	Confidence string   `json:"confidence"`
	Score      *float64 `json:"score,omitempty"`
}

// brandPatterns matches a brand's wordmark in OCR text.
//
// Built once from the corpus vocabulary, with the spellings OCR actually produces:
// letter case is lost, spacing is unreliable, and a capital I and a lowercase l are
// the same glyph in many typefaces. So the match is case-insensitive, tolerant of
// internal spacing, and anchored on word boundaries — "X" as a brand would otherwise
// match every occurrence of the letter.
var brandPatterns = buildBrandPatterns()

// minDerivedWordmark is how short a brand directory's name may be before its wordmark
// is left out.
//
// A name is turned into a pattern that matches the name, which is fine for "Acme Bank"
// and reckless for "IT" or "Pay". Three characters or fewer is not a wordmark, it is a
// substring of ordinary mail, and the built-in list already shows what that costs:
// "ups" is the plural of "up" and "X" is a letter. Short names still work by picture.
const minDerivedWordmark = 4

// wordmarkFor turns a brand directory's name into a pattern that matches that name in
// OCR text, or nil when the name is too short to be safe.
//
// Spaces become "one or more spaces" because OCR spacing is unreliable, and the whole
// thing is anchored on word boundaries. Everything else is quoted: a directory name is
// a name, not a regular expression, and an operator should not have to know that a
// bracket in their brand name would be a syntax error.
func wordmarkFor(brand string) *regexp.Regexp {
	trimmed := strings.TrimSpace(brand)
	if len([]rune(trimmed)) < minDerivedWordmark {
		return nil
	}
	lower := strings.ToLower(trimmed)
	parts := strings.Fields(lower)
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	if len(parts) == 0 {
		return nil
	}
	body := strings.Join(parts, `\s+`)

	// Anchor only where an anchor means something. \b asserts a word character on
	// one side, so putting it next to punctuation asserts the opposite of what is
	// wanted: `\bltd\.\b` cannot match "Ltd." followed by a space, because "." and
	// " " are both non-word. A name ending in a full stop or wrapped in brackets is
	// ordinary — "Acme (Holdings) Ltd." — and would silently never match.
	runes := []rune(lower)
	pattern := body
	if isWordRune(runes[0]) {
		pattern = `\b` + pattern
	}
	if isWordRune(runes[len(runes)-1]) {
		pattern += `\b`
	}

	re, err := regexp.Compile(`(?i)` + pattern)
	if err != nil {
		return nil
	}
	return re
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func buildBrandPatterns() map[string]*regexp.Regexp {
	// Aliases for the brands whose wordmark is not their label, plus the classes that
	// are not brands at all and can only come from the reference pack.
	alias := map[string][]string{
		"AT&T":                 {`at\s*&\s*t`, `at\s*and\s*t`},
		"Ebay":                 {`ebay`},
		"GeekSquad":            {`geek\s*squad`},
		"Quickbooks":           {`quick\s*books`, `intuit\s+quickbooks`},
		"Microsoft OneDrive":   {`one\s*drive`},
		"Microsoft SharePoint": {`share\s*point`},
		"Gemini Trust":         {`gemini`},
		"Robert Half":          {`robert\s*half`},
		"TD Bank":              {`td\s*bank`},
		"Capital One Bank":     {`capital\s*one`},
		"MetaMask":             {`meta\s*mask`},
		"MailChimp":            {`mail\s*chimp`},
		"SendGrid":             {`send\s*grid`},
		"SSA":                  {`social\s+security\s+administration`, `\bssa\b`},
		"USPS":                 {`\busps\b`, `united\s+states\s+postal`},
		"PNC":                  {`\bpnc\b`},
		"DHL":                  {`\bdhl\b`},
		"FedEx":                {`fed\s*ex`},
		"X":                    {}, // a single letter: unmatchable in text without false positives
		"Meta":                 {`\bmeta\b`},
		"Box":                  {`\bbox\b`},
		"Square":               {`\bsquare\b`},
		"FakeAttachment":       {},
		"Generic Webmail":      {},
		"Invite Company":       {},

		// Agencies and carriers. An acronym is the whole risk here: three letters
		// with word boundaries still matches ordinary prose, and OCR turns every
		// layout into prose. So each short form is paired with the spelled-out
		// name, and the ones that are common English words are the spelled-out
		// name only.
		"IRS":                  {`\birs\b`, `internal\s+revenue\s+service`},
		"US Treasury":          {`(?:u\.?\s*s\.?|united\s+states)\s+(?:department\s+of\s+the\s+)?treasury`},
		"FBI":                  {`\bfbi\b`, `federal\s+bureau\s+of\s+investigation`},
		"DHS":                  {`\bdhs\b`, `department\s+of\s+homeland\s+security`},
		"CISA":                 {`\bcisa\b`, `cybersecurity\s+and\s+infrastructure\s+security`},
		"USCIS":                {`\buscis\b`, `citizenship\s+and\s+immigration`},
		"Medicare":             {`\bmedicare\b`},
		"US Dept of Education": {`department\s+of\s+education`, `federal\s+student\s+aid`},
		"E-ZPass":              {`e[\s-]*z\s*pass`},
		"NHS":                  {`\bnhs\b`, `national\s+health\s+service`},
		"TV Licensing":         {`tv\s+licen[cs]ing`},
		"DVLA":                 {`\bdvla\b`, `driver\s+and\s+vehicle\s+licensing`},
		"HMRC":                 {`\bhmrc\b`, `hm\s+revenue`, `his\s+majesty.?s\s+revenue`},
		"Royal Mail":           {`royal\s*mail`},
		// "ups" is the plural of "up". Only the full name is safe.
		"UPS":            {`united\s+parcel\s+service`},
		"An Post":        {`\ban\s+post\b`},
		"Australia Post": {`australia\s*post`},
		"Canada Post":    {`canada\s*post`, `postes\s+canada`},
		"Chronopost":     {`chronopost`},
		"Correos":        {`\bcorreos\b`},
		"DPD":            {`\bdpd\b`},
		"La Poste":       {`la\s+poste`},
		"PostNL":         {`post\s*nl`},
		"PostNord":       {`post\s*nord`},
		"Poste Italiane": {`poste\s+italiane`},
		"Swiss Post":     {`swiss\s*post`, `die\s+schweizerische\s+post`},
	}

	out := map[string]*regexp.Regexp{}
	for _, b := range AllBrands() {
		alts, ok := alias[b]
		if !ok {
			alts = []string{regexp.QuoteMeta(strings.ToLower(b))}
		}
		if len(alts) == 0 {
			continue // reference-pack only
		}
		out[b] = regexp.MustCompile(`(?i)\b(?:` + strings.Join(alts, "|") + `)\b`)
	}
	return out
}

func (l *LogoDetect) Infer(ctx context.Context, req Request) (any, error) {
	ocr := req.Options["ocr_text"]

	l.mu.RLock()
	refs, localWords := l.refs, l.localWords
	l.mu.RUnlock()

	if ocr == "" && len(refs) == 0 {
		// Nothing to look with. Not "no brands present".
		return logoResult{Brands: nil, Unavailable: true}, nil
	}

	best := map[string]float64{}
	if ocr != "" {
		for brand, re := range brandPatterns {
			if re.MatchString(ocr) {
				// A wordmark read out of an image is a strong signal. It is still
				// only "this name appears", which is why it is high rather than
				// certain: a genuine footer mentioning a partner reads the same.
				best[brand] = 0.9
			}
		}
		for brand, re := range localWords {
			if re.MatchString(ocr) && best[brand] < 0.9 {
				best[brand] = 0.9
			}
		}
	}
	if len(refs) > 0 && len(req.Image) > 0 {
		h, err := perceptualHash(req.Image)
		if err == nil {
			for _, r := range refs {
				d := bits.OnesCount64(h ^ r.Hash)
				if d < logoMaxDistance {
					s := 1 - float64(d)/logoMaxDistance
					if s > best[r.Brand] {
						best[r.Brand] = s
					}
				}
			}
		}
	}

	out := logoResult{Brands: []jsonBrand{}}
	for brand, s := range best {
		conf := ConfLow
		switch {
		case s >= 0.85:
			conf = ConfHigh
		case s >= 0.6:
			conf = ConfMedium
		}
		score := s
		out.Brands = append(out.Brands, jsonBrand{Name: brand, Confidence: conf, Score: &score})
	}
	sort.Slice(out.Brands, func(i, j int) bool {
		if *out.Brands[i].Score != *out.Brands[j].Score {
			return *out.Brands[i].Score > *out.Brands[j].Score
		}
		return out.Brands[i].Name < out.Brands[j].Name
	})
	return out, nil
}

// perceptualHash computes a 64-bit difference hash of the mark in an image.
//
// dHash rather than average hash: it compares each pixel to its right-hand neighbour,
// so it measures gradients rather than absolute brightness and survives the recolouring
// and rescaling a logo gets when it is pasted into an email.
//
// The tight crop in front of it is not a refinement, it is what makes the hash mean
// anything. Measured over 37 real brand marks at three scales each: cropping to the ink
// first gives 91% recall at zero false matches in 5,994 impostor pairs. Without it the
// hash is mostly a description of how much white space the sender left around the logo,
// and the same mark with different padding lands nowhere near itself.
func perceptualHash(raw []byte) (uint64, error) {
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	return hashOf(flattenOnWhite(img))
}

// hashOf is perceptualHash's second half, for callers that already have an image.
func hashOf(img image.Image) (uint64, error) {
	img = cropToInk(img)
	const w, h = 9, 8
	b := img.Bounds()
	if b.Dx() == 0 || b.Dy() == 0 {
		return 0, fmt.Errorf("empty image")
	}
	var grid [h][w]float64
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// Box-average the source region rather than point-sampling, so a logo
			// with thin strokes does not hash differently depending on which pixel
			// a nearest-neighbour resize happened to land on.
			x0 := b.Min.X + x*b.Dx()/w
			x1 := b.Min.X + (x+1)*b.Dx()/w
			y0 := b.Min.Y + y*b.Dy()/h
			y1 := b.Min.Y + (y+1)*b.Dy()/h
			if x1 <= x0 {
				x1 = x0 + 1
			}
			if y1 <= y0 {
				y1 = y0 + 1
			}
			sum, n := 0.0, 0.0
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					r, g, bl, _ := img.At(xx, yy).RGBA()
					sum += 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(bl)
					n++
				}
			}
			grid[y][x] = sum / n
		}
	}
	var out uint64
	i := 0
	for y := 0; y < h; y++ {
		for x := 0; x < w-1; x++ {
			if grid[y][x] > grid[y][x+1] {
				out |= 1 << uint(i)
			}
			i++
		}
	}
	return out, nil
}

// MarshalJSON keeps the brands key present even when empty, because an empty array and
// an absent one mean different things to the evaluator and only the client decides
// which to send.
func (r logoResult) MarshalJSON() ([]byte, error) {
	type alias logoResult
	if r.Brands == nil && !r.Unavailable {
		r.Brands = []jsonBrand{}
	}
	return json.Marshal(alias(r))
}
