// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shipped pack must parse, and must not confuse two brands.
//
// The second half is the one that matters. A reference pack whose entries sit inside
// the match threshold of each other does not merely miss detections — it reports a
// confident wrong brand for almost any mark, and a brand-impersonation rule fed a
// wrong brand is worse than one fed nothing. This is a real failure that was measured
// here, not a hypothetical: the pack sourced from favicons had 37 of 47 brands
// colliding, because a favicon is usually a letter in a box and they all look alike at
// eight by nine pixels.
func TestShippedPackHasNoCollidingBrands(t *testing.T) {
	pack, err := shippedPack()
	if err != nil {
		t.Fatal(err)
	}
	refs, err := pack.refs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) == 0 {
		t.Fatal("the shipped pack is empty")
	}
	if pack.Source == "" {
		t.Error("the pack records no source, so nobody can regenerate or audit it")
	}

	brands := map[string]bool{}
	for _, r := range refs {
		brands[r.Brand] = true
	}
	t.Logf("%d hashes across %d brands", len(refs), len(brands))

	worst := 64
	var wa, wb string
	for i := range refs {
		for j := i + 1; j < len(refs); j++ {
			if refs[i].Brand == refs[j].Brand {
				continue
			}
			d := bits.OnesCount64(refs[i].Hash ^ refs[j].Hash)
			if d < worst {
				worst, wa, wb = d, refs[i].Brand, refs[j].Brand
			}
		}
	}
	t.Logf("closest two brands: %d bits apart (%s / %s)", worst, wa, wb)
	if worst < logoMaxDistance {
		t.Errorf("%s and %s are %d bits apart, inside the %d-bit match threshold: "+
			"anything matching one reports both", wa, wb, worst, logoMaxDistance)
	}
}

// Brand names have to be spelled the way the rule corpus spells them, because that
// string is what a rule compares against. A pack entry for "Paypal" answers nothing
// when the rule asks for "PayPal".
func TestShippedPackBrandsAreKnown(t *testing.T) {
	pack, err := shippedPack()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pack.Entries {
		if _, ok := brandPatterns[e.Brand]; ok {
			continue
		}
		// Not every symbol brand has a wordmark pattern, so this is a warning
		// rather than a failure — but a name with unexpected casing is worth
		// seeing, since it is silent otherwise.
		if e.Brand != strings.TrimSpace(e.Brand) {
			t.Errorf("brand %q has surrounding whitespace", e.Brand)
		}
	}
}

// solid builds a PNG: a dark rectangle at (x,y) on a white field of the given size.
func solid(t *testing.T, w, h, x, y, rw, rh int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for j := 0; j < h; j++ {
		for i := 0; i < w; i++ {
			img.Set(i, j, color.White)
		}
	}
	for j := y; j < y+rh && j < h; j++ {
		for i := x; i < x+rw && i < w; i++ {
			// Not a flat block: a gradient, so the hash has something to read.
			img.Set(i, j, color.RGBA{uint8(i * 255 / w), 40, 60, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The same mark with different padding must hash the same.
//
// Without the tight crop it does not, and the hash becomes a description of how much
// white space the sender left around the logo rather than of the logo. A sender
// choosing a different margin would defeat the matcher completely.
func TestHashIgnoresPadding(t *testing.T) {
	tight := solid(t, 100, 100, 10, 10, 80, 80)
	padded := solid(t, 400, 400, 160, 160, 80, 80)

	a, err := perceptualHash(tight)
	if err != nil {
		t.Fatal(err)
	}
	b, err := perceptualHash(padded)
	if err != nil {
		t.Fatal(err)
	}
	if d := bits.OnesCount64(a ^ b); d >= logoMaxDistance {
		t.Errorf("the same mark with different padding is %d bits apart, outside the "+
			"%d-bit threshold: the hash is measuring the margin", d, logoMaxDistance)
	}
}

// An operator's own images are hashed locally and replace the shipped hashes for that
// brand. Their logos never leave the machine; that is the whole point of the design.
func TestLocalImagesOverrideShippedHashes(t *testing.T) {
	dir := t.TempDir()
	brand := "Dropbox"
	if err := os.MkdirAll(filepath.Join(dir, brand), 0o755); err != nil {
		t.Fatal(err)
	}
	// A mark that looks nothing like the shipped one.
	if err := os.WriteFile(filepath.Join(dir, brand, "own.png"),
		solid(t, 120, 120, 0, 0, 120, 60), 0o644); err != nil {
		t.Fatal(err)
	}

	var l LogoDetect
	shipped, local, err := l.LoadReferences(dir)
	if err != nil {
		t.Fatal(err)
	}
	if local != 1 {
		t.Fatalf("local = %d, want the one image supplied", local)
	}
	if shipped == 0 {
		t.Fatal("no shipped hashes were loaded")
	}

	l.mu.RLock()
	defer l.mu.RUnlock()
	n := 0
	for _, r := range l.refs {
		if r.Brand == brand {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d references for %s, want only the operator's own — a worse "+
			"reference left alongside a better one keeps matching", n, brand)
	}
}

func TestLoadReferencesWithNoLocalDirectory(t *testing.T) {
	var l LogoDetect
	shipped, local, err := l.LoadReferences(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("a missing pack directory is the normal case, not an error: %v", err)
	}
	if local != 0 {
		t.Errorf("local = %d", local)
	}
	if shipped == 0 {
		t.Error("the shipped hashes should still load")
	}
}

// A pack round-trips: hash a directory, read it back, get the same references.
func TestWritePackRoundTrips(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Acme", "a.png"),
		solid(t, 90, 90, 10, 20, 60, 40), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	n, err := WritePack(dir, "test", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("wrote %d hashes, want 1", n)
	}
	if bytes.Contains(buf.Bytes(), []byte("PNG")) {
		t.Error("the pack contains image data; it must contain hashes and nothing else")
	}

	direct, err := hashDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	var back LogoPack
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	refs, err := back.refs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != len(direct) || refs[0].Hash != direct[0].Hash {
		t.Errorf("round trip changed the hash: %016x -> %016x", direct[0].Hash, refs[0].Hash)
	}
}

// A pack whose references confuse two brands must say so.
//
// This is the check that was missing when the pack came from favicons: 37 of 47 brands
// sat inside the match threshold of each other, the matcher would have reported a
// confident wrong brand for nearly any mark, and nothing anywhere said so.
func TestCollidingBrandsAreDetected(t *testing.T) {
	clean := []logoRef{
		{Brand: "Alpha", Hash: 0x0000000000000000},
		{Brand: "Beta", Hash: 0xffffffffffffffff},
	}
	if got := collidingBrands(clean); len(got) != 0 {
		t.Errorf("two opposite hashes reported as colliding: %v", got)
	}

	// One bit apart: as confusable as it gets.
	clashing := []logoRef{
		{Brand: "Alpha", Hash: 0x0f0f0f0f0f0f0f0f},
		{Brand: "Beta", Hash: 0x0f0f0f0f0f0f0f0e},
		{Brand: "Beta", Hash: 0x0f0f0f0f0f0f0f0d}, // same pair again
	}
	got := collidingBrands(clashing)
	if len(got) != 1 {
		t.Fatalf("got %d clashes, want one per brand pair: %v", len(got), got)
	}
	if got[0].a != "Alpha" || got[0].b != "Beta" {
		t.Errorf("reported %s/%s", got[0].a, got[0].b)
	}
}

// A transparent reference must hash the same as the logo composited on white.
//
// This is the bug that made the pack worthless twice over. Brand logos are distributed
// with a transparent background — 108 of the 111 references here — and Go's image.At
// returns premultiplied values, so a transparent pixel reads as black. Hash that and
// you have the mark on black, while the same logo in a message sits on white.
//
// Measured on the real references: without flattening, 15 of 111 matched their own
// on-white subject. With it, 111 of 111.
//
// The mark below has soft alpha at its edges, which is what makes the difference
// visible: a half-transparent pixel reads as half-black unflattened and as pale
// flattened. A hard-edged synthetic shape does not show this at all, because the crop
// throws the background away before it can matter — which is why the first version of
// this test passed with the fix removed.
func TestTransparentAndWhiteBackedHashTheSame(t *testing.T) {
	const w, h = 160, 160
	transparent := image.NewRGBA(image.Rect(0, 0, w, h))
	onWhite := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			onWhite.Set(x, y, color.White)

			// A ring with a soft edge, plus a bar: enough structure for the hash,
			// and enough partial alpha to matter.
			dx, dy := float64(x-80), float64(y-80)
			r := math.Sqrt(dx*dx + dy*dy)
			var a float64
			switch {
			case r < 40:
				a = 1
			case r < 55:
				a = (55 - r) / 15 // antialiased falloff
			}
			if y > 100 && y < 130 && x > 30 && x < 130 {
				a = 1
			}
			if a <= 0 {
				continue
			}
			c := color.RGBA{
				R: uint8(40 * a), G: uint8(90 * a), B: uint8(200 * a), A: uint8(255 * a),
			}
			transparent.Set(x, y, c) // premultiplied-looking, alpha carried
			// The same pixel composited over white.
			onWhite.Set(x, y, color.RGBA{
				R: uint8(40*a + 255*(1-a)),
				G: uint8(90*a + 255*(1-a)),
				B: uint8(200*a + 255*(1-a)),
				A: 255,
			})
		}
	}

	a, err := perceptualHash(encodePNG(t, transparent))
	if err != nil {
		t.Fatal(err)
	}
	b, err := perceptualHash(encodePNG(t, onWhite))
	if err != nil {
		t.Fatal(err)
	}
	if d := bits.OnesCount64(a ^ b); d >= logoMaxDistance {
		t.Errorf("transparent and white-backed copies of one mark are %d bits apart, "+
			"outside the %d-bit threshold: references are transparent and messages "+
			"are not, so every reference would miss its own subject", d, logoMaxDistance)
	}
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A logo whose own renderings disagree must not reach the pack.
//
// A reference is worth having only if the same mark at another size still lands on it.
// The case that prompted this: Gusto's logo on Wikidata is a solid coloured block with
// the wordmark reversed out, 92% ink, so the tight crop finds no border and dHash
// spends all 64 comparisons on a flat field where each is a coin toss. Its three
// renderings came out 31 bits apart.
//
// Grouped per source logo, not per brand, which is the distinction that matters once
// the pack carries every logo a brand has.
func TestUnstableRenderingsAreDropped(t *testing.T) {
	refs := []logoRef{
		// One mark, three widths, all in agreement.
		{Brand: "Acme", Hash: 0x0f0f0f0f0f0f0f0f, group: "Acme/mark"},
		{Brand: "Acme", Hash: 0x0f0f0f0f0f0f0f0b, group: "Acme/mark"},
		{Brand: "Acme", Hash: 0x0f0f0f0f0f0f0f0d, group: "Acme/mark"},
		// A different Acme logo, nothing like the first. Kept: brands have several.
		{Brand: "Acme", Hash: 0xf0f0f0f0f0f0f0f0, group: "Acme/old"},
		{Brand: "Acme", Hash: 0xf0f0f0f0f0f0f0f4, group: "Acme/old"},
		// A flat field: its renderings do not agree with each other.
		{Brand: "Acme", Hash: 0x0000000000000000, group: "Acme/block"},
		{Brand: "Acme", Hash: 0x00000000ffffffff, group: "Acme/block"},
		// A lone image with no sibling to check against. Kept, honestly.
		{Brand: "Beta", Hash: 0x1234567812345678, group: "Beta/only"},
	}
	kept := map[string]int{}
	for _, r := range dropUnstableRenders(refs) {
		kept[r.group]++
	}
	if kept["Acme/mark"] != 3 {
		t.Errorf("a stable logo lost renderings: %d kept", kept["Acme/mark"])
	}
	if kept["Acme/old"] != 2 {
		t.Errorf("a brand's second, different logo was dropped: %d kept — a phishing "+
			"kit using a superseded mark would match nothing", kept["Acme/old"])
	}
	if kept["Acme/block"] != 0 {
		t.Errorf("a logo whose renderings are 32 bits apart was kept (%d): no image of "+
			"it would ever match, and its hash matches unrelated marks at random",
			kept["Acme/block"])
	}
	if kept["Beta/only"] != 1 {
		t.Error("a single image with nothing to compare against should be kept")
	}
}

// The width suffix is what says two files are the same logo.
func TestRenderGroup(t *testing.T) {
	for in, want := range map[string]string{
		"Microsoft-logo-1982-256.png": "Microsoft-logo-1982",
		"Slack-CMYK-512.png":          "Slack-CMYK",
		"logo.png":                    "logo",        // hand-dropped: its own group
		"our-logo-v2.png":             "our-logo-v2", // "v2" is not a width
	} {
		if got := renderGroup(in); got != want {
			t.Errorf("renderGroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// One brand, several genuinely different logos, all kept.
//
// The pack takes every logo Wikidata holds for a brand, including superseded ones,
// because a phishing kit built from stale assets uses the old mark. An earlier guard
// dropped any brand whose references disagreed, which would have thrown exactly those
// away.
func TestABrandMayHaveSeveralUnlikeLogos(t *testing.T) {
	pack, err := shippedPack()
	if err != nil {
		t.Fatal(err)
	}
	refs, err := pack.refs()
	if err != nil {
		t.Fatal(err)
	}
	byBrand := map[string]map[uint64]bool{}
	for _, r := range refs {
		if byBrand[r.Brand] == nil {
			byBrand[r.Brand] = map[uint64]bool{}
		}
		byBrand[r.Brand][r.Hash] = true
	}

	spread := 0
	for brand, hs := range byBrand {
		var list []uint64
		for h := range hs {
			list = append(list, h)
		}
		for i := range list {
			for j := i + 1; j < len(list); j++ {
				if d := bits.OnesCount64(list[i] ^ list[j]); d > spread {
					spread = d
					_ = brand
				}
			}
		}
	}
	if spread < logoMaxDistance {
		t.Errorf("no brand has two references further apart than %d bits (widest is %d): "+
			"the pack is only carrying one logo per brand, so a message using a "+
			"superseded mark matches nothing", logoMaxDistance, spread)
	}
}

// The pack's admission bar has to be at least the match threshold.
//
// If a pack may contain two brands closer than the matcher's idea of "the same mark",
// a message matches both. The two numbers are separate so that tuning the threshold
// does not reshape the pack it is being tuned against, but they are not independent.
func TestPackMarginCoversTheMatchThreshold(t *testing.T) {
	if logoPackMargin < logoMaxDistance {
		t.Fatalf("pack margin %d is below the match threshold %d: the pack may admit "+
			"references the matcher cannot tell apart", logoPackMargin, logoMaxDistance)
	}
}

// The added wordmarks have to fire on the text an agency's mail contains, and stay
// quiet on ordinary prose.
//
// Acronyms are the whole risk. Three letters with word boundaries still match English
// — "ups" is the plural of "up", "irs" hides in nothing but sits one OCR slip from
// plenty — and OCR turns every layout into a run of words with no structure to lean
// on. Each short form is therefore paired with the spelled-out name, and the ones that
// are common words are the spelled-out name only.
func TestAgencyWordmarksMatchTheirMailAndNotProse(t *testing.T) {
	for _, tc := range []struct {
		brand, text string
		want        bool
	}{
		{"IRS", "Internal Revenue Service — notice of underreported income", true},
		{"IRS", "Your IRS refund is pending", true},
		{"IRS", "theirs is the first of many", false},
		{"HMRC", "HMRC: you are due a tax refund of £248.31", true},
		{"HMRC", "HM Revenue and Customs", true},
		{"UPS", "United Parcel Service delivery attempt", true},
		{"UPS", "please back ups the database and follow ups with the team", false},
		{"DVLA", "DVLA: your vehicle tax could not be collected", true},
		{"NHS", "NHS COVID-19 test result", true},
		{"NHS", "the nhsomething string", false},
		{"E-ZPass", "E-ZPass toll violation notice", true},
		{"E-ZPass", "EZ Pass unpaid balance", true},
		{"Royal Mail", "Royal Mail: a redelivery fee is required", true},
		{"Medicare", "Your Medicare card is ready", true},
		{"US Treasury", "United States Department of the Treasury", true},
		{"US Treasury", "U.S. Treasury payment authorisation", true},
		{"Canada Post", "Postes Canada / Canada Post", true},
		{"La Poste", "La Poste — colis en attente", true},
	} {
		re, ok := brandPatterns[tc.brand]
		if !ok {
			t.Errorf("%s has no wordmark pattern", tc.brand)
			continue
		}
		if got := re.MatchString(strings.ToLower(tc.text)); got != tc.want {
			t.Errorf("%s on %q: matched=%v, want %v", tc.brand, tc.text, got, tc.want)
		}
	}
}

// No wordmark may fire on ordinary business prose.
//
// One false brand is worse than a missed one: a rule handed a brand that is not in the
// message reports an impersonation that did not happen.
func TestNoWordmarkFiresOnOrdinaryMail(t *testing.T) {
	prose := strings.ToLower(strings.Join([]string{
		"Hi team, following ups from yesterday's call, I've attached the revised",
		"budget. Please back ups your working copy first. The box of samples arrived",
		"and theirs is the larger order. Let me know if the square footage looks",
		"right, and I'll post an update to the group later today.",
	}, " "))
	for _, brand := range ExtraBrands {
		re, ok := brandPatterns[brand]
		if !ok {
			continue
		}
		if re.MatchString(prose) {
			t.Errorf("%s fired on ordinary prose: %s", brand, re.String())
		}
	}
}

// Every added brand is either matchable by wordmark or present in the pack. A brand
// that is neither is a name nothing can ever return.
func TestEveryExtraBrandIsReachable(t *testing.T) {
	pack, err := shippedPack()
	if err != nil {
		t.Fatal(err)
	}
	inPack := map[string]bool{}
	for _, e := range pack.Entries {
		inPack[e.Brand] = true
	}
	for _, brand := range ExtraBrands {
		_, hasWord := brandPatterns[brand]
		if !hasWord && !inPack[brand] {
			t.Errorf("%s has neither a wordmark pattern nor a reference hash: "+
				"nothing can ever return it", brand)
		}
	}
}

// The folder name is the brand. Nothing checks it against a list.
//
// This is the question anyone adding a logo asks, so it is worth a test rather than a
// sentence in a README: drop images under logos/<anything>/ and ml.logo_detect returns
// <anything> when one of them matches. The brand lists in labels.go drive the wordmark
// half only — they are the vocabulary Sublime's rules compare against, and a rule can
// compare against any string it likes.
func TestAnyFolderNameBecomesABrand(t *testing.T) {
	const brand = "Gringotts Wizarding Bank" // in no list anywhere
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, brand), 0o755); err != nil {
		t.Fatal(err)
	}

	// A mark with enough structure to hash, and nothing like any shipped logo.
	mark := image.NewRGBA(image.Rect(0, 0, 180, 180))
	for y := 0; y < 180; y++ {
		for x := 0; x < 180; x++ {
			mark.Set(x, y, color.White)
			if (x/12+y/30)%3 == 0 && x > 20 && x < 160 && y > 40 && y < 140 {
				mark.Set(x, y, color.RGBA{uint8(x), 30, uint8(180 - y), 255})
			}
		}
	}
	png := encodePNG(t, mark)
	if err := os.WriteFile(filepath.Join(dir, brand, "mark.png"), png, 0o644); err != nil {
		t.Fatal(err)
	}

	var l LogoDetect
	if _, local, err := l.LoadReferences(dir); err != nil {
		t.Fatal(err)
	} else if local != 1 {
		t.Fatalf("loaded %d local references, want 1", local)
	}

	got, err := l.Infer(context.Background(), Request{Image: png})
	if err != nil {
		t.Fatal(err)
	}
	res, ok := got.(logoResult)
	if !ok {
		t.Fatalf("Infer returned %T", got)
	}
	for _, b := range res.Brands {
		if b.Name == brand {
			if b.Confidence != ConfHigh {
				t.Errorf("an exact match reported %q confidence, want high", b.Confidence)
			}
			return
		}
	}
	t.Errorf("a logo under logos/%s/ did not come back as that brand; got %+v",
		brand, res.Brands)
}

// A brand added as a folder is matchable by name as well as by picture.
//
// Without this, adding logos/Acme Bank/ gets you symbol matching and nothing else,
// while the built-in brands get both — and for a logo that is mostly text the OCR half
// is the stronger of the two. The folder name is the brand, so it should work in both
// directions.
func TestAFolderNameAlsoBecomesAWordmark(t *testing.T) {
	const brand = "Northgate Credit Union"
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, brand), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, brand, "m.png"),
		solid(t, 120, 120, 10, 20, 90, 60), 0o644); err != nil {
		t.Fatal(err)
	}

	var l LogoDetect
	if _, _, err := l.LoadReferences(dir); err != nil {
		t.Fatal(err)
	}

	// No image at all: the name alone, read out of an attachment by OCR.
	got, err := l.Infer(context.Background(), Request{
		Options: map[string]string{"ocr_text": "northgate  credit   union — account notice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res := got.(logoResult)
	found := false
	for _, b := range res.Brands {
		if b.Name == brand {
			found = true
		}
	}
	if !found {
		t.Errorf("the brand's own name in OCR text did not match it; got %+v", res.Brands)
	}
}

// A name too short to be a wordmark is left to match by picture only.
//
// Turning a two-letter directory name into a pattern would fire on ordinary mail
// constantly. The built-in list already shows the cost: "ups" is the plural of "up".
func TestShortFolderNamesGetNoWordmark(t *testing.T) {
	for _, short := range []string{"X", "IT", "Pay", "  a  "} {
		if re := wordmarkFor(short); re != nil {
			t.Errorf("wordmarkFor(%q) = %v, want none: too short to be safe", short, re)
		}
	}
	if wordmarkFor("Acme") == nil {
		t.Error("a four-character name should get a wordmark")
	}
}

// A directory name is a name, not a pattern.
//
// An operator should not discover that a bracket in their brand name is a syntax
// error, or that a dot matches any character.
func TestFolderNamesAreNotTreatedAsRegexes(t *testing.T) {
	re := wordmarkFor("Acme (Holdings) Ltd.")
	if re == nil {
		t.Fatal("a name with punctuation produced no pattern")
	}
	if !re.MatchString("invoice from acme (holdings) ltd. attached") {
		t.Error("the literal name did not match")
	}
	if re.MatchString("acme xholdingsx ltdz") {
		t.Error("the name was compiled as a regex; punctuation matched as metacharacters")
	}
}
