// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The shipped reference pack: perceptual hashes, and no logos.
//
// # Why a hash and not the image
//
// The symbol half of ml.logo_detect needs to know what other companies' marks look
// like. Shipping fifty trademarks inside an AGPL repository is a distribution question
// — separate from the use question, which nominative use answers comfortably — and it
// is not one to settle on an operator's behalf.
//
// A perceptual hash sidesteps it. Sixty-four bits of "is this cell brighter than the
// one to its right" is a fingerprint, not a copy: nothing can be reconstructed from it,
// it has no expressive content, and its only function is to recognise the mark it came
// from. That is the same shape as any other content-identification hash.
//
// Two things fall out of it that are worth having anyway:
//
//   - **Reproducibility.** The previous approach downloaded each logo at deploy time
//     from a favicon service. Two deployments of the same version would therefore
//     detect different things, depending on what that service returned that week, and
//     nobody could reproduce a missed detection. A checked-in pack is the same
//     everywhere, and a change to it is a diff somebody reviews.
//   - **Nothing lands on disk.** The operator ends up with no trademark images at all,
//     which is the outcome the whole exercise was after.
//
// # Where the shipped hashes come from, and why they have to
//
// The brands' own logos: located through Wikidata's logo property (P154) and rendered
// from Wikimedia Commons at three widths. The pack records that, so it can be
// regenerated and audited.
//
// It has to be the real logo, which took two failures to establish.
//
// The first pack was built from favicons. A favicon is usually a letter in a rounded
// box, and at eight by nine pixels they are all the same picture: 37 of 47 brands
// landed inside the match threshold of each other, and the matcher would have reported
// a confident wrong brand for almost any mark.
//
// The second was built from Simple Icons, a CC0 icon set. Internally it was clean —
// no two brands collided. Measured against the real logos it stood for, it matched one
// brand in thirty-one, and X's real logo was closer to Microsoft's icon than to X's
// own. An icon set is a stylised single-colour glyph; it is not what a company puts in
// its email.
//
// The lesson is about the measurement rather than the data. Reference-against-reference
// says nothing, and the icon pack passed it comfortably. Only
// reference-against-subject does, which is what TestShippedReferencesSurviveDistortion
// and the threshold table in logo.go now rest on.

//go:embed logohashes.json
var shippedPackJSON []byte

// LogoPack is the on-disk and in-repo format. Hashes, and the provenance to regenerate
// them. Deliberately not an image container.
type LogoPack struct {
	// Note is for a human reading the file, which is the only way anyone will ever
	// read it.
	Note string `json:"note"`

	// Source says where the marks came from, so a regeneration can be compared
	// against the same input rather than a different one.
	Source string `json:"source"`

	Entries []LogoPackEntry `json:"entries"`
}

// LogoPackEntry is one mark at one scale.
type LogoPackEntry struct {
	// Brand is spelled exactly as the rule corpus spells it, because that string is
	// what a rule compares against.
	Brand string `json:"brand"`

	// Hash is the 64-bit dHash, hex, of the tight-cropped mark.
	Hash string `json:"hash"`

	// Scale is the pixel size the mark was rasterised at. Several per brand is
	// wanted: a logo arrives in a message at whatever size the sender chose, and
	// hashing a few sizes covers the resampling that causes.
	Scale int `json:"scale,omitempty"`
}

// refs converts a pack to the matcher's form, dropping anything unparseable rather
// than failing the whole pack for one bad line.
func (p LogoPack) refs() ([]logoRef, error) {
	var out []logoRef
	for i, e := range p.Entries {
		if e.Brand == "" {
			return nil, fmt.Errorf("entry %d has no brand", i)
		}
		h, err := strconv.ParseUint(strings.TrimPrefix(e.Hash, "0x"), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a 64-bit hex hash", e.Brand, e.Hash)
		}
		out = append(out, logoRef{Brand: e.Brand, Hash: h})
	}
	return out, nil
}

// shippedPack is the pack compiled into the binary.
func shippedPack() (LogoPack, error) {
	var p LogoPack
	if err := json.Unmarshal(shippedPackJSON, &p); err != nil {
		return p, fmt.Errorf("the shipped logo pack is not valid JSON: %w", err)
	}
	return p, nil
}

// LoadReferences assembles the matcher's references: the shipped hashes, plus every
// image an operator has put in dir.
//
// The operator's own always wins on count — both are just references and more of them
// is strictly better — and their images are hashed here, in their process, and are
// never sent anywhere. That is the whole upload story: a directory is the interface,
// because a logo is a file and a directory of files needs no API to be useful.
//
// A brand directory that exists locally replaces the shipped entries for that brand
// rather than adding to them. An operator who has the real asset for Chase has a better
// reference than a CC0 monochrome approximation, and mixing the two would let the worse
// one keep matching.
func (l *LogoDetect) LoadReferences(dir string) (shipped, local int, err error) {
	pack, err := shippedPack()
	if err != nil {
		return 0, 0, err
	}
	base, err := pack.refs()
	if err != nil {
		return 0, 0, err
	}

	own, err := hashDirectory(dir)
	if err != nil {
		return 0, 0, err
	}

	overridden := map[string]bool{}
	for _, r := range own {
		overridden[r.Brand] = true
	}
	refs := make([]logoRef, 0, len(base)+len(own))
	for _, r := range base {
		if !overridden[r.Brand] {
			refs = append(refs, r)
		}
	}
	refs = append(refs, own...)

	// A brand somebody added should be findable by its name as well as its picture.
	// Only for names the built-in list does not already cover, so an operator adding
	// a better image for Chase does not also get a looser pattern for it.
	words := map[string]*regexp.Regexp{}
	var derived []string
	for brand := range overridden {
		if _, builtin := brandPatterns[brand]; builtin {
			continue
		}
		if re := wordmarkFor(brand); re != nil {
			words[brand] = re
			derived = append(derived, brand)
		}
	}
	sort.Strings(derived)

	l.mu.Lock()
	l.refs = refs
	l.localWords = words
	l.mu.Unlock()

	if len(derived) > 0 {
		log.Printf("lazaret-ml: also matching these by name in OCR text: %s",
			strings.Join(derived, ", "))
	}
	for _, w := range collidingBrands(refs) {
		log.Printf("lazaret-ml: logo references for %s and %s are %d bits apart, inside the "+
			"%d-bit match threshold — a mark matching one will report both. Whichever is "+
			"wrong, remove it.", w.a, w.b, w.dist, logoMaxDistance)
	}
	return len(refs) - len(own), len(own), nil
}

// renderGroup names the source logo a file is a rendering of.
//
// The convention is <name>-<width>.png, which is what -hash-logos produces and what
// the fetch of the shipped pack writes: "Microsoft-logo-1982-256.png" is the 1982
// wordmark at 256 pixels. Strip the width and you have the logo.
//
// A file that does not follow it is its own group, which is right for an image
// somebody dropped in by hand: with one rendering there is nothing to check it
// against, and inventing a verdict would be worse than admitting that.
func renderGroup(name string) string {
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	if i := strings.LastIndexByte(stem, '-'); i > 0 {
		if _, err := strconv.Atoi(stem[i+1:]); err == nil {
			return stem[:i]
		}
	}
	return stem
}

// dropUnstableRenders removes logos whose own renderings disagree.
//
// A reference is worth having only if the same mark at another size still lands on it.
// When one logo rendered at three widths spreads wider than the match threshold, the
// hash is not describing the mark, and the usual cause is an image with nothing to
// crop to: Gusto's logo on Wikidata is a solid coloured block with the wordmark
// reversed out, 92% ink, so the tight crop finds no border and dHash spends all 64
// comparisons on a flat field where each is a coin toss. Its three renders came out 31
// bits apart.
//
// Per source logo, not per brand. A brand has several logos and they are supposed to
// differ — Microsoft's 1980 wordmark and its 2012 four squares are both correct
// references and 39 bits apart, and X's current mark and the Twitter bird it replaced
// are nothing like each other. An earlier version of this check grouped by brand and
// would have thrown away exactly the references worth having, since a phishing kit
// built from stale assets uses the old mark.
func dropUnstableRenders(refs []logoRef) []logoRef {
	byGroup := map[string][]uint64{}
	for _, r := range refs {
		byGroup[r.group] = append(byGroup[r.group], r.Hash)
	}
	bad := map[string]int{}
	for g, hs := range byGroup {
		if len(hs) < 2 {
			continue // one rendering: nothing to check it against
		}
		worst := 0
		for i := range hs {
			for j := i + 1; j < len(hs); j++ {
				if d := bits.OnesCount64(hs[i] ^ hs[j]); d > worst {
					worst = d
				}
			}
		}
		if worst >= logoPackMargin {
			bad[g] = worst
		}
	}
	if len(bad) == 0 {
		return refs
	}
	names := make([]string, 0, len(bad))
	for g, d := range bad {
		names = append(names, fmt.Sprintf("%s (%d bits)", g, d))
	}
	sort.Strings(names)
	out := refs[:0:0]
	for _, r := range refs {
		if _, skip := bad[r.group]; !skip {
			out = append(out, r)
		}
	}
	fmt.Fprintf(os.Stderr, "lazaret-ml: dropped %d logo(s) whose own renderings disagree by "+
		"more than %d bits, so no image of them would match: %s\n",
		len(bad), logoPackMargin, strings.Join(names, ", "))
	return out
}

// A brand has several logos, and they are supposed to differ.
//
// There used to be a check here that dropped any brand whose references sat further
// apart than the match threshold. It was wrong as soon as the pack started taking
// every logo Wikidata holds rather than one: Microsoft's 1980 wordmark and its 2012
// four squares are both Microsoft and are nothing like each other, and X's current
// mark and the Twitter bird it replaced are twenty years apart in design. Those are
// exactly the references worth having, because a phishing kit built from stale assets
// uses the old one.
//
// What that check was really after — a hash computed over a flat field, which matches
// at random — is now tested per image by stableHash, where it belongs.

// dropCrossBrandClashes removes references that sit inside the match threshold of a
// reference belonging to a different brand.
//
// Both sides go, not the prettier one. Neither can be trusted: a mark landing between
// them reports both brands, and the matcher has no way to prefer one. Which is dropped
// cannot be decided from the hashes alone, and guessing would leave a reference that
// is wrong about half the time.
//
// This bites once the pack takes every logo a brand has rather than one. The marks it
// removes are almost always wordmark lockups — Block's black wordmark sat 13 bits from
// Slack's, because dark text on white is dark text on white at nine by eight pixels.
// Losing them costs little, since a wordmark is what the OCR half reads anyway; what
// has to survive is the symbol, and symbols are what stay far apart.
func dropCrossBrandClashes(refs []logoRef) []logoRef {
	drop := make([]bool, len(refs))
	pairs := map[[2]string]int{}
	for i := range refs {
		for j := i + 1; j < len(refs); j++ {
			if refs[i].Brand == refs[j].Brand {
				continue
			}
			d := bits.OnesCount64(refs[i].Hash ^ refs[j].Hash)
			if d >= logoPackMargin {
				continue
			}
			drop[i], drop[j] = true, true
			key := [2]string{refs[i].Brand, refs[j].Brand}
			if key[0] > key[1] {
				key[0], key[1] = key[1], key[0]
			}
			if cur, ok := pairs[key]; !ok || d < cur {
				pairs[key] = d
			}
		}
	}
	if len(pairs) == 0 {
		return refs
	}
	msgs := make([]string, 0, len(pairs))
	for k, d := range pairs {
		msgs = append(msgs, fmt.Sprintf("%s/%s (%d bits)", k[0], k[1], d))
	}
	sort.Strings(msgs)
	out := refs[:0:0]
	for i, r := range refs {
		if !drop[i] {
			out = append(out, r)
		}
	}
	fmt.Fprintf(os.Stderr, "lazaret-ml: dropped %d reference(s) that different brands share "+
		"within %d bits, so neither could be trusted: %s\n",
		len(refs)-len(out), logoPackMargin, strings.Join(msgs, ", "))
	return out
}

type brandClash struct {
	a, b string
	dist int
}

// collidingBrands finds reference pairs close enough to be confused for each other.
//
// Worth checking every start rather than only when the shipped pack changes, because
// the references an operator adds are the ones most likely to do this. The first
// version of the shipped pack was built from favicons, and a favicon is usually a
// letter in a rounded box: 37 of 47 brands collided, and the matcher would have
// reported a confident wrong brand for nearly any mark. Nothing in the logs said so.
//
// Reported once per brand pair, not once per reference pair, or a bad pack prints
// thousands of lines.
func collidingBrands(refs []logoRef) []brandClash {
	seen := map[[2]string]bool{}
	var out []brandClash
	for i := range refs {
		for j := i + 1; j < len(refs); j++ {
			if refs[i].Brand == refs[j].Brand {
				continue
			}
			d := bits.OnesCount64(refs[i].Hash ^ refs[j].Hash)
			if d >= logoMaxDistance {
				continue
			}
			key := [2]string{refs[i].Brand, refs[j].Brand}
			if key[0] > key[1] {
				key[0], key[1] = key[1], key[0]
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, brandClash{key[0], key[1], d})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dist < out[j].dist })
	return out
}

// hashDirectory hashes every image under dir, which is laid out one directory per
// brand, named exactly as the rule corpus spells the brand.
//
// Missing is not an error. Most deployments have no local pack and that is the
// expected state, not a misconfiguration.
func hashDirectory(dir string) ([]logoRef, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var refs []logoRef
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		brand := e.Name()
		files, err := os.ReadDir(filepath.Join(dir, brand))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() || !isImageName(f.Name()) {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, brand, f.Name()))
			if err != nil {
				return nil, err
			}
			h, err := perceptualHash(raw)
			if err != nil {
				// One unreadable file must not cost the operator the rest of their
				// pack: an images directory collects odd things.
				continue
			}
			refs = append(refs, logoRef{Brand: brand, Hash: h, group: brand + "/" + renderGroup(f.Name())})
		}
	}
	return refs, nil
}

func isImageName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif":
		return true
	}
	return false
}

// WritePack hashes a directory of images and writes the pack to w.
//
// This is how the shipped pack was built and how anyone regenerates or extends it:
// point it at images, get hashes, keep the images to yourself. It is also how a
// contribution works — nobody has to send a trademark to add a brand.
func WritePack(dir, source string, w io.Writer) (int, error) {
	refs, err := hashDirectory(dir)
	if err != nil {
		return 0, err
	}
	if len(refs) == 0 {
		return 0, fmt.Errorf("no images under %s (expected %s/<Brand>/*.png)", dir, dir)
	}
	refs = dropUnstableRenders(refs)
	refs = dropCrossBrandClashes(refs)
	if len(refs) == 0 {
		return 0, fmt.Errorf("no usable references under %s", dir)
	}
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Brand != refs[j].Brand {
			return refs[i].Brand < refs[j].Brand
		}
		return refs[i].Hash < refs[j].Hash
	})

	pack := LogoPack{
		Note: "Perceptual hashes of brand marks. No images: a 64-bit dHash is a " +
			"fingerprint, not a copy. Regenerate with: lazaret-ml -hash-logos <dir>",
		Source: source,
	}
	for _, r := range refs {
		pack.Entries = append(pack.Entries, LogoPackEntry{
			Brand: r.Brand,
			Hash:  fmt.Sprintf("%016x", r.Hash),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(pack); err != nil {
		return 0, err
	}
	return len(refs), nil
}
