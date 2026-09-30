// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func encode(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decode(t *testing.T, raw []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// A short message in a tall viewport is mostly empty page, and the empty part goes.
func TestTrimRemovesTheBlankPageBelowAShortMessage(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 200, 1000))
	for y := 0; y < 1000; y++ {
		for x := 0; x < 200; x++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	// Two lines of "text" near the top.
	for y := 10; y < 40; y++ {
		img.Set(20, y, color.RGBA{0, 0, 0, 255})
	}

	got := decode(t, trimBlankBottom(encode(t, img)))
	if got.Bounds().Dy() >= 1000 {
		t.Fatalf("height %d, want the blank page trimmed away", got.Bounds().Dy())
	}
	if got.Bounds().Dy() < 40 {
		t.Errorf("height %d, want the content kept", got.Bounds().Dy())
	}
	if got.Bounds().Dx() != 200 {
		t.Errorf("width %d, want it unchanged", got.Bounds().Dx())
	}
}

// Content reaching the bottom is left alone: trimming there would cut the message.
func TestTrimLeavesAFullPageAlone(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 100, 300))
	for y := 0; y < 300; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	img.Set(50, 299, color.RGBA{0, 0, 0, 255})

	raw := encode(t, img)
	if got := decode(t, trimBlankBottom(raw)); got.Bounds().Dy() != 300 {
		t.Errorf("height %d, want 300 — the content runs to the bottom", got.Bounds().Dy())
	}
}

// The background is taken from the image, not assumed to be white: a message that
// sets its own page colour must trim the same way.
func TestTrimHonoursANonWhiteBackground(t *testing.T) {
	bg := color.RGBA{18, 18, 30, 255}
	img := image.NewRGBA(image.Rect(0, 0, 100, 800))
	for y := 0; y < 800; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, bg)
		}
	}
	for y := 5; y < 25; y++ {
		img.Set(10, y, color.RGBA{255, 255, 255, 255})
	}

	got := decode(t, trimBlankBottom(encode(t, img)))
	if got.Bounds().Dy() >= 800 {
		t.Errorf("height %d, want trimming to work on a dark page too", got.Bounds().Dy())
	}
}

// Anything that is not a decodable image comes back untouched rather than lost.
func TestTrimPassesThroughWhatItCannotDecode(t *testing.T) {
	raw := []byte("not a png")
	if got := trimBlankBottom(raw); !bytes.Equal(got, raw) {
		t.Error("undecodable input must be returned unchanged")
	}
}
