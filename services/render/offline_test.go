// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"image"
	_ "image/png"
	"os/exec"
	"testing"
	"time"
)

// A screenshot must not load anything over the network.
//
// This is the property the whole feature rests on. A message body's remote images are
// tracking pixels: fetching one tells the sender their phishing was delivered, that a
// human opened it, and when — from the security team's own address space. It is the
// single worst thing a mail analysis platform can leak, and it happens by default
// unless something stops it.
//
// It used to be stopped by the container's networking: the renderer sat on a network
// marked internal and simply could not reach anything. Enabling link analysis moves it
// to a network with egress, so the guarantee had to stop depending on which compose
// file was used and become a property of how the browser is launched.
//
// Skipped without chromium, because most machines running the unit tests do not have
// one. Run it where it counts:  go test ./services/render -run Offline
func TestScreenshotLoadsNothingRemote(t *testing.T) {
	if _, err := exec.LookPath("chromium"); err != nil {
		if _, err := exec.LookPath("chromium-browser"); err != nil {
			t.Skip("no chromium on PATH")
		}
	}

	r := &Renderer{Width: 300, Height: 120, Timeout: 30 * time.Second}
	ctx := context.Background()

	// A page whose only content is a remote image with known, strongly saturated
	// colours. If the fetch succeeds those colours appear; if it is blocked, all
	// that renders is the broken-image placeholder, which is grey.
	const remote = `<html><body style="margin:0;background:#fff">` +
		`<img src="https://www.google.com/images/branding/googlelogo/2x/` +
		`googlelogo_color_272x92dp.png" width="272" height="92"></body></html>`

	png, err := r.Screenshot(ctx, []byte(remote))
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if got := saturatedColours(t, png); got > 40 {
		t.Errorf("%d saturated colours in the screenshot: the remote image loaded, "+
			"which means a tracking pixel in a real message would have fired", got)
	}
}

// saturatedColours counts distinct strongly-coloured pixels, which a placeholder has
// almost none of and a loaded colour image has many of.
func saturatedColours(t *testing.T, raw []byte) int {
	t.Helper()
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decoding the screenshot: %v", err)
	}
	seen := map[[3]uint32]bool{}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			c := [3]uint32{r >> 8, g >> 8, bl >> 8}
			hi, lo := max3(c), min3(c)
			if hi-lo > 90 {
				seen[c] = true
			}
		}
	}
	return len(seen)
}

func max3(c [3]uint32) uint32 {
	m := c[0]
	for _, v := range c[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func min3(c [3]uint32) uint32 {
	m := c[0]
	for _, v := range c[1:] {
		if v < m {
			m = v
		}
	}
	return m
}
