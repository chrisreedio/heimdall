// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestQRRenderingScans rebuilds the image from writeQR's ANSI output, so a
// real decoder can confirm what the terminal shows is scannable. It writes
// the PNG only when HEIMDALL_QR_PNG is set (decode it with zbarimg).
func TestQRRenderingScans(t *testing.T) {
	t.Parallel()
	out := os.Getenv("HEIMDALL_QR_PNG")
	if out == "" {
		t.Skip("set HEIMDALL_QR_PNG=/path.png to export the rendering")
	}
	var buf bytes.Buffer
	if err := writeQR(&buf, os.Getenv("HEIMDALL_QR_TEXT")); err != nil {
		t.Fatal(err)
	}
	cell := regexp.MustCompile(`\x1b\[(3[07]);(4[07])m▀`)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	const scale = 8
	w := len(cell.FindAllString(lines[0], -1))
	img := image.NewGray(image.Rect(0, 0, w*scale, len(lines)*2*scale))
	for row, line := range lines {
		for col, m := range cell.FindAllStringSubmatch(line, -1) {
			for half, code := range []string{m[1], m[2]} {
				v := uint8(255)
				if code == "30" || code == "40" {
					v = 0
				}
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						img.SetGray(col*scale+dx, (row*2+half)*scale+dy, color.Gray{v})
					}
				}
			}
		}
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}
