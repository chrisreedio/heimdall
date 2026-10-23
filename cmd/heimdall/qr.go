// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"strings"

	"rsc.io/qr"
)

// quietZone is the blank border QR readers need, in modules.
const quietZone = 2

// writeQR draws text as a QR code with Unicode half blocks: each character
// cell holds two module rows. Colours are explicit ANSI black on white, so
// it scans the same on dark and light terminal themes.
func writeQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	dark := func(x, y int) bool { return code.Black(x-quietZone, y-quietZone) }
	n := code.Size + 2*quietZone
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.WriteString("  ")
		for x := 0; x < n; x++ {
			top, bottom := dark(x, y), y+1 < n && dark(x, y+1)
			// ▀ draws the top half in the foreground colour, the bottom in the background.
			fg, bg := "37", "47" // white
			if top {
				fg = "30"
			}
			if bottom {
				bg = "40"
			}
			b.WriteString("\x1b[" + fg + ";" + bg + "m▀")
		}
		b.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
