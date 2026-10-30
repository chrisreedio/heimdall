// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"strconv"
	"strings"
)

// Branding images (branding.go). Uploads are PNGs only: decoded with
// image/png (anything that doesn't decode is refused), checked for size,
// scaled with a box filter and encoded again, so what's stored and served
// is pixels the hub wrote itself, with no metadata or trailing bytes.

const (
	maxLogoSize  = 512 << 10
	maxIconSize  = 1 << 20
	maxImageSide = 4096 // a cap on the decoded size, whatever the file size
	minIconSide  = 512
	maxLogoSide  = 512 // logos are scaled down to fit this
)

// iconSizes are the app icon's sizes: the manifest's 512 and 192, iOS's
// 180 (apple-touch-icon) and the favicon's 32.
var iconSizes = []int{512, 192, 180, 32}

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// decodePNG decodes an upload, refusing anything that isn't a PNG of at
// most maxBytes and maxImageSide pixels a side.
func decodePNG(b []byte, maxBytes int) (image.Image, error) {
	if len(b) == 0 {
		return nil, errors.New("choose a PNG file")
	}
	if len(b) > maxBytes {
		return nil, fmt.Errorf("that file is %s; the limit is %s", sizeText(len(b)), sizeText(maxBytes))
	}
	if !bytes.HasPrefix(b, pngMagic) {
		return nil, errors.New("that isn't a PNG file; only PNG is accepted")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, errors.New("that PNG file couldn't be read")
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxImageSide || cfg.Height > maxImageSide {
		return nil, fmt.Errorf("that image is %d × %d; the most is %d pixels a side", cfg.Width, cfg.Height, maxImageSide)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, errors.New("that PNG file couldn't be read")
	}
	return img, nil
}

// logoPNG validates a logo upload and returns it re-encoded, scaled down
// to fit maxLogoSide.
func logoPNG(b []byte) ([]byte, error) {
	img, err := decodePNG(b, maxLogoSize)
	if err != nil {
		return nil, err
	}
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	if f := float64(maxLogoSide) / float64(max(w, h)); f < 1 {
		w, h = max(1, int(math.Round(float64(w)*f))), max(1, int(math.Round(float64(h)*f)))
	}
	return encodePNG(scaleImage(img, w, h))
}

// iconPNGs validates an app icon upload (square, at least minIconSide) and
// returns it at each of iconSizes, by size. The 180 px one is flattened
// onto white, as iOS draws transparency as black.
func iconPNGs(b []byte) (map[int][]byte, error) {
	img, err := decodePNG(b, maxIconSize)
	if err != nil {
		return nil, err
	}
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	if w != h {
		return nil, fmt.Errorf("the app icon must be square; that image is %d × %d", w, h)
	}
	if w < minIconSide {
		return nil, fmt.Errorf("the app icon must be at least %d × %d; that image is %d × %d", minIconSide, minIconSide, w, h)
	}
	out := map[int][]byte{}
	for _, n := range iconSizes {
		m := scaleImage(img, n, n)
		if n == 180 {
			flat := image.NewRGBA(m.Bounds())
			draw.Draw(flat, flat.Bounds(), image.White, image.Point{}, draw.Src)
			draw.Draw(flat, flat.Bounds(), m, image.Point{}, draw.Over)
			m = flat
		}
		if out[n], err = encodePNG(m); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// scaleImage resizes img to w × h with a box filter: each output pixel is
// the area-weighted average of the source pixels under it, in
// premultiplied alpha so transparent pixels don't darken the edges. Good
// for shrinking, which is all branding does; enlarging repeats pixels.
func scaleImage(img image.Image, w, h int) *image.RGBA {
	src := image.NewRGBA(image.Rect(0, 0, img.Bounds().Dx(), img.Bounds().Dy()))
	draw.Draw(src, src.Bounds(), img, img.Bounds().Min, draw.Src)
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	if sw == w && sh == h {
		return src
	}
	// Horizontal pass into a float buffer (sh rows of w pixels), then
	// vertical into the result.
	tmp := make([]float64, w*sh*4)
	xs := boxWeights(sw, w)
	for y := range sh {
		row := src.Pix[y*src.Stride:]
		for x, ws := range xs {
			var acc [4]float64
			for _, k := range ws {
				p := row[k.i*4:]
				for c := range 4 {
					acc[c] += float64(p[c]) * k.w
				}
			}
			copy(tmp[(y*w+x)*4:], acc[:])
		}
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	ys := boxWeights(sh, h)
	for y, ws := range ys {
		for x := range w {
			var acc [4]float64
			for _, k := range ws {
				p := tmp[(k.i*w+x)*4:]
				for c := range 4 {
					acc[c] += p[c] * k.w
				}
			}
			o := dst.Pix[y*dst.Stride+x*4:]
			for c := range 4 {
				o[c] = uint8(math.Min(255, math.Round(acc[c])))
			}
			// Premultiplied: no channel may exceed alpha after rounding.
			o[0], o[1], o[2] = min(o[0], o[3]), min(o[1], o[3]), min(o[2], o[3])
		}
	}
	return dst
}

type boxWeight struct {
	i int
	w float64
}

// boxWeights maps each of n output pixels to the source pixels (of src)
// it covers, with the fraction of each it covers; the weights sum to 1.
func boxWeights(src, n int) [][]boxWeight {
	out := make([][]boxWeight, n)
	scale := float64(src) / float64(n)
	for o := range n {
		lo, hi := float64(o)*scale, float64(o+1)*scale
		if scale < 1 { // enlarging: the nearest source pixel
			out[o] = []boxWeight{{i: min(src-1, int(lo+scale/2)), w: 1}}
			continue
		}
		for i := int(lo); i < src && float64(i) < hi; i++ {
			cover := math.Min(hi, float64(i+1)) - math.Max(lo, float64(i))
			if cover > 1e-9 {
				out[o] = append(out[o], boxWeight{i: i, w: cover / scale})
			}
		}
	}
	return out
}

// sizeText is a byte count for messages: "1.2 MB", "300 KB".
func sizeText(n int) string {
	if n >= 1<<20 {
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	}
	return strconv.Itoa((n+1023)/1024) + " KB"
}

// ── Accent color ───────────────────────────────────────────────────────────

// Where the accent is used (app.css): the background of buttons and the
// patch wizard's current step, under white text (--accent-text), and the
// edge of AI cards and hand-off notes, in both themes. So a custom accent
// must carry white text at 4.5:1 (WCAG AA for text) and stand out 3:1
// (AA for non-text) against the surfaces of both themes. The light
// theme's surface is white, so the first check covers it.
const (
	accentText  = "#ffffff"
	darkSurface = "#1a1e24" // app.css --surface, dark theme
)

// parseHex reads "#rrggbb" or "#rgb" (case-insensitive) as "#rrggbb".
func parseHex(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "#") {
		s = "#" + s
	}
	if len(s) == 4 {
		s = "#" + strings.Repeat(s[1:2], 2) + strings.Repeat(s[2:3], 2) + strings.Repeat(s[3:4], 2)
	}
	if len(s) != 7 {
		return "", false
	}
	if _, err := strconv.ParseUint(s[1:], 16, 32); err != nil {
		return "", false
	}
	return s, true
}

func hexColor(s string) color.RGBA {
	v, _ := strconv.ParseUint(s[1:], 16, 32)
	return color.RGBA{uint8(v >> 16), uint8(v >> 8), uint8(v), 255}
}

// luminance is WCAG 2's relative luminance of an sRGB color.
func luminance(c color.RGBA) float64 {
	lin := func(v uint8) float64 {
		f := float64(v) / 255
		if f <= 0.04045 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.R) + 0.7152*lin(c.G) + 0.0722*lin(c.B)
}

// contrast is WCAG 2's contrast ratio of two "#rrggbb" colors (1 to 21).
func contrast(a, b string) float64 {
	la, lb := luminance(hexColor(a)), luminance(hexColor(b))
	return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
}

// checkAccent validates a custom accent color, returning it as "#rrggbb"
// or a message saying what's wrong with it.
func checkAccent(s string) (string, error) {
	hex, ok := parseHex(s)
	if !ok {
		return "", errors.New("enter the accent as a hex color, like #2f6db5")
	}
	ratio := func(r float64) string { return strconv.FormatFloat(math.Floor(r*10)/10, 'f', 1, 64) + ":1" }
	if r := contrast(hex, accentText); r < 4.5 {
		return "", fmt.Errorf("%s is too light: white button text on it is %s, and needs 4.5:1. Try a darker shade", hex, ratio(r))
	}
	if r := contrast(hex, darkSurface); r < 3 {
		return "", fmt.Errorf("%s is too dark for the dark theme: %s against the page, and needs 3:1. Try a lighter shade", hex, ratio(r))
	}
	return hex, nil
}
