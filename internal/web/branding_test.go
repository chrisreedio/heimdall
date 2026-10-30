// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// testPNG is a w × h PNG filled with c.
func testPNG(t *testing.T, w, h int, c color.Color) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodePNGRejects(t *testing.T) {
	t.Parallel()
	good := testPNG(t, 8, 8, color.White)
	for name, b := range map[string][]byte{
		"empty":     nil,
		"jpeg":      []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00"),
		"svg":       []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"truncated": good[:len(good)/2],
		"corrupt":   append(append([]byte{}, good[:40]...), bytes.Repeat([]byte{0xAA}, 40)...),
		"too big":   append(append([]byte{}, pngMagic...), make([]byte, maxLogoSize)...),
		"too wide":  testPNG(t, maxImageSide+1, 1, color.White),
	} {
		if _, err := decodePNG(b, maxLogoSize); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := decodePNG(good, maxLogoSize); err != nil {
		t.Errorf("good PNG: %v", err)
	}
}

// Re-encoding keeps only the pixels: text chunks and bytes after IEND go.
func TestLogoReencoded(t *testing.T) {
	t.Parallel()
	b := testPNG(t, 40, 20, color.NRGBA{200, 10, 10, 255})
	// A text chunk after IHDR (the 8-byte magic and 25-byte IHDR chunk),
	// and junk after IEND.
	chunk := pngChunk("tEXt", []byte("Comment\x00<script>alert(1)</script>"))
	b = append(append(append([]byte{}, b[:33]...), chunk...), b[33:]...)
	b = append(b, []byte("TRAILING-JUNK")...)
	if _, err := png.Decode(bytes.NewReader(b)); err != nil {
		t.Fatalf("the crafted input should decode: %v", err)
	}
	out, err := logoPNG(b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("script")) || bytes.Contains(out, []byte("TRAILING")) || bytes.Contains(out, []byte("tEXt")) {
		t.Error("re-encoded logo kept more than pixels")
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil || img.Bounds().Dx() != 40 || img.Bounds().Dy() != 20 {
		t.Fatalf("logo: %v %v", img.Bounds(), err)
	}
	// Big logos are scaled to fit maxLogoSide, keeping their shape.
	out, err = logoPNG(testPNG(t, 2000, 500, color.White))
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _ := png.DecodeConfig(bytes.NewReader(out)); cfg.Width != 512 || cfg.Height != 128 {
		t.Errorf("scaled logo: %d × %d", cfg.Width, cfg.Height)
	}
}

func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	n := len(data)
	b.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	b.WriteString(typ)
	b.Write(data)
	crc := crc32.ChecksumIEEE(append([]byte(typ), data...))
	b.Write([]byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)})
	return b.Bytes()
}

func TestIconSizes(t *testing.T) {
	t.Parallel()
	icons, err := iconPNGs(testPNG(t, 600, 600, color.NRGBA{0, 0, 255, 0})) // fully transparent
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range iconSizes {
		img, err := png.Decode(bytes.NewReader(icons[n]))
		if err != nil || img.Bounds().Dx() != n || img.Bounds().Dy() != n {
			t.Errorf("%d px: %v %v", n, img.Bounds(), err)
			continue
		}
		_, _, _, a := img.At(n/2, n/2).RGBA()
		if n == 180 && a != 0xffff {
			t.Error("apple-touch-icon isn't opaque")
		} else if n != 180 && a != 0 {
			t.Errorf("%d px: transparency lost", n)
		}
	}
	for name, b := range map[string][]byte{
		"not square": testPNG(t, 600, 512, color.White),
		"too small":  testPNG(t, 256, 256, color.White),
	} {
		if _, err := iconPNGs(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The box filter averages what's under each output pixel, and doesn't
// darken edges next to transparency.
func TestScaleImage(t *testing.T) {
	t.Parallel()
	checker := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	for y := range 4 {
		for x := range 4 {
			if (x+y)%2 == 0 {
				checker.Set(x, y, color.White)
			} else {
				checker.Set(x, y, color.Black)
			}
		}
	}
	m := scaleImage(checker, 2, 2)
	if c := m.RGBAAt(1, 1); c.R < 126 || c.R > 129 || c.A != 255 {
		t.Errorf("checker average: %v", c)
	}
	half := image.NewNRGBA(image.Rect(0, 0, 2, 1)) // red, and transparent
	half.Set(0, 0, color.NRGBA{255, 0, 0, 255})
	c := color.NRGBAModel.Convert(scaleImage(half, 1, 1).At(0, 0)).(color.NRGBA)
	if c.R < 250 || c.A < 126 || c.A > 129 {
		t.Errorf("edge next to transparency: %v", c)
	}
	if m := scaleImage(checker, 3, 7); m.Bounds().Dx() != 3 || m.Bounds().Dy() != 7 {
		t.Errorf("odd sizes: %v", m.Bounds())
	}
}

func TestCheckAccent(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"#3b6fb6": "#3b6fb6", // Heimdall's dark-theme accent passes both themes
		"#2E7D32": "#2e7d32",
		"2f6db5":  "#2f6db5",
	} {
		if got, err := checkAccent(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for in, why := range map[string]string{
		"#ffff00": "too light",
		"#7fb3ff": "too light",
		"#1f4e8c": "too dark for the dark theme", // the light theme's own: too dark on the dark page
		"#000000": "too dark",
		"red":     "hex color",
		"#12345":  "hex color",
		"#ggg000": "hex color",
	} {
		if _, err := checkAccent(in); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v, want %q", in, err, why)
		}
	}
}

// brandPost posts a branding form, multipart when file is set.
func (e *env) brandPost(action string, form url.Values, field string, file []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["csrf"]; !ok {
		form.Set("csrf", auth.CSRFToken(goodToken))
	}
	if field == "" {
		return e.post("/admin/branding/"+action, form, signedIn(e), origin("http://127.0.0.1:8080"))
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, vs := range form {
		for _, v := range vs {
			mw.WriteField(k, v)
		}
	}
	fw, _ := mw.CreateFormFile(field, "upload.png")
	fw.Write(file)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/admin/branding/"+action, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	signedIn(e)(r)
	origin("http://127.0.0.1:8080")(r)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestBrandingDefaultsUnchanged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	body := e.get("/", signedIn(e)).Body.String()
	for _, want := range []string{"<title>Dashboard · Heimdall</title>", `<link rel="icon" href="/static/icon.svg"`,
		`<img src="/static/icon.svg" alt="" width="22" height="22"><span class="side-text">Heimdall</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if strings.Contains(body, "/branding/") {
		t.Error("unbranded page links branding files")
	}
	for _, f := range []string{"logo.png", "icon-512.png", "accent.css"} {
		if w := e.get("/branding/" + f); w.Code != http.StatusNotFound {
			t.Errorf("%s without branding: %d", f, w.Code)
		}
	}
	// mcp.name, when the hub set one, is the default display name.
	e = newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.MCP.Name = "acme-prod" })
	if body := e.get("/login").Body.String(); !strings.Contains(body, "Sign in to acme-prod") {
		t.Error("mcp.name isn't the default name")
	}
}

func TestBrandingSettings(t *testing.T) {
	t.Parallel()
	e := adminEnv(t)
	if w := e.get("/admin/branding", signedIn(e)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "App icon") {
		t.Fatalf("settings page: %d", w.Code)
	}
	for _, step := range []struct {
		action, field string
		form          url.Values
		file          []byte
		audit         string
	}{
		{action: "name", form: url.Values{"name": {"  Acme   Ops "}}, audit: "branding.name"},
		{action: "accent", form: url.Values{"accent": {"#2E7D32"}}, audit: "branding.accent"},
		{action: "logo", field: "logo", file: testPNG(t, 120, 40, color.NRGBA{9, 9, 9, 255}), audit: "branding.logo"},
		{action: "icon", field: "icon", file: testPNG(t, 512, 512, color.NRGBA{9, 99, 9, 255}), audit: "branding.icon"},
	} {
		w := e.brandPost(step.action, step.form, step.field, step.file)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/branding?ok="+step.action {
			t.Fatalf("%s: %d %s", step.action, w.Code, w.Body.String())
		}
		if at, _ := e.st.LastAuditAt(t.Context(), step.audit); at.IsZero() {
			t.Errorf("%s: not audited", step.action)
		}
	}
	b, _ := e.st.Branding(t.Context())
	if b.Name != "Acme Ops" || b.Accent != "#2e7d32" || len(b.Logo) == 0 || len(b.Icon32) == 0 || b.Version != 4 {
		t.Fatalf("stored: %q %q %d %d v%d", b.Name, b.Accent, len(b.Logo), len(b.Icon32), b.Version)
	}

	page := e.get("/", signedIn(e)).Body.String()
	for _, want := range []string{"<title>Dashboard · Acme Ops</title>", `href="/branding/accent.css?v=4"`,
		`<link rel="icon" href="/branding/icon-32.png?v=4" type="image/png"`, `src="/branding/logo.png?v=4"`,
		`<span class="side-text">Acme Ops</span>`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if login := e.get("/login").Body.String(); !strings.Contains(login, "Sign in to Acme Ops") || !strings.Contains(login, `src="/branding/logo.png?v=4"`) {
		t.Error("sign-in page isn't branded")
	}

	// Files: public, cached for good at the current version, revalidated otherwise.
	w := e.get("/branding/accent.css?v=4")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "--accent: #2e7d32") ||
		w.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("accent.css: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	etag := w.Header().Get("ETag")
	if w := e.get("/branding/icon-512.png?v=3"); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-cache" ||
		w.Header().Get("Content-Type") != "image/png" {
		t.Errorf("old version: %d %v", w.Code, w.Header())
	}
	r := httptest.NewRequest(http.MethodGet, "/branding/accent.css?v=4", nil)
	r.Header.Set("If-None-Match", etag)
	rw := httptest.NewRecorder()
	e.h.ServeHTTP(rw, r)
	if rw.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", rw.Code)
	}
	if w := e.get("/branding/../../etc/passwd"); w.Code == http.StatusOK {
		t.Error("path escape")
	}

	// Resets go back to Heimdall's, one at a time.
	for _, a := range []string{"reset-name", "reset-accent", "reset-logo", "reset-icon"} {
		if w := e.brandPost(a, nil, "", nil); w.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d", a, w.Code)
		}
	}
	if at, _ := e.st.LastAuditAt(t.Context(), "branding.icon.reset"); at.IsZero() {
		t.Error("reset not audited")
	}
	page = e.get("/", signedIn(e)).Body.String()
	if !strings.Contains(page, "<title>Dashboard · Heimdall</title>") || strings.Contains(page, "/branding/") {
		t.Error("reset didn't restore the defaults")
	}
}

func TestBrandingRefusals(t *testing.T) {
	t.Parallel()
	e := adminEnv(t)
	for name, c := range map[string]struct {
		action, field string
		form          url.Values
		file          []byte
		msg           string
	}{
		"long name":    {action: "name", form: url.Values{"name": {strings.Repeat("x", 31)}}, msg: "up to 30 characters"},
		"bad accent":   {action: "accent", form: url.Values{"accent": {"#ffff00"}}, msg: "too light"},
		"logo not png": {action: "logo", field: "logo", file: []byte("GIF89a...."), msg: "isn&#39;t a PNG"},
		"logo too big": {action: "logo", field: "logo", file: append(append([]byte{}, pngMagic...), make([]byte, maxLogoSize)...),
			msg: "the limit is 512 KB"},
		"small icon": {action: "icon", field: "icon", file: testPNG(t, 128, 128, color.White), msg: "at least 512"},
		"no file":    {action: "icon", msg: "choose a PNG file"},
	} {
		w := e.brandPost(c.action, c.form, c.field, c.file)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.msg) {
			t.Errorf("%s: %d, want %q in the page", name, w.Code, c.msg)
		}
	}
	if b, _ := e.st.Branding(t.Context()); b.Version != 0 {
		t.Error("a refused change was saved")
	}

	// CSRF and Origin are checked on uploads too, and only admins may brand.
	if w := e.brandPost("logo", url.Values{"csrf": {"nope"}}, "logo", testPNG(t, 8, 8, color.White)); w.Code != http.StatusForbidden {
		t.Errorf("upload without CSRF: %d", w.Code)
	}
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com", Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleAdmin}}, SessionToken: goodToken}
	if w := e.get("/admin/branding", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("non-admin GET: %d", w.Code)
	}
	if w := e.brandPost("name", url.Values{"name": {"x"}}, "", nil); w.Code != http.StatusNotFound {
		t.Errorf("non-admin POST: %d", w.Code)
	}
	if strings.Contains(e.get("/", signedIn(e)).Body.String(), `href="/admin/branding"`) {
		t.Error("Branding nav shown to a non-admin")
	}
}
