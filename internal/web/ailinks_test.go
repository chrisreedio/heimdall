// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/report"
)

func TestAILinker(t *testing.T) {
	hosts := []report.Host{
		{Name: "web-01", Sites: []report.Site{{Root: "/srv/shop", ServerNames: []string{"shop.example.com", "_", "*.example.com"}},
			{Root: "/srv/shared", ServerNames: []string{"shared.example.com"}}}},
		{Name: "web-01.example.com"},
		{Name: "web-02", Sites: []report.Site{{Root: "/srv/shared", ServerNames: []string{"shared.example.com"}}}},
	}
	l := newAILinker("acme", hosts)
	got := string(l.HTML(`Patch web-01 first, then WEB-02. shop.example.com runs <b>old</b> PHP; web-01.example.com and ` +
		`shared.example.com wait. CVE-2026-111497 is live. Not web-010, xweb-01 or web-01-db; cve-2026-1 neither.`))
	for _, want := range []string{
		`Patch <a class="ref ref-host" href="/hosts/acme/web-01" title="Host"><svg`,
		`>web-01</a> first, then <a class="ref ref-host" href="/hosts/acme/web-02" title="Host">`,
		`>WEB-02</a>.`, // case is kept as written, and a sentence's period isn't part of the name
		`<a class="ref ref-site" href="/hosts/acme/web-01/site?root=%2Fsrv%2Fshop" title="Site">`,
		`&lt;b&gt;old&lt;/b&gt;`,
		`href="/hosts/acme/web-01.example.com"`, // the longer name wins
		` shared.example.com wait`,              // on two hosts: left plain
		`<a class="ref ref-cve" href="/search?q=CVE-2026-111497" title="Search for this CVE">CVE-2026-111497</a>`,
		`Not web-010, xweb-01 or web-01-db; cve-2026-1 neither.`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "<b>") {
		t.Error("unescaped")
	}
	var none *aiLinker
	if got := none.HTML("<x> web-01"); got != "&lt;x&gt; web-01" {
		t.Errorf("nil linker = %q", got)
	}
}
