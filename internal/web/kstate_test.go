// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

func kernelCaseEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.st.CreateOrg(t.Context(), "test", "acme", "Acme")
	storetest.SeedKernelCases(t, e.st, "acme", testNow)
	return e
}

func preText(body, id string) string {
	m := regexp.MustCompile(`<pre id="` + id + `">([^<]*)</pre>`).FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// The two real AWS kernel cases on the host page.
func TestKernelCaseHostPages(t *testing.T) {
	e := kernelCaseEnv(t)

	// web-01 runs 6.17 with 7.0 installed: reboot, not a metapackage upgrade.
	local := e.get("/hosts/acme/"+storetest.RebootPendingHost, signedIn(e)).Body.String()
	for _, want := range []string{
		`kernel ` + storetest.KernelOld,
		`reboot pending: ` + storetest.KernelNew + ` installed</a>`,
		`>reboot pending</span>`, // the badge on the KEV findings
		`>next kernel</span>`,    // the 7.0 kernel's own finding
		`Reboot to run ` + storetest.KernelNew + ` <span class="muted small">· clears 4 findings marked "reboot pending"</span>`,
		`may still have findings of its own`,
		`2 findings fixed upstream, not yet in this host's package cache.`,
		`<code>sudo apt-get update</code>`,
	} {
		if !strings.Contains(local, want) {
			t.Errorf("web-01 page missing %q", want)
		}
	}
	if got := preText(local, "cmd-reboot"); got != "sudo reboot" {
		t.Errorf("web-01 reboot command %q", got)
	}
	if got := preText(local, "cmd-fix"); got != "sudo apt-get update &amp;&amp; sudo apt-get install --only-upgrade liblzma5" {
		t.Errorf("web-01 fix command %q", got)
	}
	if i, j := strings.Index(local, `id="cmd-reboot"`), strings.Index(local, `id="cmd-fix"`); i < 0 || i > j {
		t.Error("the reboot should come before the upgrade")
	}
	if strings.Contains(local, "old kernel installed") || strings.Contains(local, `id="cmd-old-kernels"`) {
		t.Error("web-01 has no old kernel")
	}

	// web-02 runs 7.0: the 6.17 findings are on an old kernel.
	fun := e.get("/hosts/acme/"+storetest.OldKernelHost, signedIn(e)).Body.String()
	for _, want := range []string{
		`kernel ` + storetest.KernelNew, `old kernel installed</a>`, `>not running</span>`,
		`<strong>4</strong> on kernels not running`, `<strong>0</strong> known-exploited`,
		`2 findings fixed upstream, not yet in this host's package cache.`,
	} {
		if !strings.Contains(fun, want) {
			t.Errorf("web-02 page missing %q", want)
		}
	}
	if got := preText(fun, "cmd-fix"); got != "sudo apt-get update &amp;&amp; sudo apt-get install --only-upgrade liblzma5" {
		t.Errorf("web-02 fix command %q", got)
	}
	if got := preText(fun, "cmd-old-kernels"); !strings.HasPrefix(got, "sudo apt-get purge linux-aws-6.17-headers-6.17.0-1009 ") ||
		strings.Contains(got, "7.0.0") {
		t.Errorf("web-02 purge command %q", got)
	}
	if strings.Contains(fun, "reboot pending") || strings.Contains(fun, `id="cmd-reboot"`) {
		t.Error("web-02 has no reboot pending")
	}
	for name, body := range map[string]string{"web-01": local, "web-02": fun} {
		if cmd := preText(body, "cmd-fix"); strings.Contains(cmd, "linux-aws") {
			t.Errorf("%s: the patch command names a metapackage with no update pending: %q", name, cmd)
		}
	}
}

// Dashboard and host list counts leave findings on kernels that aren't
// running out of the actionable numbers, and the SQL tallies agree with
// counting every finding.
func TestKernelCaseCounts(t *testing.T) {
	e := kernelCaseEnv(t)
	ctx := t.Context()
	full, err := report.Build(ctx, e.st, report.Filter{Scope: store.AllScope}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	quick, err := report.Build(ctx, e.st, report.Filter{Scope: store.AllScope, CountsOnly: true}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]report.Counts{}
	for i, h := range full.Hosts {
		if h.Counts != quick.Hosts[i].Counts {
			t.Errorf("%s: full %+v, counts-only %+v", h.Name, h.Counts, quick.Hosts[i].Counts)
		}
		counts[h.Name] = h.Counts
	}
	want := map[string]report.Counts{
		storetest.OldKernelHost: {Total: 8, KEV: 0, Critical: 1, High: 5, Medium: 2, Fixable: 2, FixPending: 1, NoFix: 1, FixUrgent: 1,
			NotRunning: 4, KernelUserland: 1},
		storetest.RebootPendingHost: {Total: 8, KEV: 4, Critical: 1, High: 5, Medium: 2, Fixable: 6, FixPending: 1, NoFix: 1, FixUrgent: 5,
			RebootPending: 4, KernelUserland: 1},
	}
	for name, w := range want {
		if counts[name] != w {
			t.Errorf("%s counts\n got %+v\nwant %+v", name, counts[name], w)
		}
	}

	hosts := e.get("/hosts", signedIn(e)).Body.String()
	row := func(name string) string {
		i := strings.Index(hosts, `class="h-name" href="/hosts/acme/`+name+`"`)
		if i < 0 {
			t.Fatalf("no row for %s", name)
		}
		j := strings.Index(hosts[i:], "</tr>")
		return hosts[i : i+j]
	}
	if r := row(storetest.RebootPendingHost); !strings.Contains(r, `>reboot pending</span>`) || !strings.Contains(r, `<span class="badge kev">4</span>`) {
		t.Errorf("web-01 row: %s", r)
	}
	if r := row(storetest.OldKernelHost); !strings.Contains(r, `data-label="Not running">4</td>`) || strings.Contains(r, `badge kev`) {
		t.Errorf("web-02 row: %s", r)
	}
	if body := e.get("/hosts?only=kev", signedIn(e)).Body.String(); strings.Contains(body, storetest.OldKernelHost) {
		t.Error("web-02 is listed as known-exploited, but its KEVs are on a kernel that isn't running")
	}
	if dash := e.get("/", signedIn(e)).Body.String(); !strings.Contains(dash, "4 on kernels not running") || !strings.Contains(dash, "2 on kernel userland") {
		t.Error("dashboard doesn't count findings on kernels not running or kernel userland")
	}

	// The linux-tools-common KEV is muted: badged, left out of the
	// known-exploited filter, still listed with all findings.
	page := e.get("/hosts/acme/"+storetest.OldKernelHost+"?findings=all", signedIn(e)).Body.String()
	for _, want := range []string{`>kernel userland</span>`, `<strong>1</strong> on kernel userland</span>`, `linux-tools-common`} {
		if !strings.Contains(page, want) {
			t.Errorf("web-02 page missing %q", want)
		}
	}
	if kev := e.get("/hosts/acme/"+storetest.OldKernelHost+"?sev=kev", signedIn(e)).Body.String(); strings.Contains(kev, storetest.UserlandKEVCVE) {
		t.Error("the known-exploited filter lists a kernel userland finding")
	}
}
