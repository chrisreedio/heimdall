// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/kernel"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

// kernelCaseFacts seeds the two real AWS kernel cases (see
// storetest.SeedKernelCases) and returns each host's facts and allowlist.
func kernelCaseFacts(t *testing.T) (*store.Store, store.Org, map[string]store.IngestHost, map[string]hostFact, map[string]HostAllowed) {
	t.Helper()
	st := storetest.New(t)
	org, err := st.CreateOrg(t.Context(), "test", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	fun, local := storetest.SeedKernelCases(t, st, "acme", now)
	hosts := map[string]store.IngestHost{fun.Name: fun, local.Name: local}
	facts, allowed := map[string]hostFact{}, map[string]HostAllowed{}
	for name, h := range hosts {
		b, a, err := Sources{Store: st, Now: now}.BuildHost(t.Context(), org, h, 24000)
		if err != nil {
			t.Fatal(err)
		}
		var hf HostFacts
		if err := json.Unmarshal(b, &hf); err != nil {
			t.Fatal(err)
		}
		facts[name], allowed[name] = hf.Host, a.Hosts[name]
	}
	return st, org, hosts, facts, allowed
}

func commandsOf(h hostFact) []string {
	var out []string
	for _, c := range h.Commands {
		out = append(out, c.Command)
	}
	return out
}

func statusesOf(h hostFact) map[string]string {
	out := map[string]string{}
	for _, f := range h.Top {
		out[f.Advisory] = f.KernelStatus
	}
	return out
}

const (
	liblzma    = "sudo apt-get update && sudo apt-get install --only-upgrade liblzma5"
	securityUp = "sudo apt-get install --only-upgrade liblzma5 libsystemd0 libudev1 zlib1g"
	purge617   = "sudo apt-get purge linux-aws-6.17-headers-6.17.0-1009 linux-aws-6.17-tools-6.17.0-1009 linux-headers-6.17.0-1009-aws " +
		"linux-image-6.17.0-1009-aws linux-modules-6.17.0-1009-aws linux-tools-6.17.0-1009-aws"
	noOpMeta = "sudo apt-get update && sudo apt-get install --only-upgrade linux-aws linux-headers-aws linux-image-aws"
)

func TestKernelCaseFacts(t *testing.T) {
	_, _, _, facts, allowed := kernelCaseFacts(t)

	// web-01 runs 6.17 with 7.0 installed: the reboot comes first, and
	// nothing upgrades the metapackages (they have no update pending).
	l := facts[storetest.RebootPendingHost]
	if l.KernelState != kernel.StateRebootPending || l.NewerKernel != storetest.KernelNew || l.RunningKernel != storetest.KernelOld ||
		l.RebootPending != storetest.KernelKEVs || l.NotRunning != 0 || l.NotInCache != 1 {
		t.Errorf("web-01 kernel facts: state %q newer %q running %q reboot-pending %d not-running %d not-in-cache %d",
			l.KernelState, l.NewerKernel, l.RunningKernel, l.RebootPending, l.NotRunning, l.NotInCache)
	}
	if got, want := commandsOf(l), []string{RebootCommand, liblzma, securityUp}; !slices.Equal(got, want) {
		t.Errorf("web-01 commands %q\nwant %q", got, want)
	}
	if !strings.HasPrefix(l.Commands[0].Label, "Reboot to run "+storetest.KernelNew) {
		t.Errorf("reboot label %q", l.Commands[0].Label)
	}
	if l.Counts.KEV != storetest.KernelKEVs || l.Counts.RebootPending != storetest.KernelKEVs || l.Counts.NotRunning != 0 {
		t.Errorf("web-01 counts %+v", l.Counts)
	}
	st := statusesOf(l)
	if st["UBUNTU-CVE-2026-31001"] != kernel.StatusRebootPending || st["UBUNTU-CVE-2026-31010"] != kernel.StatusRebootPending ||
		st["UBUNTU-CVE-2026-32001"] != kernel.StatusNewerKernel || st["UBUNTU-CVE-2026-33001"] != "" {
		t.Errorf("web-01 kernel statuses %v", st)
	}

	// web-02 runs 7.0: the 6.17 KEVs are on an old kernel, cleared by
	// the purge, not live, and not counted as KEV.
	f := facts[storetest.OldKernelHost]
	if f.KernelState != kernel.StateOldKernels || f.NewerKernel != "" || f.NotRunning != storetest.KernelKEVs || f.RebootPending != 0 || f.NotInCache != 1 {
		t.Errorf("web-02 kernel facts: state %q newer %q not-running %d not-in-cache %d", f.KernelState, f.NewerKernel, f.NotRunning, f.NotInCache)
	}
	if got, want := commandsOf(f), []string{liblzma, securityUp, purge617}; !slices.Equal(got, want) {
		t.Errorf("web-02 commands %q\nwant %q", got, want)
	}
	if f.Counts.KEV != 0 || f.Counts.NotRunning != storetest.KernelKEVs || f.Counts.Fixable != 2 || f.Counts.NoFix != 1 {
		t.Errorf("web-02 counts %+v", f.Counts)
	}
	st = statusesOf(f)
	if st["UBUNTU-CVE-2026-31001"] != kernel.StatusNotRunning || st["UBUNTU-CVE-2026-32001"] != kernel.StatusRunning {
		t.Errorf("web-02 kernel statuses %v", st)
	}
	if f.Top[len(f.Top)-1].KernelStatus != kernel.StatusNotRunning || f.Top[0].KernelStatus == kernel.StatusNotRunning {
		t.Error("findings on the old kernel should rank after live ones")
	}

	for name, h := range facts {
		for _, c := range h.Commands {
			if strings.Contains(c.Command, "linux-aws ") || strings.HasSuffix(c.Command, "linux-aws") {
				t.Errorf("%s: suggests the no-op metapackage upgrade %q", name, c.Command)
			}
		}
		if !slices.Equal(allowed[name].Commands, commandsOf(h)) {
			t.Errorf("%s: allowlist %q differs from the facts' commands", name, allowed[name].Commands)
		}
	}
	if a := allowed[storetest.RebootPendingHost]; len(a.Required) != 1 || a.Required[0].Command != RebootCommand || !a.RequiredFirst {
		t.Errorf("web-01 required steps %+v", a.Required)
	}
	if a := allowed[storetest.OldKernelHost]; len(a.Required) != 0 {
		t.Errorf("web-02 required steps %+v", a.Required)
	}
}

// The model's plan for web-01 led with the metapackage upgrade, which
// does nothing there. The consistency check drops it, trims a mixed
// command to what Heimdall suggested, and puts the missing reboot first.
func TestKernelCaseReconcile(t *testing.T) {
	st, org, hosts, _, allowed := kernelCaseFacts(t)
	local := storetest.RebootPendingHost
	a := Allowed{Hosts: map[string]HostAllowed{local: allowed[local]}}
	text := answer(
		act(local, noOpMeta),
		act(local, "sudo apt-get install --only-upgrade liblzma5 linux-aws"),
		act(local, nil),
	)
	res, err := Parse(text, a)
	if err != nil {
		t.Fatal(err)
	}
	res = Reconcile(res, a)
	if len(res.Actions) != 3 {
		t.Fatalf("actions %+v", res.Actions)
	}
	if r := res.Actions[0]; r.Command != RebootCommand || r.Heimdall != HeimdallAdded || r.Host != local ||
		!strings.Contains(r.Title, storetest.KernelNew) || !strings.Contains(r.Why, "may still have findings of its own") {
		t.Errorf("added reboot step %+v", r)
	}
	if e := res.Actions[1]; e.Command != "sudo apt-get install --only-upgrade liblzma5" || e.Heimdall != HeimdallEdited {
		t.Errorf("edited step %+v", e)
	}
	if n := res.Actions[2]; n.Command != "" || n.Heimdall != "" {
		t.Errorf("step without a command %+v", n)
	}
	for _, act := range res.Actions {
		if strings.Contains(act.Command, "linux-aws") {
			t.Errorf("kept %q", act.Command)
		}
	}

	// A plan that already reboots gets nothing added.
	res, _ = Parse(answer(act(local, liblzma), act(local, RebootCommand)), a)
	if res = Reconcile(res, a); len(res.Actions) != 2 || res.Actions[0].Heimdall != "" || res.Actions[1].Heimdall != "" {
		t.Errorf("plan with the reboot: %+v", res.Actions)
	}

	// web-02 has nothing to reboot for: a reboot Heimdall didn't suggest
	// is dropped, the purge stays, and nothing is added.
	fun := storetest.OldKernelHost
	fa := Allowed{Hosts: map[string]HostAllowed{fun: allowed[fun]}}
	res, _ = Parse(answer(act(fun, purge617), act(fun, RebootCommand), act(fun, noOpMeta)), fa)
	if res = Reconcile(res, fa); len(res.Actions) != 1 || res.Actions[0].Command != purge617 {
		t.Errorf("web-02 plan: %+v", res.Actions)
	}

	// End to end: the stored result carries the mark, and Decode keeps it.
	svc := newService(st, &fakeProvider{text: text})
	id, err := st.StartAIRun(t.Context(), org.ID, hosts[local].ID, store.AIHost, "user:1", svc.Deployment(), now, time.Minute, svc.Stale())
	if err != nil {
		t.Fatal(err)
	}
	svc.runHost(id, "user:1", org, hosts[local])
	runs, err := st.AIRuns(t.Context(), org.ID, hosts[local].ID, 1)
	if err != nil || len(runs) != 1 {
		t.Fatal(runs, err)
	}
	v := ViewOf(runs, now, svc.Stale())
	if v.Result == nil || len(v.Result.Actions) != 3 || v.Result.Actions[0].Heimdall != HeimdallAdded || v.Result.Actions[0].Command != RebootCommand {
		t.Errorf("stored plan %+v", v.Result)
	}
}

func TestDecodeKeepsOnlyKnownMarks(t *testing.T) {
	raw, _ := json.Marshal(Result{Summary: "s", Actions: []Action{{Title: "a", Heimdall: HeimdallAdded}, {Title: "b", Heimdall: "<b>x</b>"}}})
	r, ok := Decode(raw)
	if !ok || r.Actions[0].Heimdall != HeimdallAdded || r.Actions[1].Heimdall != "" {
		t.Errorf("%+v", r)
	}
}
