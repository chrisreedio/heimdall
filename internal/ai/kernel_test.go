// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/ingest"
	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

// Realistic installed package sets.
var (
	ubuntuAWSKernel = []string{"linux-aws", "linux-image-aws", "linux-headers-aws", "linux-tools-aws",
		"linux-image-6.17.0-1009-aws", "linux-modules-6.17.0-1009-aws", "linux-headers-6.17.0-1009-aws",
		"linux-aws-6.17-headers-6.17.0-1009", "linux-tools-6.17.0-1009-aws", "linux-aws-6.17-tools-6.17.0-1009",
		"linux-tools-common", "linux-libc-dev", "linux-firmware"}
	ubuntuGenericKernel = []string{"linux-generic", "linux-image-generic", "linux-headers-generic",
		"linux-image-6.8.0-45-generic", "linux-modules-6.8.0-45-generic", "linux-headers-6.8.0-45", "linux-headers-6.8.0-45-generic",
		"linux-libc-dev"}
	ubuntuHWEKernel = []string{"linux-generic-hwe-24.04", "linux-image-generic-hwe-24.04", "linux-headers-generic-hwe-24.04",
		"linux-image-6.11.0-29-generic", "linux-modules-6.11.0-29-generic", "linux-hwe-6.11-headers-6.11.0-29", "linux-headers-6.11.0-29-generic"}
	ubuntuNoMeta = []string{"linux-image-6.8.0-45-generic", "linux-modules-6.8.0-45-generic", "linux-libc-dev"}
	debianKernel = []string{"linux-image-amd64", "linux-image-6.1.0-26-amd64", "linux-headers-amd64", "linux-headers-6.1.0-26-amd64",
		"linux-headers-6.1.0-26-common", "linux-kbuild-6.1"}
	userland     = []string{"openssl", "libssl3", "curl", "libcurl4t64"}
	rockyKernel  = []string{"kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-tools", "kernel-tools-libs", "kernel-headers", "openssl", "openssl-libs"}
	alpineKernel = []string{"linux-lts", "linux-firmware-none", "linux-pam", "openssl", "libssl3", "libcrypto3"}
)

var (
	awsFinding = report.Finding{Package: "linux-aws-6.17", Version: "6.17.0-1009.9~24.04.1", Fixed: "6.17.0-1019.19~24.04.1", Severity: "high",
		Binaries: []string{"linux-aws-6.17-headers-6.17.0-1009", "linux-aws-6.17-tools-6.17.0-1009", "linux-headers-6.17.0-1009-aws",
			"linux-modules-6.17.0-1009-aws", "linux-tools-6.17.0-1009-aws"}}
	signedAWSFinding = report.Finding{Package: "linux-signed-aws-6.17", Fixed: "6.17.0-1019.19~24.04.1", Severity: "high",
		Binaries: []string{"linux-image-6.17.0-1009-aws"}}
	genericFinding = report.Finding{Package: "linux", Fixed: "6.8.0-47.47", Severity: "high",
		Binaries: []string{"linux-headers-6.8.0-45", "linux-headers-6.8.0-45-generic", "linux-modules-6.8.0-45-generic", "linux-libc-dev"}}
	hweFinding = report.Finding{Package: "linux-hwe-6.11", Fixed: "6.11.0-31.31~24.04.1", Severity: "medium",
		Binaries: []string{"linux-hwe-6.11-headers-6.11.0-29", "linux-headers-6.11.0-29-generic", "linux-modules-6.11.0-29-generic"}}
	debianFinding = report.Finding{Package: "linux", Fixed: "6.1.115-1", Severity: "high",
		Binaries: []string{"linux-image-6.1.0-26-amd64", "linux-headers-6.1.0-26-amd64", "linux-headers-6.1.0-26-common", "linux-kbuild-6.1"}}
	opensslFinding = report.Finding{Package: "openssl", Fixed: "3.0.13-0ubuntu3.5", Severity: "critical", Binaries: []string{"libssl3", "openssl"}}
	rockyFinding   = report.Finding{Package: "kernel", Fixed: "5.14.0-503.14.1.el9_5", Severity: "high",
		Binaries: []string{"kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-tools", "kernel-tools-libs"}}
	alpineFinding = report.Finding{Package: "linux-lts", Fixed: "6.6.58-r0", Severity: "high", Binaries: []string{"linux-lts"}}
)

// testHost is a host's package manager and installed packages, every one
// with an update pending.
type testHost struct {
	PM   string
	Pkgs report.Pkgs
}

func hostWith(pm string, sets ...[]string) testHost {
	h := testHost{PM: pm, Pkgs: report.Pkgs{}}
	for _, s := range sets {
		for _, p := range s {
			h.Pkgs[p] = true
		}
	}
	return h
}

// allowedFor is what Heimdall allows on a host where it suggested cmds.
func allowedFor(pm string, cmds ...string) HostAllowed { return HostAllowed{PM: pm, Commands: cmds} }

type kernelCase struct {
	name     string
	host     testHost
	findings []report.Finding
	want     string
	kernel   bool
}

var kernelCases = []kernelCase{
	{"ubuntu aws, kernel only", hostWith("dpkg", ubuntuAWSKernel), []report.Finding{awsFinding, signedAWSFinding},
		"sudo apt-get update && sudo apt-get install --only-upgrade linux-aws linux-headers-aws linux-image-aws linux-tools-aws", true},
	{"ubuntu aws, mixed", hostWith("dpkg", ubuntuAWSKernel, userland), []report.Finding{awsFinding, opensslFinding},
		"sudo apt-get update && sudo apt-get install --only-upgrade libssl3 linux-aws linux-headers-aws linux-image-aws linux-tools-aws openssl", true},
	{"ubuntu generic, kernel only", hostWith("dpkg", ubuntuGenericKernel), []report.Finding{genericFinding},
		"sudo apt-get update && sudo apt-get install --only-upgrade linux-generic linux-headers-generic linux-image-generic linux-libc-dev", true},
	{"ubuntu hwe, mixed", hostWith("dpkg", ubuntuHWEKernel, userland), []report.Finding{hweFinding, opensslFinding},
		"sudo apt-get update && sudo apt-get install --only-upgrade libssl3 linux-generic-hwe-24.04 linux-headers-generic-hwe-24.04 linux-image-generic-hwe-24.04 openssl", true},
	{"ubuntu, no metapackage", hostWith("dpkg", ubuntuNoMeta, userland), []report.Finding{genericFinding, opensslFinding},
		"sudo apt-get update && sudo apt-get upgrade", true},
	{"debian, kernel only", hostWith("dpkg", debianKernel), []report.Finding{debianFinding},
		"sudo apt-get update && sudo apt-get install --only-upgrade linux-headers-amd64 linux-image-amd64 linux-kbuild-6.1", true},
	{"ubuntu, no kernel finding", hostWith("dpkg", ubuntuAWSKernel, userland), []report.Finding{opensslFinding},
		"sudo apt-get update && sudo apt-get install --only-upgrade libssl3 openssl", false},
	{"rocky, mixed", hostWith("rpm", rockyKernel), []report.Finding{rockyFinding, {Package: "openssl", Fixed: "1:3.2.2-6.el9_5", Binaries: []string{"openssl", "openssl-libs"}}},
		"sudo dnf upgrade --refresh kernel kernel-core kernel-modules kernel-modules-core kernel-tools kernel-tools-libs openssl openssl-libs", true},
	{"alpine, kernel only", hostWith("apk", alpineKernel), []report.Finding{alpineFinding},
		"sudo apk update && sudo apk upgrade linux-lts", true},
}

func TestKernelFixCommand(t *testing.T) {
	for _, c := range kernelCases {
		t.Run(c.name, func(t *testing.T) {
			cmd, label, u := fixCommand(c.host.PM, c.findings, c.host.Pkgs)
			isKernel := u.Kernel
			if cmd != c.want || isKernel != c.kernel {
				t.Fatalf("got %q (kernel %v)\nwant %q (kernel %v)", cmd, isKernel, c.want, c.kernel)
			}
			if strings.Contains(cmd, "-1009") || strings.Contains(cmd, "-45-") || strings.Contains(cmd, "6.1.0-26") || strings.Contains(cmd, "6.11.0-29") {
				t.Errorf("names an ABI-versioned kernel package: %q", cmd)
			}
			if c.kernel != strings.Contains(label, "Reboot") {
				t.Errorf("label %q", label)
			}
			// The suggestion itself passes the output validator for that host,
			// in both its checks.
			allowed := Allowed{Hosts: map[string]HostAllowed{"h": allowedFor(c.host.PM, cmd)}}
			res, err := Parse(answer(act("h", cmd)), allowed)
			if err != nil || res.Actions[0].Command != cmd {
				t.Errorf("validator dropped %q: %v", cmd, err)
			}
			if !commandShapeOK(cmd) {
				t.Errorf("stored shape check dropped %q", cmd)
			}
		})
	}
}

func TestKernelCommandVariantsRejected(t *testing.T) {
	built := func(h testHost, fs ...report.Finding) HostAllowed {
		cmd, _, _ := fixCommand(h.PM, fs, h.Pkgs)
		return allowedFor(h.PM, cmd)
	}
	allowed := Allowed{Hosts: map[string]HostAllowed{
		"aws": built(hostWith("dpkg", ubuntuAWSKernel, userland), awsFinding, opensslFinding),
		"el":  built(hostWith("rpm", rockyKernel), rockyFinding),
		"alp": built(hostWith("apk", alpineKernel), alpineFinding),
	}}
	for _, c := range []struct{ host, cmd string }{
		{"aws", "sudo apt-get update && sudo apt-get install --only-upgrade linux-image-6.17.0-1009-aws"},
		{"aws", "sudo apt-get install --only-upgrade linux-aws linux-modules-6.17.0-1009-aws"},
		{"aws", "sudo apt-get update && sudo apt-get install --only-upgrade linux-aws-6.17-headers-6.17.0-1009"},
		{"aws", "sudo apt-get update && sudo apt-get install --only-upgrade linux-generic"}, // not installed there
		{"aws", "sudo apt-get update && sudo apt-get install linux-aws"},
		{"aws", "sudo apt-get update && sudo apt-get upgrade -y"},
		{"aws", "sudo apt-get update && sudo apt-get upgrade linux-aws"},
		{"aws", "sudo apt-get update && sudo apt-get dist-upgrade"},
		{"aws", "sudo apt-get update && sudo apt-get full-upgrade"},
		{"aws", "sudo apt-get upgrade"},
		{"aws", "sudo apt-get update && sudo apt-get upgrade && sudo reboot"},
		{"aws", "sudo apt-get update && sudo apt-get upgrade; rm -rf /"},
		{"aws", "sudo apt update && sudo apt upgrade"},
		{"el", "sudo apt-get update && sudo apt-get upgrade"}, // wrong package manager
		{"el", "sudo dnf upgrade --refresh kernel*"},
		{"el", "sudo dnf upgrade"},
		{"alp", "sudo apt-get update && sudo apt-get upgrade"},
		{"alp", "sudo apk update && sudo apk upgrade"},
	} {
		res, err := Parse(answer(act(c.host, c.cmd)), allowed)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Actions[0].Command; got != "" {
			t.Errorf("%s: kept %q", c.host, got)
		}
	}
	// The stored-result check rejects ABI names too, whatever the host.
	for _, cmd := range []string{"sudo apt-get install --only-upgrade linux-image-6.17.0-1009-aws", "sudo apt-get upgrade -y"} {
		if commandShapeOK(cmd) {
			t.Errorf("shape check kept %q", cmd)
		}
	}
}

// The per-host facts carry the running kernel, the reboot flag and the
// newest installed kernel, and the suggested commands the fix above.
func TestKernelFacts(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	org, err := st.CreateOrg(ctx, "test", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", "ip-10-0-0-5", nil); err != nil {
		t.Fatal(err)
	}
	host, _ := st.HostByName(ctx, "acme", "ip-10-0-0-5")
	pkg := func(name, ver, src string) map[string]any {
		return map[string]any{"name": name, "version": ver, "arch": "amd64", "source_name": src, "source_version": ver}
	}
	snap := map[string]any{
		"format":         "heimdall.snapshot/v1",
		"collector":      map[string]any{"version": "0.4.17", "sha256": strings.Repeat("ab", 32)},
		"collected_at":   now.Format(time.RFC3339),
		"os":             map[string]any{"id": "ubuntu", "id_like": "debian", "version_id": "24.04", "version_codename": "noble", "pretty_name": "Ubuntu 24.04.3 LTS"},
		"kernel":         map[string]any{"release": "6.17.0-1009-aws", "arch": "x86_64"},
		"uptime_seconds": 86400, "reboot_required": false, "package_manager": "dpkg",
		"packages": []any{
			pkg("linux-aws", "6.17.0.1009.9", "linux-meta-aws-6.17"),
			pkg("linux-image-aws", "6.17.0.1009.9", "linux-meta-aws-6.17"),
			pkg("linux-image-6.17.0-1009-aws", "6.17.0-1009.9~24.04.1", "linux-signed-aws-6.17"),
			pkg("linux-modules-6.17.0-1009-aws", "6.17.0-1009.9~24.04.1", "linux-aws-6.17"),
			pkg("linux-tools-6.17.0-1009-aws", "6.17.0-1009.9~24.04.1", "linux-aws-6.17"),
			pkg("openssl", "3.0.13-0ubuntu3.4", "openssl"),
		},
		"updates": []any{
			map[string]any{"name": "linux-aws", "arch": "amd64", "version": "6.17.0.1019.19", "security": false},
			map[string]any{"name": "linux-image-aws", "arch": "amd64", "version": "6.17.0.1019.19", "security": false},
		},
		"unavailable": []any{},
	}
	raw, _ := json.Marshal(snap)
	acc := ingest.Accepter{Store: st, Now: func() time.Time { return now }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("ingest: %+v %v", res, err)
	}
	if err := st.PutAdvisory(ctx, store.Advisory{ID: "UBUNTU-CVE-2026-1", Modified: now, Severity: "high", Raw: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.SetFindings(ctx, host.ID, []store.Finding{{AdvisoryID: "UBUNTU-CVE-2026-1", Ecosystem: "Ubuntu:24.04",
		Package: "linux-aws-6.17", Version: "6.17.0-1009.9~24.04.1", FixedVersion: "6.17.0-1019.19~24.04.1",
		Binaries: []string{"linux-modules-6.17.0-1009-aws", "linux-tools-6.17.0-1009-aws"}}}, now); err != nil {
		t.Fatal(err)
	}
	b, _, err := Sources{Store: st, Now: now}.BuildHost(ctx, org, host, 24000)
	if err != nil {
		t.Fatal(err)
	}
	var facts HostFacts
	if err := json.Unmarshal(b, &facts); err != nil {
		t.Fatal(err)
	}
	h := facts.Host
	if h.RunningKernel != "6.17.0-1009-aws" || h.NewestKernel != "6.17.0-1009-aws" || h.RebootRequired == nil || *h.RebootRequired {
		t.Errorf("kernel facts: running %q newest %q reboot %v", h.RunningKernel, h.NewestKernel, h.RebootRequired)
	}
	var cmds []string
	for _, c := range h.Commands {
		cmds = append(cmds, c.Command)
	}
	want := []string{"sudo apt-get update && sudo apt-get install --only-upgrade linux-aws linux-image-aws", RebootCommand}
	if !slices.Equal(cmds, want) {
		t.Errorf("commands %q, want %q", cmds, want)
	}
	if !strings.Contains(string(b), `"running_kernel":"6.17.0-1009-aws"`) || !strings.Contains(string(b), `"reboot_required":false`) {
		t.Errorf("facts JSON: %s", b)
	}
}
