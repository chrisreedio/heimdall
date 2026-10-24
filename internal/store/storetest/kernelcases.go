// SPDX-License-Identifier: AGPL-3.0-or-later

package storetest

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/snapshot"
	"github.com/chrisreedio/heimdall/internal/store"
)

// The two real Ubuntu 24.04 AWS kernel cases, as regression fixtures. Both
// hosts have the same packages (internal/snapshot/testdata/ubuntu2404-aws-*):
// the linux-aws metapackages, already at the 7.0 kernel with no update
// pending, and both the 6.17.0-1009 and the 7.0.0-1014 ABI packages.
//
//   - web-02 runs 7.0.0-1014-aws. The 6.17 packages are an old kernel
//     that isn't running, and carry the 4 KEV findings.
//   - web-01 runs 6.17.0-1009-aws, with 7.0.0-1014-aws installed but
//     not booted (reboot required). The KEV findings are on the running
//     kernel, and upgrading the metapackages does nothing: the fix is the
//     reboot.
//
// Each host also has a finding on the 7.0 kernel with no fix, an openssl
// finding whose fix no pending update installs (fixed upstream, not in the
// package cache), an xz-utils finding whose fix is pending (liblzma5), and
// a known-exploited kernel advisory that only lists linux-tools-common
// (kernel userland: perf tooling from the generic linux source, not the
// running kernel).
const (
	OldKernelHost     = "web-02"
	RebootPendingHost = "web-01"
	KernelOld         = "6.17.0-1009-aws"
	KernelNew         = "7.0.0-1014-aws"
	KernelKEVs        = 4
)

// KernelKEVCVEs are the known-exploited CVEs on the 6.17 kernel.
// UserlandKEVCVE is known-exploited too, but only on linux-tools-common.
var KernelKEVCVEs = []string{"CVE-2026-31001", "CVE-2026-31002", "CVE-2026-31003", "CVE-2026-31010"}

const UserlandKEVCVE = "CVE-2026-35001"

var (
	aws617 = []string{"linux-aws-6.17-headers-6.17.0-1009", "linux-aws-6.17-tools-6.17.0-1009", "linux-headers-6.17.0-1009-aws",
		"linux-modules-6.17.0-1009-aws", "linux-tools-6.17.0-1009-aws"}
	aws70 = []string{"linux-aws-7.0-headers-7.0.0-1014", "linux-aws-7.0-tools-7.0.0-1014", "linux-headers-7.0.0-1014-aws",
		"linux-modules-7.0.0-1014-aws", "linux-tools-7.0.0-1014-aws"}
)

// KernelCaseFindings are the findings both hosts get.
var KernelCaseFindings = []store.Finding{
	{AdvisoryID: "UBUNTU-CVE-2026-31001", Package: "linux-aws-6.17", Version: "6.17.0-1009.9~24.04.1", FixedVersion: "6.17.0-1012.12~24.04.1", Binaries: aws617},
	{AdvisoryID: "UBUNTU-CVE-2026-31002", Package: "linux-aws-6.17", Version: "6.17.0-1009.9~24.04.1", FixedVersion: "6.17.0-1012.12~24.04.1", Binaries: aws617},
	{AdvisoryID: "UBUNTU-CVE-2026-31003", Package: "linux-aws-6.17", Version: "6.17.0-1009.9~24.04.1", FixedVersion: "6.17.0-1012.12~24.04.1", Binaries: aws617},
	{AdvisoryID: "UBUNTU-CVE-2026-31010", Package: "linux-signed-aws-6.17", Version: "6.17.0-1009.9~24.04.1", FixedVersion: "6.17.0-1012.12~24.04.1",
		Binaries: []string{"linux-image-6.17.0-1009-aws"}},
	{AdvisoryID: "UBUNTU-CVE-2026-32001", Package: "linux-aws-7.0", Version: "7.0.0-1014.14~24.04.1", Binaries: aws70},
	{AdvisoryID: "UBUNTU-CVE-2026-33001", Package: "openssl", Version: "3.0.13-0ubuntu3.16", FixedVersion: "3.0.13-0ubuntu3.17",
		Binaries: []string{"libssl3t64"}},
	{AdvisoryID: "UBUNTU-CVE-2026-34001", Package: "xz-utils", Version: "5.6.1+really5.4.5-1ubuntu0.3", FixedVersion: "5.6.1+really5.4.5-1ubuntu0.4",
		Binaries: []string{"liblzma5"}, FixPending: true},
	{AdvisoryID: "UBUNTU-" + UserlandKEVCVE, Package: "linux", Version: "6.8.0-87.88", FixedVersion: "6.8.0-88.89",
		Binaries: []string{"linux-tools-common"}},
}

var kernelCaseSeverity = map[string]string{
	"UBUNTU-CVE-2026-31001": "high", "UBUNTU-CVE-2026-31002": "high", "UBUNTU-CVE-2026-31003": "critical", "UBUNTU-CVE-2026-31010": "high",
	"UBUNTU-CVE-2026-32001": "medium", "UBUNTU-CVE-2026-33001": "medium", "UBUNTU-CVE-2026-34001": "high",
	"UBUNTU-" + UserlandKEVCVE: "high",
}

// KernelCaseSnapshot is one case's snapshot JSON, collected at now.
func KernelCaseSnapshot(t testing.TB, host string, now time.Time) []byte {
	t.Helper()
	name := map[string]string{OldKernelHost: "ubuntu2404-aws-old-kernel.json", RebootPendingHost: "ubuntu2404-aws-reboot-pending.json"}[host]
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "snapshot", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	snap["collected_at"] = now.UTC().Format(time.RFC3339)
	raw, _ = json.Marshal(snap)
	return raw
}

// SeedKernelCases adds both hosts to org (which must exist, environment
// "prod" is created) with their snapshots, advisories, KEV entries and
// findings, and returns them (web-02, web-01).
func SeedKernelCases(t testing.TB, st *store.Store, org string, now time.Time) (fun, local store.IngestHost) {
	t.Helper()
	ctx := t.Context()
	st.CreateEnv(ctx, "test", org, "prod", "")
	for id, sev := range kernelCaseSeverity {
		cve := id[len("UBUNTU-"):]
		if err := st.PutAdvisory(ctx, store.Advisory{ID: id, Modified: now, Severity: sev, Summary: "Test advisory " + cve,
			Raw: []byte(`{}`), Aliases: []string{cve}}); err != nil {
			t.Fatal(err)
		}
	}
	var kev []store.KEVEntry
	for _, c := range append(KernelKEVCVEs, UserlandKEVCVE) {
		kev = append(kev, store.KEVEntry{CVE: c, DateAdded: now})
	}
	if err := st.ReplaceKEV(ctx, kev); err != nil {
		t.Fatal(err)
	}
	var hosts []store.IngestHost
	for _, name := range []string{OldKernelHost, RebootPendingHost} {
		if _, _, err := st.AddHost(ctx, "test", org, "prod", name, nil); err != nil {
			t.Fatal(err)
		}
		h, err := st.HostByName(ctx, org, name)
		if err != nil {
			t.Fatal(err)
		}
		raw := KernelCaseSnapshot(t, name, now)
		snap, err := snapshot.DecodeBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.SaveReport(ctx, store.NewSnapshot{Host: h, Source: "push", ReceivedAt: now, PayloadSHA256: sha256.Sum256(raw),
			Snapshot: snap}, nil); err != nil {
			t.Fatal(err)
		}
		fs := make([]store.Finding, len(KernelCaseFindings))
		for i, f := range KernelCaseFindings {
			f.Ecosystem = "Ubuntu:24.04:LTS"
			fs[i] = f
		}
		if _, _, err := st.SetFindings(ctx, h.ID, fs, now); err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}
	return hosts[0], hosts[1]
}
