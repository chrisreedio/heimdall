// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"regexp"
	"slices"

	"github.com/realmwatch/heimdall/internal/kernel"
	"github.com/realmwatch/heimdall/internal/store"
)

// Pkgs is a host's installed OS packages: name → whether the collector saw
// a pending update for it. The collector reads the package manager's
// existing metadata cache (apt-get -s dist-upgrade, dnf -C check-update,
// apk version) and never refreshes it, so "no pending update" can also
// mean the cache is old.
type Pkgs map[string]bool

// PackagesOf is the inventory's OS packages with their pending updates.
func PackagesOf(inv store.HostInventory) Pkgs {
	m := make(Pkgs, len(inv.Packages))
	for _, p := range inv.Packages {
		m[p.Name] = m[p.Name] || p.PendingVersion != ""
	}
	return m
}

var safePackage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// Upgrade is how upgrading clears a set of OS findings. The host page's
// patch command and the AI facts' suggested commands are both built from
// it, so they always agree.
type Upgrade struct {
	// Names are the packages to upgrade, in the order the findings came:
	// only ones with a pending update, so the command never names a
	// package apt (or dnf, or apk) has nothing newer for.
	Names []string
	// Metas are the Debian/Ubuntu kernel metapackages among Names. They're
	// added only when they have a pending update themselves, and never
	// for findings a reboot clears.
	Metas []string
	// FullUpgrade: a Debian/Ubuntu kernel fix on a host with no kernel
	// metapackage, so the command is kernel.DpkgFullUpgrade instead.
	FullUpgrade bool
	// Kernel: the upgrade installs a kernel fix, so it needs a reboot.
	Kernel bool
	// NamesFixPending counts Names that come from a finding whose fixed
	// version a pending update reaches.
	NamesFixPending int
	// RebootFindings are on the running kernel while a newer one is
	// installed (kernel.StatusRebootPending): a reboot clears them, with
	// or without a fix released.
	RebootFindings int
	// NotInCache counts findings with a published fix that no pending
	// update installs: fixed upstream, not (yet) offered by the host's
	// package sources, or the cache the collector read is old.
	NotInCache int
}

// PlanUpgrade works out the upgrade for OS findings (site findings are
// skipped). pkgs is the host's installed packages; findings on old
// kernels that aren't running are left to the removal command.
func PlanUpgrade(pm string, list []Finding, pkgs Pkgs) Upgrade {
	var u Upgrade
	has := func(n string) bool { _, ok := pkgs[n]; return ok }
	var metas, pendingMetas []string
	if pm == "dpkg" {
		var all []string
		for n := range pkgs {
			if safePackage.MatchString(n) {
				all = append(all, n)
			}
		}
		metas = kernel.Metapackages(pm, all)
		for _, m := range metas {
			if pkgs[m] {
				pendingMetas = append(pendingMetas, m)
			}
		}
	}
	dpkgKernel := false
	add := func(n string, fixPending bool) {
		if !slices.Contains(u.Names, n) {
			u.Names = append(u.Names, n)
			if fixPending {
				u.NamesFixPending++
			}
		}
	}
	for _, f := range list {
		if f.Site != "" {
			continue
		}
		switch f.KernelStatus {
		case kernel.StatusNotRunning: // removing that kernel is the fix
			continue
		case kernel.StatusRebootPending:
			u.RebootFindings++
			continue
		}
		if f.Fixed == "" {
			continue
		}
		bins, isKernel := kernel.Split(pm, f.Binaries, f.Package, has)
		added := false
		for _, b := range bins {
			if pkgs[b] && safePackage.MatchString(b) {
				add(b, f.FixPending)
				added = true
			}
		}
		available := f.FixPending
		switch {
		case isKernel && pm == "dpkg":
			dpkgKernel = true
			// The fix arrives through the metapackage (or the full-upgrade
			// fallback when there's none).
			available = available || len(metas) == 0 || len(pendingMetas) > 0
		case isKernel && added:
			u.Kernel = true
		}
		if !available {
			u.NotInCache++
		}
	}
	if dpkgKernel {
		switch {
		case len(metas) == 0:
			u.FullUpgrade, u.Kernel = true, true
		case len(pendingMetas) > 0:
			u.Metas, u.Kernel = pendingMetas, true
			for _, m := range pendingMetas {
				add(m, false)
			}
		}
	}
	return u
}
