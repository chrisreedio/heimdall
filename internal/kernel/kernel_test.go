// SPDX-License-Identifier: AGPL-3.0-or-later

package kernel

import (
	"slices"
	"testing"
)

func TestABIAndMetapackages(t *testing.T) {
	for _, c := range []struct {
		name      string
		abi, meta bool
	}{
		{"linux-image-6.17.0-1009-aws", true, false},
		{"linux-aws-6.17-headers-6.17.0-1009", true, false},
		{"linux-tools-6.17.0-1009-aws", true, false},
		{"linux-modules-6.17.0-1009-aws", true, false},
		{"linux-hwe-6.11-headers-6.11.0-29", true, false},
		{"linux-modules-nvidia-550-6.8.0-45-generic", true, false},
		{"linux-image-6.1.0-26-amd64", true, false},
		{"linux-headers-6.1.0-26-common", true, false},
		{"linux-aws", false, true},
		{"linux-image-aws", false, true},
		{"linux-headers-aws", false, true},
		{"linux-tools-aws", false, true},
		{"linux-generic", false, true},
		{"linux-image-generic", false, true},
		{"linux-virtual", false, true},
		{"linux-generic-hwe-24.04", false, true},
		{"linux-image-generic-hwe-24.04", false, true},
		{"linux-oem-24.04b", false, true},
		{"linux-image-amd64", false, true},
		{"linux-image-cloud-amd64", false, true},
		{"linux-headers-amd64", false, true},
		{"linux-tools-common", false, false},
		{"linux-libc-dev", false, false},
		{"linux-firmware", false, false},
		{"linux-kbuild-6.1", false, false},
		{"linux-aws-6.17", false, true}, // a source name; Split checks it isn't installed
		{"openssl", false, false},
	} {
		if got := ABIPackage("dpkg", c.name); got != c.abi {
			t.Errorf("ABIPackage(%q) = %v", c.name, got)
		}
		if got := len(Metapackages("dpkg", []string{c.name})) == 1; got != c.meta {
			t.Errorf("metapackage %q = %v", c.name, got)
		}
		if ABIPackage("rpm", c.name) || Metapackages("rpm", []string{c.name}) != nil {
			t.Errorf("%q: only dpkg has ABI-named kernels", c.name)
		}
	}
}

func TestPackage(t *testing.T) {
	for _, c := range []struct {
		pm, name string
		want     bool
	}{
		{"dpkg", "linux", true}, {"dpkg", "linux-aws-6.17", true}, {"dpkg", "linux-signed-generic", true},
		{"dpkg", "linux-firmware", false}, {"dpkg", "linux-libc-dev", false}, {"dpkg", "linux-base", false},
		{"rpm", "kernel", true}, {"rpm", "kernel-core", true}, {"rpm", "kernel-modules-core", true}, {"rpm", "kernel-uek", true},
		{"rpm", "kernel-headers", false}, {"rpm", "kernel-tools-libs", false}, {"rpm", "kernel-devel", false}, {"rpm", "kernelshark", false},
		{"apk", "linux-lts", true}, {"apk", "linux-virt", true}, {"apk", "linux-pam", false}, {"apk", "linux-firmware-none", false},
		{"apk", "linux-headers", false},
		{"pacman", "linux", false},
	} {
		if got := Package(c.pm, c.name); got != c.want {
			t.Errorf("Package(%s, %q) = %v", c.pm, c.name, got)
		}
	}
}

func TestSplit(t *testing.T) {
	installed := func(names ...string) func(string) bool {
		return func(n string) bool { return slices.Contains(names, n) }
	}
	none := installed()
	for _, c := range []struct {
		name, pm, source string
		bins             []string
		has              func(string) bool
		want             []string
		kernel           bool
	}{
		{"ubuntu abi", "dpkg", "linux-aws-6.17",
			[]string{"linux-aws-6.17-headers-6.17.0-1009", "linux-tools-6.17.0-1009-aws", "linux-modules-6.17.0-1009-aws"}, none, nil, true},
		{"ubuntu stable binaries kept", "dpkg", "linux", []string{"linux-image-6.8.0-45-generic", "linux-libc-dev", "linux-tools-common"},
			none, []string{"linux-libc-dev", "linux-tools-common"}, true},
		{"source only", "dpkg", "linux-aws-6.17", nil, none, nil, true},
		{"not a kernel", "dpkg", "openssl", []string{"libssl3", "openssl"}, none, []string{"libssl3", "openssl"}, false},
		{"firmware", "dpkg", "linux-firmware", nil, installed("linux-firmware"), []string{"linux-firmware"}, false},
		{"rocky", "rpm", "kernel", []string{"kernel", "kernel-core", "kernel-modules"}, none, []string{"kernel", "kernel-core", "kernel-modules"}, true},
		{"rocky headers", "rpm", "kernel", []string{"kernel-headers"}, none, []string{"kernel-headers"}, false},
		{"alpine", "apk", "linux-lts", []string{"linux-lts"}, none, []string{"linux-lts"}, true},
	} {
		got, k := Split(c.pm, c.bins, c.source, c.has)
		if !slices.Equal(got, c.want) || k != c.kernel {
			t.Errorf("%s: %v %v, want %v %v", c.name, got, k, c.want, c.kernel)
		}
	}
}

func TestNewest(t *testing.T) {
	for _, c := range []struct {
		name, pm string
		pkgs     []Installed
		want     string
	}{
		{"ubuntu aws", "dpkg", []Installed{
			{"linux-aws", "6.17.0.1019.19", "amd64"},
			{"linux-image-6.17.0-1009-aws", "6.17.0-1009.9~24.04.1", "amd64"},
			{"linux-image-6.17.0-1019-aws", "6.17.0-1019.19~24.04.1", "amd64"},
			{"linux-modules-6.17.0-1019-aws", "6.17.0-1019.19~24.04.1", "amd64"},
		}, "6.17.0-1019-aws"},
		{"version order, not name order", "dpkg", []Installed{
			{"linux-image-6.8.0-100-generic", "6.8.0-100.100", "amd64"},
			{"linux-image-6.8.0-99-generic", "6.8.0-99.99", "amd64"},
		}, "6.8.0-100-generic"},
		{"unsigned", "dpkg", []Installed{{"linux-image-unsigned-6.8.0-45-generic", "6.8.0-45.45", "amd64"}}, "6.8.0-45-generic"},
		{"debian", "dpkg", []Installed{
			{"linux-image-amd64", "6.1.115-1", "amd64"},
			{"linux-image-6.1.0-26-amd64", "6.1.112-1", "amd64"},
			{"linux-image-6.1.0-27-amd64", "6.1.115-1", "amd64"},
		}, "6.1.0-27-amd64"},
		{"no kernel package", "dpkg", []Installed{{"linux-image-generic", "6.8.0.45.45", "amd64"}, {"openssl", "3.0", "amd64"}}, ""},
		{"rocky", "rpm", []Installed{
			{"kernel-core", "5.14.0-427.13.1.el9_4", "x86_64"},
			{"kernel-core", "5.14.0-503.14.1.el9_5", "x86_64"},
			{"kernel-headers", "5.14.0-611.1.1.el9_6", "x86_64"},
		}, "5.14.0-503.14.1.el9_5.x86_64"},
		{"alpine", "apk", []Installed{{"linux-lts", "6.6.52-r0", "x86_64"}, {"linux-pam", "1.6.1-r0", "x86_64"}}, "6.6.52-0-lts"},
		{"alpine virt", "apk", []Installed{{"linux-virt", "6.12.13-r1", "x86_64"}}, "6.12.13-1-virt"},
	} {
		if got := Newest(c.pm, c.pkgs); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
