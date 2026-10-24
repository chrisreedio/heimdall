// SPDX-License-Identifier: AGPL-3.0-or-later

package kernel

import (
	"slices"
	"strings"
	"testing"
)

// Ubuntu 24.04 on AWS with the 6.17.0-1009 and 7.0.0-1014 kernels installed.
var awsBoth = []Installed{
	{Name: "linux-aws", Version: "7.0.0.1014.14~24.04.1"}, {Name: "linux-image-aws", Version: "7.0.0.1014.14~24.04.1"},
	{Name: "linux-image-6.17.0-1009-aws", Version: "6.17.0-1009.9~24.04.1"}, {Name: "linux-modules-6.17.0-1009-aws", Version: "6.17.0-1009.9~24.04.1"},
	{Name: "linux-aws-6.17-headers-6.17.0-1009", Version: "6.17.0-1009.9~24.04.1"},
	{Name: "linux-image-7.0.0-1014-aws", Version: "7.0.0-1014.14~24.04.1"}, {Name: "linux-modules-7.0.0-1014-aws", Version: "7.0.0-1014.14~24.04.1"},
	{Name: "linux-libc-dev", Version: "6.8.0-87.88"}, {Name: "openssl", Version: "3.0.13-0ubuntu3.16"},
}

var (
	bins617 = []string{"linux-modules-6.17.0-1009-aws", "linux-aws-6.17-headers-6.17.0-1009"}
	bins70  = []string{"linux-image-7.0.0-1014-aws", "linux-modules-7.0.0-1014-aws"}
)

func TestHostStateRebootPending(t *testing.T) {
	s := HostState("dpkg", "6.17.0-1009-aws", awsBoth)
	if s.Name() != StateRebootPending || s.Newer != "7.0.0-1014-aws" || len(s.Old) != 0 {
		t.Fatalf("state %q newer %q old %v", s.Name(), s.Newer, s.Old)
	}
	if want := []string{"linux-aws-6.17-headers-6.17.0-1009", "linux-image-6.17.0-1009-aws", "linux-modules-6.17.0-1009-aws"}; !slices.Equal(s.Boot, want) {
		t.Errorf("boot %v", s.Boot)
	}
	for bins, want := range map[*[]string]string{
		&bins617: StatusRebootPending, &bins70: StatusNewerKernel,
		{"openssl"}: "", {"linux-modules-6.17.0-1009-aws", "linux-libc-dev"}: StatusRunning,
	} {
		if got := s.Status(*bins); got != want {
			t.Errorf("Status(%v) = %q, want %q", *bins, got, want)
		}
	}
}

func TestHostStateOldKernels(t *testing.T) {
	s := HostState("dpkg", "7.0.0-1014-aws", awsBoth)
	if s.Name() != StateOldKernels || s.Newer != "" || len(s.Boot) != 0 || len(s.Old) != 3 {
		t.Fatalf("state %q newer %q old %v boot %v", s.Name(), s.Newer, s.Old, s.Boot)
	}
	if s.Status(bins617) != StatusNotRunning || s.Status(bins70) != StatusRunning {
		t.Errorf("statuses %q %q", s.Status(bins617), s.Status(bins70))
	}
	// Three kernels: older, running, newer.
	three := append(slices.Clone(awsBoth), Installed{Name: "linux-image-7.0.0-1020-aws", Version: "7.0.0-1020.20~24.04.1"})
	if s := HostState("dpkg", "7.0.0-1014-aws", three); s.Name() != StateRebootAndOldKernels || s.Newer != "7.0.0-1020-aws" ||
		s.Status(bins617) != StatusNotRunning || s.Status(bins70) != StatusRebootPending {
		t.Errorf("three kernels: %q %q", s.Name(), s.Newer)
	}
	if s := HostState("dpkg", "7.0.0-1014-aws", awsBoth[5:]); s.Name() != StateCurrent {
		t.Errorf("one kernel: %q", s.Name())
	}
	for _, s := range []State{HostState("rpm", "7.0.0-1014-aws", awsBoth), HostState("dpkg", "", awsBoth), HostState("dpkg", "weird", awsBoth)} {
		if s.Name() != "" || s.Status(bins617) != "" {
			t.Errorf("unknown state should say nothing: %+v", s)
		}
	}
}

func TestStatusUserland(t *testing.T) {
	s := HostState("dpkg", "7.0.0-1014-aws", []Installed{{Name: "linux-image-7.0.0-1014-aws", Version: "7.0.0-1014.14"}})
	for bins, want := range map[string]string{
		"linux-tools-common":                            StatusUserland,
		"linux-libc-dev":                                StatusUserland,
		"linux-source-6.8.0":                            StatusUserland,
		"linux-tools-common linux-libc-dev":             StatusUserland,
		"linux-tools-common linux-image-7.0.0-1014-aws": StatusRunning,
		"libssl3t64":                                    "",
	} {
		if got := s.Status(strings.Fields(bins)); got != want {
			t.Errorf("Status(%s) = %q, want %q", bins, got, want)
		}
	}
	// Known even when the running kernel isn't; never for other managers.
	if got := HostState("dpkg", "", nil).Status([]string{"linux-libc-dev"}); got != StatusUserland {
		t.Errorf("unknown running kernel: %q", got)
	}
	if got := HostState("rpm", "5.14.0-427.el9.x86_64", nil).Status([]string{"linux-libc-dev"}); got != "" {
		t.Errorf("rpm: %q", got)
	}
}
