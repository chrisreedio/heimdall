// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"os"
	"slices"
	"testing"
	"time"
)

func TestInventoryHash(t *testing.T) {
	raw, err := os.ReadFile("testdata/debian12.json")
	if err != nil {
		t.Fatal(err)
	}
	load := func() *Snapshot {
		s, err := DecodeBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := load().InventoryHash()

	// Volatile: a later run of an unchanged host hashes the same, whatever
	// order the package manager printed in.
	s := load()
	s.CollectedAt = s.CollectedAt.Add(time.Hour)
	s.UptimeSeconds += 3600
	slices.Reverse(s.Packages)
	if s.InventoryHash() != base {
		t.Error("collected_at, uptime or package order changed the hash")
	}

	for name, change := range map[string]func(*Snapshot){
		"package version": func(s *Snapshot) { s.Packages[0].Version += "+1" },
		"package removed": func(s *Snapshot) { s.Packages = s.Packages[1:] },
		"pending update":  func(s *Snapshot) { s.Updates = append(s.Updates, Update{Name: "curl", Version: "9"}) },
		"kernel":          func(s *Snapshot) { s.Kernel.Release = "6.1.0-99-amd64" },
		"collector sha":   func(s *Snapshot) { s.Collector.SHA256 = "00" + s.Collector.SHA256[2:] },
		"reboot flag": func(s *Snapshot) {
			b := s.RebootRequired == nil || !*s.RebootRequired
			s.RebootRequired = &b
		},
		"os": func(s *Snapshot) { s.OS.VersionID = "13" },
	} {
		s := load()
		change(s)
		if s.InventoryHash() == base {
			t.Errorf("%s didn't change the hash", name)
		}
	}
}
