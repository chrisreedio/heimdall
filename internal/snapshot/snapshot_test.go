// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeExamples(t *testing.T) {
	for _, name := range []string{"debian12.json", "alpine320.json"} {
		t.Run(name, func(t *testing.T) {
			s, err := DecodeBytes(load(t, name))
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Packages) == 0 || s.Collector.Version != "0.1.0" {
				t.Errorf("decoded %+v", s)
			}
		})
	}
}

func TestDecodeRejectsStructuralProblems(t *testing.T) {
	valid := load(t, "debian12.json")
	tests := map[string][]byte{
		"unknown field":  bytes.Replace(valid, []byte(`"uptime_seconds"`), []byte(`"evil": 1, "uptime_seconds"`), 1),
		"nested unknown": bytes.Replace(valid, []byte(`"arch": "x86_64" }`), []byte(`"arch": "x86_64", "x": 1 }`), 1),
		"trailing data":  append(bytes.Clone(valid), []byte(`{}`)...),
		"two documents":  append(bytes.Clone(valid), valid...),
		"not json":       []byte("<html>"),
		"empty":          nil,
		"wrong type":     bytes.Replace(valid, []byte(`"uptime_seconds": 1209600`), []byte(`"uptime_seconds": "1"`), 1),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBytes(in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// mutate decodes the Debian example, applies fn, and re-encodes it.
func mutate(t *testing.T, fn func(*Snapshot)) []byte {
	t.Helper()
	var s Snapshot
	if err := json.Unmarshal(load(t, "debian12.json"), &s); err != nil {
		t.Fatal(err)
	}
	fn(&s)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidateRejectsBadValues(t *testing.T) {
	no := false
	tests := []struct {
		name  string
		fn    func(*Snapshot)
		field string
	}{
		{"wrong format", func(s *Snapshot) { s.Format = "heimdall.snapshot/v9" }, "format"},
		{"bad collector version", func(s *Snapshot) { s.Collector.Version = "latest" }, "collector.version"},
		{"uppercase sha", func(s *Snapshot) { s.Collector.SHA256 = strings.ToUpper(s.Collector.SHA256) }, "collector.sha256"},
		{"missing collected_at", func(s *Snapshot) { s.CollectedAt = s.CollectedAt.AddDate(-2026, 0, 0) }, "collected_at"},
		{"os id with space", func(s *Snapshot) { s.OS.ID = "debian linux" }, "os.id"},
		{"markup in pretty name", func(s *Snapshot) { s.OS.PrettyName = "Debian\x1b[2J" }, "os.pretty_name"},
		{"html in kernel", func(s *Snapshot) { s.Kernel.Release = "<script>alert(1)</script>" }, "kernel.release"},
		{"missing arch", func(s *Snapshot) { s.Kernel.Arch = "" }, "kernel.arch"},
		{"negative uptime", func(s *Snapshot) { s.UptimeSeconds = -1 }, "uptime_seconds"},
		{"unknown package manager", func(s *Snapshot) { s.PackageManager = "pip" }, "package_manager"},
		{"shell in package name", func(s *Snapshot) { s.Packages[0].Name = "openssl;rm -rf /" }, "packages[0].name"},
		{"space in version", func(s *Snapshot) { s.Packages[1].Version = "3.0 beta" }, "packages[1].version"},
		{"duplicate package", func(s *Snapshot) { s.Packages = append(s.Packages, s.Packages[0]) }, "packages[4]"},
		{"no packages undeclared", func(s *Snapshot) { s.Packages = nil }, "packages"},
		{"too many packages", func(s *Snapshot) { s.Packages = make([]Package, MaxPackages+1) }, "packages"},
		{"bad update", func(s *Snapshot) { s.Updates[0].Version = "" }, "updates[0].version"},
		{"unknown check", func(s *Snapshot) { s.Unavailable = []string{"firewall"} }, "unavailable[0]"},
		{"reboot null undeclared", func(s *Snapshot) { s.RebootRequired = nil }, "reboot_required"},
		{"reboot set but declared unavailable", func(s *Snapshot) {
			s.RebootRequired = &no
			s.Unavailable = []string{"reboot_required"}
		}, "reboot_required"},
		{"updates present but declared unavailable", func(s *Snapshot) { s.Unavailable = []string{"updates"} }, "updates"},
		{"missing sha undeclared", func(s *Snapshot) { s.Collector.SHA256 = "" }, "collector.sha256"},
		{"sha present but declared unavailable", func(s *Snapshot) { s.Unavailable = []string{"collector_sha256"} }, "collector.sha256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBytes(mutate(t, tt.fn))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.field+":") {
				t.Errorf("error should name %s, got: %v", tt.field, err)
			}
		})
	}
}

func TestErrorsAreBounded(t *testing.T) {
	b := mutate(t, func(s *Snapshot) {
		for i := range s.Packages {
			s.Packages[i].Name = "bad name"
		}
		for range 100 {
			s.Packages = append(s.Packages, Package{Name: "x y", Version: "1", Arch: "all"})
		}
	})
	_, err := DecodeBytes(b)
	if err == nil {
		t.Fatal("expected error")
	}
	if n := strings.Count(err.Error(), "\n") + 1; n > 20 {
		t.Errorf("%d error lines; should be capped at 20", n)
	}
}

func TestPackagesUnavailableIsAllowed(t *testing.T) {
	b := mutate(t, func(s *Snapshot) {
		s.Packages, s.Updates = nil, nil
		s.Unavailable = []string{"packages", "updates"}
	})
	if _, err := DecodeBytes(b); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorSHAUnavailableIsAllowed(t *testing.T) {
	b := mutate(t, func(s *Snapshot) {
		s.Collector.SHA256 = ""
		s.Unavailable = []string{"collector_sha256"}
	})
	if _, err := DecodeBytes(b); err != nil {
		t.Fatal(err)
	}
}
