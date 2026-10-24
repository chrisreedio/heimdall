// SPDX-License-Identifier: AGPL-3.0-or-later

package osv

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

var fixtures = []string{
	"ALPINE-CVE-2024-12797.json", "ALSA-2024_0310.json", "DEBIAN-CVE-2023-5678.json",
	"GHSA-78fx-h6xr-vch4.json", "RLSA-2024_6783.json", "UBUNTU-CVE-2023-2975.json",
}

// comparable clears what Slim drops by design.
func comparable(v *Vuln) *Vuln {
	c := *v
	if len(c.DatabaseSpecific) > 0 { // re-encoding compacts it
		var buf bytes.Buffer
		if err := json.Compact(&buf, c.DatabaseSpecific); err == nil {
			c.DatabaseSpecific = buf.Bytes()
		}
	}
	c.Affected = nil
	for _, a := range v.Affected {
		a.Versions, a.DatabaseSpecific, a.EcosystemSpecific = nil, nil, nil
		c.Affected = append(c.Affected, a)
	}
	return &c
}

func TestSlimKeepsEverythingHeimdallReads(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			raw := fixture(t, name)
			slim, err := Slim(raw)
			if err != nil {
				t.Fatal(err)
			}
			full, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(slim)
			if err != nil {
				t.Fatalf("slim record doesn't parse: %v", err)
			}
			if !reflect.DeepEqual(comparable(full), comparable(got)) {
				t.Errorf("parsed records differ:\nfull %+v\nslim %+v", comparable(full), comparable(got))
			}
			if a, b := full.DistroRating(), got.DistroRating(); a != b {
				t.Errorf("DistroRating %q, slim %q", a, b)
			}
			if a, b := full.CVEs(), got.CVEs(); !reflect.DeepEqual(a, b) {
				t.Errorf("CVEs %v, slim %v", a, b)
			}
			for _, a := range full.Affected {
				eco, pkg := a.Package.Ecosystem, a.Package.Name
				if x, y := full.FixedVersions(eco, pkg), got.FixedVersions(eco, pkg); !reflect.DeepEqual(x, y) {
					t.Errorf("FixedVersions(%s, %s) = %v, slim %v", eco, pkg, x, y)
				}
			}
			if len(slim) > len(raw) {
				t.Errorf("slim is %d bytes, raw %d", len(slim), len(raw))
			}
			// Slimming twice changes nothing.
			again, err := Slim(slim)
			if err != nil || string(again) != string(slim) {
				t.Errorf("Slim isn't idempotent: %v\n%s\n%s", err, slim, again)
			}
		})
	}
}

func TestSlimDropsBulkKeepsReferences(t *testing.T) {
	raw := fixture(t, "UBUNTU-CVE-2023-2975.json")
	slim, err := Slim(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{`"versions"`, `"binaries"`, `"purl"`} {
		if strings.Contains(string(raw), gone) && strings.Contains(string(slim), gone) {
			t.Errorf("slim record still has %s", gone)
		}
	}
	var w struct {
		References []struct{ URL string } `json:"references"`
		Details    string                 `json:"details"`
	}
	var r struct {
		References []struct{ URL string } `json:"references"`
	}
	json.Unmarshal(slim, &w)
	json.Unmarshal(raw, &r)
	if len(r.References) == 0 || !reflect.DeepEqual(w.References, r.References) || w.Details == "" {
		t.Errorf("references or details lost: %d vs %d refs", len(w.References), len(r.References))
	}

	// Debian keeps its urgency next to what's dropped.
	es := dropKey(json.RawMessage(`{"urgency":"high","binaries":[{"binary_name":"x"}]}`), "binaries")
	if string(es) != `{"urgency":"high"}` {
		t.Errorf("dropKey = %s", es)
	}
	if es := dropKey(json.RawMessage(`{"binaries":[]}`), "binaries"); es != nil {
		t.Errorf("empty object kept: %s", es)
	}
	if es := dropKey(json.RawMessage(`[1]`), "binaries"); string(es) != `[1]` {
		t.Errorf("non-object changed: %s", es)
	}
}

func TestSlimRejectsBadRecords(t *testing.T) {
	for _, raw := range []string{`not json`, `{"id":"../etc"}`, `{"id":""}`} {
		if _, err := Slim([]byte(raw)); err == nil {
			t.Errorf("Slim(%s) succeeded", raw)
		}
	}
}
