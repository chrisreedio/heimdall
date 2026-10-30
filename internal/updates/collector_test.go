// SPDX-License-Identifier: AGPL-3.0-or-later

package updates

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// collectorSum is collectorDigest at CollectorChanged.
const collectorSum = "b6ade890b13d4c98e5fd50d8de0fc7e30d8cda303e9c4ddce31c08e612078ace"

// versionLine is a collector script's version number, which every release
// changes.
var versionLine = regexp.MustCompile(`(?m)^(VERSION=|\$script:CollectorVersion = ).*\n`)

// collectorDigest hashes collector/ (but its tests) without the version
// lines, in path order.
func collectorDigest(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	root := filepath.Join("..", "..", "collector")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "test" {
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		h.Write([]byte(filepath.ToSlash(rel) + "\x00"))
		h.Write(versionLine.ReplaceAll(b, nil))
		h.Write([]byte{0})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestCollectorChanged(t *testing.T) {
	t.Parallel()
	if got := collectorDigest(t); got != collectorSum {
		t.Fatalf("collector/ changed: set CollectorChanged (collector.go) to the release it ships in, "+
			"the VERSION collector/collect.sh will have, and collectorSum to %s", got)
	}
}

func TestCollectorBehind(t *testing.T) {
	t.Parallel()
	at := strings.TrimPrefix(CollectorChanged, "v")
	for v, want := range map[string]bool{"0.4.41": true, "v0.4.48": true, at: false, "v" + at: false, "v99.0.0": false, "dev": false, "": false} {
		if got := CollectorBehind(v); got != want {
			t.Errorf("CollectorBehind(%q) = %v, want %v", v, got, want)
		}
	}
}
