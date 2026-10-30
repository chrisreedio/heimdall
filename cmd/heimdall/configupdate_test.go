// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
)

// oldConfig writes the current template minus the named sections.
func oldConfig(t *testing.T, path, database string, drop ...string) string {
	t.Helper()
	out := strings.Replace(string(config.Template("heimdall.db")), `database = "heimdall.db"`, "database = "+strconv.Quote(database), 1)
	out = "# my hub, my comments\n" + strings.Replace(out, `session_idle = "30m"`, `session_idle = "45m"   # longer`, 1)
	for _, s := range config.TemplateSections() {
		for _, d := range drop {
			if s.Name == d {
				out = strings.Replace(out, s.Text+"\n", "", 1)
			}
		}
	}
	if err := os.WriteFile(path, []byte(out), 0o640); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConfigUpdate(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	old := oldConfig(t, c.config, "heimdall.db", "news", "ai", "notify")

	out, errOut, err := c.run("config", "update", "--dry-run")
	if err != nil || !strings.Contains(errOut, "would add [news], [notify], [ai] (off)") || !strings.Contains(out, "[ai]\n") {
		t.Fatalf("dry run: %v\n%s\n%s", err, errOut, out)
	}
	if b, _ := os.ReadFile(c.config); string(b) != old {
		t.Fatal("dry run changed the file")
	}

	_, errOut, err = c.run("config", "update")
	if err != nil || !strings.Contains(errOut, "config: added [news], [notify], [ai] (off)") {
		t.Fatalf("update: %v\n%s", err, errOut)
	}
	b, _ := os.ReadFile(c.config)
	if !strings.HasPrefix(string(b), old) {
		t.Fatal("existing content changed")
	}
	cfg, err := config.Load(c.config)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AI.Enabled || cfg.News.Enabled || cfg.UI.SessionIdle.Minutes() != 45 {
		t.Errorf("loaded: ai %v news %v idle %v", cfg.AI.Enabled, cfg.News.Enabled, cfg.UI.SessionIdle)
	}
	if bak, _ := os.ReadFile(c.config + ".pre-upgrade"); string(bak) != old {
		t.Error("backup is not the old file")
	}
	for _, p := range []string{c.config, c.config + ".pre-upgrade"} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
			t.Errorf("%s mode %04o", p, fi.Mode().Perm())
		}
	}

	// Idempotent: nothing more to add, file and backup untouched.
	if _, errOut, _ := c.run("config", "update"); !strings.Contains(errOut, "up to date") {
		t.Errorf("second run: %s", errOut)
	}
	if b2, _ := os.ReadFile(c.config); string(b2) != string(b) {
		t.Error("second run changed the file")
	}
}

func TestConfigUpdateUpToDate(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.init()
	before, _ := os.ReadFile(c.config)
	c.ok("config", "update")
	after, _ := os.ReadFile(c.config)
	if string(before) != string(after) {
		t.Error("up-to-date config changed")
	}
	if _, err := os.Stat(c.config + ".pre-upgrade"); err == nil {
		t.Error("backup written with nothing to add")
	}
}

func TestConfigUpdateInvalidLeavesFile(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	old := oldConfig(t, c.config, "heimdall.db", "ai")
	old += "bogus = 1\n" // an unknown key: the result won't load
	os.WriteFile(c.config, []byte(old), 0o640)
	if _, _, err := c.run("config", "update"); err == nil || !strings.Contains(err.Error(), "left unchanged") {
		t.Fatalf("want a load error, got %v", err)
	}
	if b, _ := os.ReadFile(c.config); string(b) != old {
		t.Error("file changed")
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(c.config), ".tmp-*")); len(m) > 0 {
		t.Errorf("temp files left: %v", m)
	}
}

func TestMigrateUpdatesConfig(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.init()
	oldConfig(t, c.config, "heimdall.db", "news", "ai")
	_, errOut, err := c.run("migrate")
	if err != nil || !strings.Contains(errOut, "config: added [news], [ai] (off)\n") {
		t.Fatalf("migrate: %v\n%s", err, errOut)
	}
}

func TestMigrateUnwritableConfigHints(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	c := newCLI(t)
	other := newCLI(t)
	other.init()
	db := filepath.Join(filepath.Dir(other.config), "heimdall.db")
	old := oldConfig(t, c.config, db, "ai")
	dir := filepath.Dir(c.config)
	os.Chmod(dir, 0o555)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	_, errOut, err := c.run("migrate")
	if err != nil || !strings.Contains(errOut, "run: sudo heimdall config update") {
		t.Fatalf("migrate: %v\n%s", err, errOut)
	}
	if b, _ := os.ReadFile(c.config); string(b) != old {
		t.Error("file changed")
	}
	if _, _, err := c.run("config", "update"); err == nil || !strings.Contains(err.Error(), "sudo heimdall config update") {
		t.Errorf("config update: %v", err)
	}
}
