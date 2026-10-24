// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

// oldTemplate is the current template without the named sections, as a
// hub installed before those features would have it.
func oldTemplate(t *testing.T, drop ...string) string {
	t.Helper()
	out := string(Template("heimdall.db"))
	for _, s := range TemplateSections() {
		for _, d := range drop {
			if s.Name == d {
				if !strings.Contains(out, s.Text+"\n") {
					t.Fatalf("section [%s] not found verbatim", d)
				}
				out = strings.Replace(out, s.Text+"\n", "", 1)
			}
		}
	}
	return out
}

func names(secs []Section) string {
	var n []string
	for _, s := range secs {
		n = append(n, s.Name)
	}
	return strings.Join(n, ",")
}

// Every section that could be appended to a hub's config must be off.
func TestTemplateSectionsAreOff(t *testing.T) {
	secs := TemplateSections()
	if len(secs) < 10 {
		t.Fatalf("only %d sections parsed: %s", len(secs), names(secs))
	}
	for _, s := range secs {
		if !sectionOff(s) {
			t.Errorf("[%s] is not off (enabled must be false when present):\n%s", s.Name, s.Text)
		}
		if strings.Contains(s.Text, "\n[[") || strings.HasPrefix(s.Text, "[[") {
			t.Errorf("[%s] contains an array-of-tables entry", s.Name)
		}
	}
}

func TestTemplateSectionsSkipArrays(t *testing.T) {
	got := templateSections("a = 1\n[x]\nk = 1\n\n[[agents]]\nname = \"n\"\n\n[y.z] # c\nenabled = false\n")
	if names(got) != "x,y.z" || got[0].Text != "[x]\nk = 1" {
		t.Fatalf("got %q", got)
	}
}

func TestMissingSectionsOldConfig(t *testing.T) {
	old := oldTemplate(t, "news", "ai", "notify")
	secs, err := MissingSections([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if names(secs) != "news,notify,ai" {
		t.Fatalf("missing = %s", names(secs))
	}
	out := AppendSections([]byte(old), secs, "v9.9.9")
	if !strings.HasPrefix(string(out), old) {
		t.Fatal("existing content changed")
	}
	if !strings.Contains(string(out), "\n# Added by heimdall v9.9.9: new features, off until you turn them on.\n[news]\n") {
		t.Errorf("marker missing:\n%s", out[len(old):])
	}
	cfg, err := parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.AI.Enabled || cfg.News.Enabled {
		t.Error("appended sections must be off")
	}
	again, err := MissingSections(out)
	if err != nil || len(again) != 0 {
		t.Errorf("second run adds %s (%v)", names(again), err)
	}
}

func TestMissingSectionsUpToDate(t *testing.T) {
	src := Template("heimdall.db")
	secs, err := MissingSections(src)
	if err != nil || len(secs) != 0 {
		t.Fatalf("up-to-date config: %s (%v)", names(secs), err)
	}
	if string(AppendSections(src, nil, "v1")) != string(src) {
		t.Error("changed")
	}
}

func TestMissingSubtables(t *testing.T) {
	// No [auth] at all: both it and [auth.entra] come back, parent first.
	secs, _ := MissingSections([]byte(oldTemplate(t, "auth", "auth.entra")))
	if names(secs) != "auth,auth.entra" {
		t.Errorf("got %s", names(secs))
	}
	// [auth] via a dotted key counts as present; only the subtable is added.
	secs, _ = MissingSections([]byte("auth.local_login = true\n" + oldTemplate(t, "auth", "auth.entra")))
	if names(secs) != "auth.entra" {
		t.Errorf("got %s", names(secs))
	}
	// Existing [auth.entra] values are kept, nothing added.
	user := strings.Replace(string(Template("heimdall.db")), `client_id        = ""`, `client_id        = "abc" # mine`, 1)
	secs, _ = MissingSections([]byte(user))
	if len(secs) != 0 {
		t.Errorf("got %s", names(secs))
	}
}
