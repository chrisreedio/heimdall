// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"

	"github.com/BurntSushi/toml"
)

// Section is one [table] of the config template: its header line and the
// comment and key lines up to the next header.
type Section struct {
	Name string // e.g. "auth.entra"
	Text string // verbatim, without trailing blank lines
}

// templateSections splits t into its [table] sections, in order. Lines
// before the first header (root keys) and [[array]] sections are skipped:
// arrays of tables are entries, not settings, and are never appended.
func templateSections(t string) []Section {
	var out []Section
	var cur *Section
	var lines []string
	flush := func() {
		if cur != nil {
			cur.Text = strings.TrimRight(strings.Join(lines, "\n"), "\n \t")
			out = append(out, *cur)
		}
		cur, lines = nil, nil
	}
	skipping := false
	for _, l := range strings.Split(t, "\n") {
		s := strings.TrimSpace(l)
		if strings.HasPrefix(s, "[") && !strings.Contains(s, "=") {
			flush()
			skipping = strings.HasPrefix(s, "[[")
			if !skipping {
				name := strings.TrimSpace(strings.Trim(strings.SplitN(s, "#", 2)[0], " \t[]"))
				cur = &Section{Name: name}
			}
		}
		if cur != nil {
			lines = append(lines, l)
		}
	}
	flush()
	return out
}

// TemplateSections returns the default template's [table] sections.
func TemplateSections() []Section { return templateSections(defaultTemplate) }

// MissingSections returns the template sections (features added since the
// file was written) that src doesn't have, in template order. A subtable is
// returned only when its parent is present or returned too. Sections that
// would be turned on (enabled = true) are never returned.
func MissingSections(src []byte) ([]Section, error) {
	var v map[string]any
	md, err := toml.Decode(string(src), &v)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, k := range md.Keys() {
		for i := 1; i <= len(k); i++ {
			have[strings.Join(k[:i], ".")] = true
		}
	}
	var out []Section
	for _, s := range TemplateSections() {
		if have[s.Name] || !sectionOff(s) {
			continue
		}
		if i := strings.LastIndex(s.Name, "."); i >= 0 && !have[s.Name[:i]] {
			continue
		}
		have[s.Name] = true
		out = append(out, s)
	}
	return out, nil
}

// sectionOff reports whether s, decoded on its own, has no enabled key or
// enabled = false.
func sectionOff(s Section) bool {
	var v map[string]any
	if _, err := toml.Decode(s.Text, &v); err != nil {
		return false
	}
	t := v
	for _, part := range strings.Split(s.Name, ".") {
		next, ok := t[part].(map[string]any)
		if !ok {
			return false
		}
		t = next
	}
	e, has := t["enabled"]
	return !has || e == false
}

// AppendSections returns src with secs appended after one marker comment,
// leaving the existing content exactly as it was.
func AppendSections(src []byte, secs []Section, version string) []byte {
	if len(secs) == 0 {
		return src
	}
	var b strings.Builder
	b.Write(src)
	if len(src) > 0 && !strings.HasSuffix(string(src), "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n# Added by heimdall " + version + ": new features, off until you turn them on.\n")
	for i, s := range secs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(s.Text + "\n")
	}
	return []byte(b.String())
}
