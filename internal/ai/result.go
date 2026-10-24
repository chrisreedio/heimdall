// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Result is the validated, advisory-only output of a run.
type Result struct {
	Summary string   `json:"summary"`
	Actions []Action `json:"actions"`
	Notes   string   `json:"notes,omitempty"`
}

// Action is one suggested step. Command is set only when it passed the
// allowlist (see checkCommand); it's shown for copying, never executed.
type Action struct {
	Title   string `json:"title"`
	Why     string `json:"why"`
	Host    string `json:"host,omitempty"`
	Command string `json:"command,omitempty"`
}

// Limits on what's kept from the model's answer.
const (
	MaxActions     = 8
	maxSummary     = 1200
	maxTitle       = 160
	maxWhy         = 700
	maxNotes       = 1500
	maxCommand     = 2000
	maxCommandPkgs = 60
)

// SchemaName is the structured-output schema's name.
const SchemaName = "heimdall_analysis"

// Schema is the strict JSON schema the model must answer with: every
// property required, optional ones nullable, no extra properties, and no
// keywords strict mode rejects (lengths are enforced after parsing).
func Schema() map[string]any {
	nullable := func(desc string) map[string]any {
		return map[string]any{"type": []string{"string", "null"}, "description": desc}
	}
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"summary", "actions", "notes"},
		"properties": map[string]any{
			"summary": str("Two to four plain sentences: what matters most right now."),
			"actions": map[string]any{
				"type":        "array",
				"description": "Three to five prioritized steps, most urgent first.",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"required":             []string{"title", "why", "host", "command"},
					"properties": map[string]any{
						"title":   str("Short imperative step, e.g. 'Patch openssl on web-01'."),
						"why":     str("One or two sentences: the evidence from the data."),
						"host":    nullable("The hostname this step is for, exactly as in the data, or null."),
						"command": nullable("One command copied exactly from that host's suggested_commands, or null."),
					},
				},
			},
			"notes": nullable("Optional: what can safely wait and why (e.g. findings with no fix released yet)."),
		},
	}
}

// Allowed is what a suggested command may name: per host, its package
// manager and installed package names (OS and Composer).
type Allowed struct {
	Hosts map[string]HostAllowed
}

type HostAllowed struct {
	PM       string          // dpkg, rpm, apk, or ""
	Packages map[string]bool // OS package names (binary and source)
	Composer map[string]bool // Composer package names in its sites
}

// Parse validates the model's text against the schema and the limits,
// keeping only commands that pass the allowlist for the action's host.
func Parse(text string, allowed Allowed) (*Result, error) {
	text = strings.TrimSpace(text)
	// Models without strict structured output sometimes fence their JSON.
	if t, ok := strings.CutPrefix(text, "```json"); ok {
		text = strings.TrimSuffix(strings.TrimSpace(t), "```")
	} else if t, ok := strings.CutPrefix(text, "```"); ok {
		text = strings.TrimSuffix(strings.TrimSpace(t), "```")
	}
	var raw struct {
		Summary *string `json:"summary"`
		Actions []struct {
			Title   *string `json:"title"`
			Why     *string `json:"why"`
			Host    *string `json:"host"`
			Command *string `json:"command"`
		} `json:"actions"`
		Notes *string `json:"notes"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	if err := dec.Decode(&raw); err != nil || dec.More() {
		return nil, &APIError{Status: 200, Kind: ErrBadOutput, Message: "answer isn't the expected JSON object"}
	}
	if raw.Summary == nil || strings.TrimSpace(*raw.Summary) == "" {
		return nil, &APIError{Status: 200, Kind: ErrBadOutput, Message: "answer has no summary"}
	}
	res := &Result{Summary: cleanText(*raw.Summary, maxSummary), Actions: []Action{}}
	if raw.Notes != nil {
		res.Notes = cleanText(*raw.Notes, maxNotes)
	}
	for _, a := range raw.Actions {
		if len(res.Actions) == MaxActions {
			break
		}
		if a.Title == nil || strings.TrimSpace(*a.Title) == "" {
			continue
		}
		act := Action{Title: cleanLine(*a.Title, maxTitle)}
		if a.Why != nil {
			act.Why = cleanText(*a.Why, maxWhy)
		}
		var host HostAllowed
		var known bool
		if a.Host != nil {
			h := strings.TrimSpace(*a.Host)
			if host, known = allowed.Hosts[h]; known {
				act.Host = h
			}
		}
		if a.Command != nil && known {
			act.Command = checkCommand(*a.Command, host)
		}
		res.Actions = append(res.Actions, act)
	}
	return res, nil
}

// Decode reads a stored result for display, re-applying the text limits
// and the command shape check (defense in depth: stored results were
// already validated in full).
func Decode(raw []byte) (*Result, bool) {
	var r Result
	if json.Unmarshal(raw, &r) != nil || strings.TrimSpace(r.Summary) == "" {
		return nil, false
	}
	r.Summary, r.Notes = cleanText(r.Summary, maxSummary), cleanText(r.Notes, maxNotes)
	if len(r.Actions) > MaxActions {
		r.Actions = r.Actions[:MaxActions]
	}
	for i := range r.Actions {
		a := &r.Actions[i]
		a.Title, a.Why, a.Host = cleanLine(a.Title, maxTitle), cleanText(a.Why, maxWhy), cleanLine(a.Host, 253)
		if a.Command != "" && !commandShapeOK(a.Command) {
			a.Command = ""
		}
	}
	return &r, true
}

// safePackage is the same shape the host page's upgrade commands allow.
var (
	safePackage  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	composerName = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)
)

// commandPrefixes are the only commands a suggestion may contain, per
// package manager: exactly the upgrade commands the host page builds.
var commandPrefixes = map[string][]string{
	"dpkg": {"sudo apt-get update && sudo apt-get install --only-upgrade", "sudo apt-get install --only-upgrade"},
	"rpm":  {"sudo dnf upgrade --refresh", "sudo dnf upgrade"},
	"apk":  {"sudo apk update && sudo apk upgrade", "sudo apk upgrade"},
}

// RebootCommand is the one non-upgrade command allowed.
const RebootCommand = "sudo reboot"

// checkCommand returns the command (whitespace-normalized) if it has an
// allowed shape and names only packages the host has, else "".
func checkCommand(cmd string, h HostAllowed) string {
	cmd = strings.Join(strings.Fields(cmd), " ")
	if cmd == "" || len(cmd) > maxCommand {
		return ""
	}
	if cmd == RebootCommand {
		return cmd
	}
	if rest, ok := strings.CutPrefix(cmd, "composer update "); ok {
		rest = strings.TrimSuffix(rest, " --with-dependencies")
		if pkgs := strings.Fields(rest); len(pkgs) > 0 && len(pkgs) <= maxCommandPkgs && allIn(pkgs, composerName, h.Composer) {
			return cmd
		}
		return ""
	}
	for _, prefix := range commandPrefixes[h.PM] {
		if rest, ok := strings.CutPrefix(cmd, prefix+" "); ok {
			if pkgs := strings.Fields(rest); len(pkgs) > 0 && len(pkgs) <= maxCommandPkgs && allIn(pkgs, safePackage, h.Packages) {
				return cmd
			}
			return ""
		}
	}
	return ""
}

func allIn(pkgs []string, shape *regexp.Regexp, known map[string]bool) bool {
	for i, p := range pkgs {
		if !shape.MatchString(p) || !known[p] || slices.Contains(pkgs[:i], p) {
			return false
		}
	}
	return true
}

// commandShapeOK checks a stored command's shape (not the package list).
func commandShapeOK(cmd string) bool {
	if cmd == RebootCommand {
		return true
	}
	if rest, ok := strings.CutPrefix(cmd, "composer update "); ok {
		pkgs := strings.Fields(strings.TrimSuffix(rest, " --with-dependencies"))
		return len(pkgs) > 0 && len(pkgs) <= maxCommandPkgs && all(pkgs, composerName)
	}
	for _, prefixes := range commandPrefixes {
		for _, prefix := range prefixes {
			if rest, ok := strings.CutPrefix(cmd, prefix+" "); ok {
				pkgs := strings.Fields(rest)
				return len(pkgs) > 0 && len(pkgs) <= maxCommandPkgs && all(pkgs, safePackage) && strings.Join(pkgs, " ") == rest
			}
		}
	}
	return false
}

func all(pkgs []string, shape *regexp.Regexp) bool {
	for _, p := range pkgs {
		if !shape.MatchString(p) {
			return false
		}
	}
	return true
}

// cleanText drops control characters (keeping newlines), collapses blank
// runs and trims to n runes.
func cleanText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	lines := strings.Split(s, "\n")
	out := lines[:0]
	blank := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			if blank || len(out) == 0 {
				continue
			}
			blank = true
		} else {
			blank = false
		}
		out = append(out, l)
	}
	return truncate(strings.TrimSpace(strings.Join(out, "\n")), n)
}

// cleanLine is cleanText on one line.
func cleanLine(s string, n int) string {
	return truncate(strings.Join(strings.Fields(cleanText(s, 4*n)), " "), n)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}
