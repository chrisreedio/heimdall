// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/realmwatch/heimdall/internal/kernel"
)

// Result is the validated, advisory-only output of a run.
type Result struct {
	Summary string   `json:"summary"`
	Actions []Action `json:"actions"`
	Notes   Notes    `json:"notes,omitempty"`
}

// Notes are up to maxNoteItems short points. A result stored before notes
// were a list holds one string, read as one point.
type Notes []string

func (n *Notes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*n = nil
		if strings.TrimSpace(s) != "" {
			*n = Notes{s}
		}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*n = l
	return nil
}

// Action is one suggested step: one fix, and every host it applies to.
// Commands are set only when they passed the allowlist (see checkCommand)
// for each of their hosts; they're shown for copying, never executed.
type Action struct {
	Title    string    `json:"title"`
	Why      string    `json:"why"`
	Hosts    []string  `json:"hosts,omitempty"`
	Commands []Command `json:"commands,omitempty"`
	// Heimdall is set on a step Heimdall changed after the model answered
	// (see Reconcile): HeimdallAdded or HeimdallEdited.
	Heimdall string `json:"heimdall,omitempty"`

	rejected []rejectedCommand // the model's commands for known hosts that the allowlist dropped
}

// Command is one command and the hosts (of its action) it's for.
type Command struct {
	Hosts   []string `json:"hosts,omitempty"`
	Command string   `json:"command"`
}

type rejectedCommand struct{ host, command string }

// UnmarshalJSON also reads a step stored before steps had several hosts:
// one "host" and one "command".
func (a *Action) UnmarshalJSON(b []byte) error {
	type plain Action
	var v struct {
		plain
		Host    string `json:"host"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*a = Action(v.plain)
	if len(a.Hosts) == 0 && v.Host != "" {
		a.Hosts = []string{v.Host}
	}
	if len(a.Commands) == 0 && v.Command != "" {
		a.Commands = []Command{{Hosts: a.Hosts, Command: v.Command}}
	}
	return nil
}

// addHost adds a host to the step, once.
func (a *Action) addHost(h string) {
	if !slices.Contains(a.Hosts, h) {
		a.Hosts = append(a.Hosts, h)
	}
}

// addCommand adds cmd for host h, grouped with the same command for other
// hosts.
func (a *Action) addCommand(h, cmd string) {
	a.addHost(h)
	for i := range a.Commands {
		if c := &a.Commands[i]; c.Command == cmd {
			if !slices.Contains(c.Hosts, h) {
				c.Hosts = append(c.Hosts, h)
			}
			return
		}
	}
	a.Commands = append(a.Commands, Command{Hosts: []string{h}, Command: cmd})
}

// HasCommand reports whether the step has cmd for host h.
func (a Action) HasCommand(h, cmd string) bool {
	return slices.ContainsFunc(a.Commands, func(c Command) bool { return c.Command == cmd && slices.Contains(c.Hosts, h) })
}

func (a Action) hasCommandFor(h string) bool {
	return slices.ContainsFunc(a.Commands, func(c Command) bool { return slices.Contains(c.Hosts, h) })
}

// Labelled reports whether the commands need their hosts shown: some
// command isn't for exactly the step's hosts.
func (a Action) Labelled() bool {
	return slices.ContainsFunc(a.Commands, func(c Command) bool {
		return len(c.Hosts) > 0 && !sameSet(c.Hosts, a.Hosts)
	})
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// Action.Heimdall values.
const (
	HeimdallAdded  = "added"  // Heimdall wrote the whole step
	HeimdallEdited = "edited" // Heimdall removed packages from the model's command
)

// Limits on what's kept from the model's answer. MaxActions applies after
// same-fix steps are merged (Reconcile); Parse keeps up to maxRawActions.
const (
	MaxActions     = 8
	maxRawActions  = 4 * MaxActions
	maxSummary     = 1200
	maxTitle       = 160
	maxWhy         = 700
	maxNotes       = 1500 // one note stored as a string
	maxNote        = 600
	maxNoteItems   = 3
	maxHosts       = 60 // per step
	maxCommand     = 2000
	maxCommandPkgs = 60
)

// SchemaName is the structured-output schema's name.
const SchemaName = "heimdall_analysis"

// Schema is the strict JSON schema the model must answer with: every
// property required, optional ones nullable, no extra properties, and no
// keywords strict mode rejects (lengths are enforced after parsing).
func Schema() map[string]any {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	strs := func(desc string) map[string]any {
		return map[string]any{"type": "array", "description": desc, "items": map[string]any{"type": "string"}}
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"summary", "actions", "notes"},
		"properties": map[string]any{
			"summary": str("Two to four plain sentences: what matters most right now."),
			"actions": map[string]any{
				"type":        "array",
				"description": "Three to five prioritized steps, most urgent first. One step per fix: a fix that applies to several hosts is one step listing all of them.",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"required":             []string{"title", "why", "hosts", "commands"},
					"properties": map[string]any{
						"title": str("Short imperative step without hostnames, e.g. 'Patch openssl' (the hosts are shown next to it)."),
						"why":   str("One or two sentences: the evidence from the data."),
						"hosts": strs("Every hostname this step applies to, exactly as in the data; empty if none."),
						"commands": map[string]any{
							"type":        "array",
							"description": "The step's commands; empty if none. One entry per distinct command, with the hosts it's for.",
							"items": map[string]any{
								"type":                 "object",
								"additionalProperties": false,
								"required":             []string{"hosts", "command"},
								"properties": map[string]any{
									"hosts":   strs("The hosts this command is for, from the step's hosts."),
									"command": str("One command copied exactly from each of those hosts' suggested_commands."),
								},
							},
						},
					},
				},
			},
			"notes": strs("Up to three short points: what can safely wait and why (e.g. findings with no fix released yet). Empty if none."),
		},
	}
}

// Allowed is, per host, what a suggested command may be and which steps a
// plan must include.
type Allowed struct {
	Hosts map[string]HostAllowed
}

type HostAllowed struct {
	PM string // dpkg, rpm, apk, or ""
	// Commands are the commands Heimdall built for this host (its facts'
	// suggested_commands). A step's command must be one of them, or one
	// of them with fewer packages: never a package Heimdall didn't name,
	// which also means never one without a pending update.
	Commands []string
	// Required are steps the plan must have (matched by host and
	// command); Reconcile adds any that are missing, first when
	// RequiredFirst.
	Required      []RequiredStep
	RequiredFirst bool
}

// RequiredStep is a step Heimdall writes for a host when the plan lacks it.
type RequiredStep struct {
	Title, Why, Command string
}

// Parse validates the model's text against the schema and the limits,
// keeping only commands that pass the allowlist for each of their hosts.
// It also reads the older answer shape (one "host" and one "command" per
// step, notes as one string), which models without strict structured
// output may still give.
func Parse(text string, allowed Allowed) (*Result, error) {
	text = strings.TrimSpace(text)
	// Models without strict structured output sometimes fence their JSON.
	if t, ok := strings.CutPrefix(text, "```json"); ok {
		text = strings.TrimSuffix(strings.TrimSpace(t), "```")
	} else if t, ok := strings.CutPrefix(text, "```"); ok {
		text = strings.TrimSuffix(strings.TrimSpace(t), "```")
	}
	type rawCommand struct {
		Hosts   []*string `json:"hosts"`
		Command *string   `json:"command"`
	}
	var raw struct {
		Summary *string `json:"summary"`
		Actions []struct {
			Title    *string      `json:"title"`
			Why      *string      `json:"why"`
			Hosts    []*string    `json:"hosts"`
			Commands []rawCommand `json:"commands"`
			Host     *string      `json:"host"`
			Command  *string      `json:"command"`
		} `json:"actions"`
		Notes *Notes `json:"notes"`
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
		res.Notes = cleanNotes(*raw.Notes)
	}
	for _, a := range raw.Actions {
		if len(res.Actions) == maxRawActions {
			break
		}
		if a.Title == nil || strings.TrimSpace(*a.Title) == "" {
			continue
		}
		act := Action{}
		if a.Why != nil {
			act.Why = cleanText(*a.Why, maxWhy)
		}
		known := func(h *string) (string, HostAllowed, bool) {
			if h == nil {
				return "", HostAllowed{}, false
			}
			name := strings.TrimSpace(*h)
			ha, ok := allowed.Hosts[name]
			return name, ha, ok
		}
		for _, h := range append(a.Hosts, a.Host) {
			if name, _, ok := known(h); ok && len(act.Hosts) < maxHosts {
				act.addHost(name)
			}
		}
		cmds := a.Commands
		if a.Command != nil {
			cmds = append(cmds, rawCommand{Command: a.Command})
		}
		for _, c := range cmds {
			if c.Command == nil || strings.TrimSpace(*c.Command) == "" {
				continue
			}
			targets := c.Hosts
			if len(targets) == 0 { // for all of the step's hosts
				for _, h := range act.Hosts {
					targets = append(targets, &h)
				}
			}
			for _, h := range targets {
				// A command for a host that isn't in the data is dropped.
				name, ha, ok := known(h)
				if !ok || (!slices.Contains(act.Hosts, name) && len(act.Hosts) >= maxHosts) {
					continue
				}
				if cmd := checkCommand(*c.Command, ha); cmd != "" {
					act.addCommand(name, cmd)
				} else {
					act.addHost(name)
					act.rejected = append(act.rejected, rejectedCommand{host: name, command: cleanLine(*c.Command, maxCommand)})
				}
			}
		}
		// The hosts show next to the title: "Patch openssl on web-01" is
		// "Patch openssl".
		act.Title = stripHostSuffix(cleanLine(*a.Title, maxTitle), act.Hosts)
		res.Actions = append(res.Actions, act)
	}
	return res, nil
}

// cleanNotes keeps up to maxNoteItems non-empty notes. A lone note (the
// older string form) may be longer.
func cleanNotes(in Notes) Notes {
	var out Notes
	limit := maxNote
	if len(in) == 1 {
		limit = maxNotes
	}
	for _, n := range in {
		if n = cleanText(n, limit); n != "" && len(out) < maxNoteItems {
			out = append(out, n)
		}
	}
	return out
}

// Reconcile checks a parsed plan against the facts, deterministically:
//   - a command the allowlist rejected keeps the packages that one of
//     Heimdall's commands for that host names (the step is marked
//     edited); when none are left, that host is dropped from the step, and
//     a step left with no command is dropped: a step built on a command
//     Heimdall didn't suggest (such as upgrading a package with no
//     pending update) isn't safe to show;
//   - steps that are the same fix are merged into one (see sameFix), so
//     one fix on three hosts is one step with three hosts;
//   - each host's Required steps (the reboot when a newer kernel is
//     installed and findings are on the running one) are added when the
//     plan lacks them, marked added;
//   - then the plan is cut to MaxActions.
func Reconcile(res *Result, allowed Allowed) *Result {
	kept := make([]Action, 0, len(res.Actions))
	for _, a := range res.Actions {
		if len(a.rejected) > 0 {
			for _, r := range a.rejected {
				if c := trimCommand(r.command, allowed.Hosts[r.host]); c != "" {
					a.addCommand(r.host, c)
					a.Heimdall = HeimdallEdited
				} else if !a.hasCommandFor(r.host) {
					a.Hosts = slices.DeleteFunc(slices.Clone(a.Hosts), func(h string) bool { return h == r.host })
				}
			}
			a.rejected = nil
			if len(a.Commands) == 0 {
				continue
			}
		}
		kept = append(kept, a)
	}
	kept = mergeSameFix(kept, allowed)
	hosts := make([]string, 0, len(allowed.Hosts))
	for h := range allowed.Hosts {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	for _, h := range hosts {
		ha := allowed.Hosts[h]
		for _, req := range ha.Required {
			if slices.ContainsFunc(kept, func(a Action) bool { return a.HasCommand(h, req.Command) }) {
				continue
			}
			add := Action{Title: req.Title, Why: req.Why, Hosts: []string{h},
				Commands: []Command{{Hosts: []string{h}, Command: req.Command}}, Heimdall: HeimdallAdded}
			if ha.RequiredFirst {
				kept = append([]Action{add}, kept...)
			} else {
				kept = append(kept, add)
			}
		}
	}
	if len(kept) > MaxActions {
		kept = kept[:MaxActions]
	}
	res.Actions = kept
	return res
}

// mergeSameFix merges the steps that are the same fix into the first of
// them: their hosts in order, the first one's title and why, and their
// commands grouped (the same command for several hosts is one group).
func mergeSameFix(acts []Action, allowed Allowed) []Action {
	names := make([]string, 0, len(allowed.Hosts))
	for h := range allowed.Hosts {
		names = append(names, h)
	}
	type keyed struct{ pkgs, title string }
	var out []Action
	var keys []keyed
	for _, a := range acts {
		k := keyed{packageKey(a, allowed), titleKey(a.Title, names)}
		i := slices.IndexFunc(keys, func(m keyed) bool { return (k.pkgs != "" && m.pkgs == k.pkgs) || (k.title != "" && m.title == k.title) })
		if i < 0 {
			out, keys = append(out, a), append(keys, k)
			continue
		}
		m := &out[i]
		m.Hosts = slices.Clone(m.Hosts)
		m.Commands = slices.Clone(m.Commands)
		for j := range m.Commands {
			m.Commands[j].Hosts = slices.Clone(m.Commands[j].Hosts)
		}
		for _, h := range a.Hosts {
			if len(m.Hosts) < maxHosts {
				m.addHost(h)
			}
		}
		for _, c := range a.Commands {
			for _, h := range c.Hosts {
				if slices.Contains(m.Hosts, h) {
					m.addCommand(h, c.Command)
				}
			}
		}
		if a.Heimdall == HeimdallEdited && m.Heimdall == "" {
			m.Heimdall = HeimdallEdited
		}
	}
	return out
}

// packageKey identifies a step's fix by Heimdall's own facts: the kind and
// package set of each of its package commands (which passed the
// allowlist, so they name only packages Heimdall suggested), whatever the
// host or the refresh prefix. "" for a step without one (a reboot or a
// full upgrade names no package, so isn't enough to tell two fixes apart).
func packageKey(a Action, allowed Allowed) string {
	var keys []string
	for _, c := range a.Commands {
		if len(c.Hosts) == 0 {
			continue
		}
		kind, _, pkgs, ok := splitCommand(c.Command, allowed.Hosts[c.Hosts[0]].PM)
		if !ok {
			continue
		}
		pkgs = slices.Clone(pkgs)
		slices.Sort(pkgs)
		if k := kind + ":" + strings.Join(pkgs, " "); !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return strings.Join(keys, "|")
}

// titleKey is a step's title with hostnames and the words that join them
// ("on", "for", "and") left out, lowercased: "Patch Brotli on web-01" and
// "Patch brotli on web-02" are the same fix.
func titleKey(title string, hosts []string) string {
	var words []string
	for _, w := range strings.FieldsFunc(strings.ToLower(title), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_.+:/", r)
	}) {
		w = strings.TrimRight(w, ".:")
		if w == "" || slices.Contains([]string{"on", "for", "across", "and"}, w) ||
			slices.ContainsFunc(hosts, func(h string) bool { return strings.EqualFold(h, w) }) {
			continue
		}
		words = append(words, w)
	}
	return strings.Join(words, " ")
}

// stripHostSuffix drops a trailing "on web-01", "for web-01 and web-02"
// or "on web-01, web-02 and web-03" from a title when every host it names
// is one of the step's hosts (they're shown next to the title).
func stripHostSuffix(title string, hosts []string) string {
	if len(hosts) == 0 {
		return title
	}
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = regexp.QuoteMeta(h)
	}
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })
	name := `(?:` + strings.Join(names, "|") + `)`
	re := regexp.MustCompile(`(?i)\s+(?:on|for|across)\s+(?:the\s+hosts?\s+)?` + name + `(?:\s*,\s*(?:and\s+)?` + name + `|\s+and\s+` + name + `)*\s*\.?$`)
	m := re.FindStringIndex(title)
	if m == nil || m[0] == 0 {
		return title
	}
	return strings.TrimSpace(title[:m[0]])
}

// trimCommand keeps, from a rejected command, the packages that the
// closest of Heimdall's commands of the same kind names, or "".
func trimCommand(cmd string, h HostAllowed) string {
	cmd = strings.Join(strings.Fields(cmd), " ")
	kind, prefix, pkgs, ok := splitCommand(cmd, h.PM)
	if !ok {
		return ""
	}
	var best []string
	for _, c := range h.Commands {
		k, _, cpkgs, ok := splitCommand(c, h.PM)
		if !ok || k != kind {
			continue
		}
		var keep []string
		for _, p := range pkgs {
			if slices.Contains(cpkgs, p) && !slices.Contains(keep, p) {
				keep = append(keep, p)
			}
		}
		if len(keep) > len(best) {
			best = keep
		}
	}
	if len(best) == 0 {
		return ""
	}
	out := prefix + " " + strings.Join(best, " ")
	if kind == "composer" && strings.HasSuffix(cmd, " --with-dependencies") {
		out += " --with-dependencies"
	}
	return checkCommand(out, h)
}

// Decode reads a stored result for display, re-applying the text limits
// and the command shape check (defense in depth: stored results were
// already validated in full). Results stored before steps had several
// hosts (one "host" and "command", notes as one string) read the same.
func Decode(raw []byte) (*Result, bool) {
	var r Result
	if json.Unmarshal(raw, &r) != nil || strings.TrimSpace(r.Summary) == "" {
		return nil, false
	}
	r.Summary, r.Notes = cleanText(r.Summary, maxSummary), cleanNotes(r.Notes)
	if len(r.Actions) > maxRawActions {
		r.Actions = r.Actions[:maxRawActions]
	}
	for i := range r.Actions {
		a := &r.Actions[i]
		var hosts []string
		for _, h := range a.Hosts {
			if h = cleanLine(h, 253); h != "" && !slices.Contains(hosts, h) && len(hosts) < maxHosts {
				hosts = append(hosts, h)
			}
		}
		a.Hosts = hosts
		a.Title, a.Why = stripHostSuffix(cleanLine(a.Title, maxTitle), a.Hosts), cleanText(a.Why, maxWhy)
		if a.Heimdall != HeimdallAdded && a.Heimdall != HeimdallEdited {
			a.Heimdall = ""
		}
		a.Commands = slices.DeleteFunc(a.Commands, func(c Command) bool { return !commandShapeOK(c.Command) })
		for j := range a.Commands {
			a.Commands[j].Hosts = slices.DeleteFunc(a.Commands[j].Hosts, func(h string) bool { return !slices.Contains(a.Hosts, h) })
		}
	}
	// A brief stored before same-fix steps were merged ("Patch Brotli" on
	// each of three hosts) reads as one step, by title.
	hosts := Allowed{Hosts: map[string]HostAllowed{}}
	for _, a := range r.Actions {
		for _, h := range a.Hosts {
			hosts.Hosts[h] = HostAllowed{}
		}
	}
	if r.Actions = mergeSameFix(r.Actions, hosts); len(r.Actions) > MaxActions {
		r.Actions = r.Actions[:MaxActions]
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

// checkCommand returns the command (whitespace-normalized) if it's one
// Heimdall built for the host (h.Commands), or one of those with fewer of
// its packages (in any order, no duplicates), else "". The two prefixes of
// one package manager (with and without the metadata refresh) count as the
// same command.
func checkCommand(cmd string, h HostAllowed) string {
	cmd = strings.Join(strings.Fields(cmd), " ")
	if cmd == "" || len(cmd) > maxCommand {
		return ""
	}
	if slices.Contains(h.Commands, cmd) && commandShapeOK(cmd) {
		return cmd
	}
	kind, _, pkgs, ok := splitCommand(cmd, h.PM)
	if !ok || len(pkgs) == 0 || len(pkgs) > maxCommandPkgs {
		return ""
	}
	for i, p := range pkgs {
		if slices.Contains(pkgs[:i], p) {
			return ""
		}
	}
	for _, c := range h.Commands {
		k, _, cpkgs, ok := splitCommand(c, h.PM)
		if ok && k == kind && !slices.ContainsFunc(pkgs, func(p string) bool { return !slices.Contains(cpkgs, p) }) {
			return cmd
		}
	}
	return ""
}

// splitCommand splits a command with a package list into its kind
// ("upgrade", "purge" or "composer"), its prefix and its packages, for
// the host's package manager. ok is false for any other shape.
func splitCommand(cmd, pm string) (kind, prefix string, pkgs []string, ok bool) {
	if rest, found := strings.CutPrefix(cmd, "composer update "); found {
		pkgs = strings.Fields(strings.TrimSuffix(rest, " --with-dependencies"))
		return "composer", "composer update", pkgs, len(pkgs) > 0 && all(pkgs, composerName)
	}
	if rest, found := strings.CutPrefix(cmd, kernel.PurgePrefix+" "); found {
		pkgs = strings.Fields(rest)
		return "purge", kernel.PurgePrefix, pkgs, pm == "dpkg" && len(pkgs) > 0 && all(pkgs, safePackage)
	}
	for _, p := range commandPrefixes[pm] {
		if rest, found := strings.CutPrefix(cmd, p+" "); found {
			pkgs = strings.Fields(rest)
			return "upgrade", p, pkgs, len(pkgs) > 0 && all(pkgs, safePackage) && noABIKernel(pm, pkgs)
		}
	}
	return "", "", nil, false
}

// noABIKernel rejects Debian/Ubuntu packages named for one kernel ABI:
// upgrading them never installs a kernel fix (the metapackage does).
func noABIKernel(pm string, pkgs []string) bool {
	return !slices.ContainsFunc(pkgs, func(p string) bool { return kernel.ABIPackage(pm, p) })
}

// commandShapeOK checks a stored command's shape (not the package list).
func commandShapeOK(cmd string) bool {
	if cmd == RebootCommand || cmd == kernel.DpkgFullUpgrade {
		return true
	}
	if rest, ok := strings.CutPrefix(cmd, "composer update "); ok {
		pkgs := strings.Fields(strings.TrimSuffix(rest, " --with-dependencies"))
		return len(pkgs) > 0 && len(pkgs) <= maxCommandPkgs && all(pkgs, composerName)
	}
	if rest, ok := strings.CutPrefix(cmd, kernel.PurgePrefix+" "); ok {
		pkgs := strings.Fields(rest)
		return len(pkgs) > 0 && len(pkgs) <= maxCommandPkgs && all(pkgs, safePackage) && strings.Join(pkgs, " ") == rest &&
			!slices.ContainsFunc(pkgs, func(p string) bool { return !kernel.ABIPackage("dpkg", p) })
	}
	for pm, prefixes := range commandPrefixes {
		for _, prefix := range prefixes {
			if rest, ok := strings.CutPrefix(cmd, prefix+" "); ok {
				pkgs := strings.Fields(rest)
				return len(pkgs) > 0 && len(pkgs) <= maxCommandPkgs && all(pkgs, safePackage) && strings.Join(pkgs, " ") == rest &&
					noABIKernel(pm, pkgs)
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
