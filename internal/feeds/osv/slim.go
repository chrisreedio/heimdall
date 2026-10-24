// SPDX-License-Identifier: AGPL-3.0-or-later

package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Slim returns raw (one OSV record) without the parts Heimdall never reads,
// for storage. What's dropped is bulk: each affected entry's explicit
// "versions" list (OSV's querybatch does version matching, not Heimdall),
// the package purl, per-entry database_specific (source URLs and the like)
// and Ubuntu's ecosystem_specific "binaries" list. Ubuntu's kernel records
// repeat those for every kernel flavour in every release, so they run to
// hundreds of kilobytes, sometimes megabytes; slimmed they're a few percent
// of that.
//
// Everything Heimdall derives from a record survives: Parse(Slim(raw))
// yields the same summary, aliases, severities, distro rating and affected
// ranges as Parse(raw), for every ecosystem in the record (not only the
// ones this hub's hosts run, so a host on a new release still matches).
// References and details are kept too.
func Slim(raw []byte) ([]byte, error) {
	if len(raw) > maxVulnBytes {
		return nil, fmt.Errorf("record larger than %d bytes", maxVulnBytes)
	}
	var w slimWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	if !idRe.MatchString(w.ID) {
		return nil, fmt.Errorf("invalid vulnerability id %q", truncate(w.ID))
	}
	for i := range w.Affected {
		a := &w.Affected[i]
		a.EcosystemSpecific = dropKey(a.EcosystemSpecific, "binaries")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// slimWire is the stored shape: the fields Parse reads plus references.
type slimWire struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Upstream         []string        `json:"upstream,omitempty"`
	Related          []string        `json:"related,omitempty"`
	Modified         string          `json:"modified,omitempty"`
	Published        string          `json:"published,omitempty"`
	Withdrawn        string          `json:"withdrawn,omitempty"`
	Severity         json.RawMessage `json:"severity,omitempty"`
	References       json.RawMessage `json:"references,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
	Affected         []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges            json.RawMessage `json:"ranges,omitempty"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	} `json:"affected,omitempty"`
}

// dropKey removes key from a JSON object; anything else (including an
// object without key) is returned unchanged, and an object left empty
// becomes nil.
func dropKey(obj json.RawMessage, key string) json.RawMessage {
	if len(obj) == 0 || obj[0] != '{' {
		return obj
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(obj, &m) != nil {
		return obj
	}
	if _, ok := m[key]; !ok {
		return obj
	}
	delete(m, key)
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return obj
	}
	return b
}
