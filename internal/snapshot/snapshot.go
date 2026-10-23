// SPDX-License-Identifier: AGPL-3.0-or-later

// Package snapshot defines the JSON document a collector sends and decodes
// it strictly. Every snapshot is untrusted input from a possibly
// compromised host: unknown fields, trailing data, oversized lists and
// unexpected characters are all rejected rather than cleaned up.
package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Format strings. A breaking change gets a new one, and the hub accepts
// several during a transition. Collectors 0.2+ emit v2 (v1 plus sites).
const (
	FormatV1 = "heimdall.snapshot/v1"
	FormatV2 = "heimdall.snapshot/v2"
	// Format is v1, kept for compatibility. New code should use FormatV1
	// or FormatV2 explicitly.
	Format = FormatV1
)

// Formats lists every format the hub accepts.
var Formats = []string{FormatV1, FormatV2, FormatV3}

// Limits keep a hostile host from storing unbounded data.
const (
	MaxPackages = 20000
	MaxUpdates  = MaxPackages
)

type Snapshot struct {
	Format         string    `json:"format"`
	Collector      Collector `json:"collector"`
	CollectedAt    time.Time `json:"collected_at"`
	OS             OS        `json:"os"`
	Kernel         Kernel    `json:"kernel"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	RebootRequired *bool     `json:"reboot_required"` // nil if it couldn't be determined
	PackageManager string    `json:"package_manager"`
	Packages       []Package `json:"packages"`
	Updates        []Update  `json:"updates"`
	Unavailable    []string  `json:"unavailable"` // checks the collector skipped
	// Sites is v2 only: web apps found on the host. nil in v1 documents.
	Sites      []Site      `json:"sites"`
	Containers []Container `json:"containers"` // v3
	Lockfiles  []Lockfile  `json:"lockfiles"`  // v3
}

type Collector struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"` // hex digest of the collector script; "" if unavailable
}

// OS carries raw /etc/os-release values.
type OS struct {
	ID         string `json:"id"`
	IDLike     string `json:"id_like"`
	VersionID  string `json:"version_id"`
	Codename   string `json:"version_codename"`
	PrettyName string `json:"pretty_name"`
}

type Kernel struct {
	Release string `json:"release"` // uname -r
	Arch    string `json:"arch"`    // uname -m
}

type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	SourceName    string `json:"source_name"`
	SourceVersion string `json:"source_version"`
}

type Update struct {
	Name     string `json:"name"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`  // version that would be installed
	Security *bool  `json:"security"` // nil if the package manager can't tell
}

// Package managers and skippable checks the format knows about.
var (
	PackageManagers = []string{"dpkg", "rpm", "apk", "pacman", "windows"}
	Checks          = []string{"packages", "updates", "reboot_required", "uptime", "collector_sha256", "sites", "containers", "lockfiles"}
)

var (
	collectorVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]{1,32})?$`)
	sha256Re           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	osIDRe             = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`) // per os-release(5)
	osIDLikeRe         = regexp.MustCompile(`^[a-z0-9._ -]{0,128}$`)
	osVersionRe        = regexp.MustCompile(`^[A-Za-z0-9._~-]{0,32}$`)
	kernelRe           = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,128}$`)
	archRe             = regexp.MustCompile(`^[A-Za-z0-9_]{0,32}$`)
	pkgNameRe          = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}$`)
	// Windows program names ("Microsoft Visual C++ 2022 X64 Runtime") have
	// spaces and punctuation; still no quotes, angle brackets or controls.
	windowsNameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._+()&,'#@/:-]{0,199}$`)
	// dpkg uses ':' (epoch), '~' and '+'; rpm uses '^' and '~'.
	pkgVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:^-]{0,127}$`)
)

// Decode reads exactly one snapshot from r and validates it. The caller is
// responsible for capping how much r can return.
func Decode(r io.Reader) (*Snapshot, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode: unexpected data after the snapshot")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// DecodeBytes is Decode for an in-memory payload.
func DecodeBytes(b []byte) (*Snapshot, error) { return Decode(bytes.NewReader(b)) }

// FieldError names the offending field so problems can be fixed on the host.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func (s *Snapshot) Validate() error {
	var errs []error
	bad := func(field, format string, a ...any) {
		if len(errs) < 20 { // enough to be useful, bounded for hostile input
			errs = append(errs, &FieldError{field, fmt.Sprintf(format, a...)})
		}
	}
	match := func(field string, re *regexp.Regexp, v string) {
		if !re.MatchString(v) {
			bad(field, "invalid value %s", quote(v))
		}
	}

	if !slices.Contains(Formats, s.Format) {
		bad("format", "must be one of %s, got %s", strings.Join(Formats, ", "), quote(s.Format))
		return errors.Join(errs...) // nothing else is meaningful
	}

	match("collector.version", collectorVersionRe, s.Collector.Version)

	if y := s.CollectedAt.Year(); y < 2020 || y > 2100 {
		bad("collected_at", "implausible time %s", s.CollectedAt.Format(time.RFC3339))
	}

	match("os.id", osIDRe, s.OS.ID)
	match("os.id_like", osIDLikeRe, s.OS.IDLike)
	match("os.version_id", osVersionRe, s.OS.VersionID)
	match("os.version_codename", osVersionRe, s.OS.Codename)
	if err := checkText(s.OS.PrettyName, 128); err != "" {
		bad("os.pretty_name", "%s", err)
	}

	match("kernel.release", kernelRe, s.Kernel.Release)
	match("kernel.arch", archRe, s.Kernel.Arch)
	if s.Kernel.Arch == "" {
		bad("kernel.arch", "is required")
	}

	if s.UptimeSeconds < 0 || s.UptimeSeconds > 20*365*24*3600 {
		bad("uptime_seconds", "out of range: %d", s.UptimeSeconds)
	}

	if !slices.Contains(PackageManagers, s.PackageManager) {
		bad("package_manager", "must be one of %s, got %s", strings.Join(PackageManagers, ", "), quote(s.PackageManager))
	}

	seenChecks := map[string]bool{}
	for i, c := range s.Unavailable {
		if !slices.Contains(Checks, c) || seenChecks[c] {
			bad(fmt.Sprintf("unavailable[%d]", i), "unknown or repeated check %s", quote(c))
		}
		seenChecks[c] = true
	}
	// A skipped check carries no data, and missing data must be declared.
	if (s.RebootRequired == nil) != seenChecks["reboot_required"] {
		bad("reboot_required", "must be null exactly when listed in unavailable")
	}
	// A collector piped into `sh -s` can't hash itself.
	if seenChecks["collector_sha256"] {
		if s.Collector.SHA256 != "" {
			bad("collector.sha256", "must be empty when listed in unavailable")
		}
	} else {
		match("collector.sha256", sha256Re, s.Collector.SHA256)
	}
	if seenChecks["uptime"] && s.UptimeSeconds != 0 {
		bad("uptime_seconds", "must be 0 when listed in unavailable")
	}
	if seenChecks["packages"] && len(s.Packages) > 0 {
		bad("packages", "must be empty when listed in unavailable")
	}
	if seenChecks["updates"] && len(s.Updates) > 0 {
		bad("updates", "must be empty when listed in unavailable")
	}
	validateSites(s, seenChecks, bad)
	validateV3(s, seenChecks, bad)

	if len(s.Packages) > MaxPackages {
		bad("packages", "too many (%d > %d)", len(s.Packages), MaxPackages)
	} else {
		if len(s.Packages) == 0 && !seenChecks["packages"] {
			bad("packages", "empty, but \"packages\" is not listed as unavailable")
		}
		type key struct{ name, arch, version string }
		seen := make(map[key]bool, len(s.Packages))
		for i, p := range s.Packages {
			f := fmt.Sprintf("packages[%d]", i)
			nameRe := pkgNameRe
			if s.PackageManager == "windows" {
				nameRe = windowsNameRe
			}
			match(f+".name", nameRe, p.Name)
			match(f+".version", pkgVersionRe, p.Version)
			match(f+".arch", archRe, p.Arch)
			if p.SourceName != "" {
				match(f+".source_name", pkgNameRe, p.SourceName)
			}
			if p.SourceVersion != "" {
				match(f+".source_version", pkgVersionRe, p.SourceVersion)
			}
			k := key{p.Name, p.Arch, p.Version}
			if seen[k] {
				bad(f, "duplicate package %s", quote(p.Name))
			}
			seen[k] = true
		}
	}

	if len(s.Updates) > MaxUpdates {
		bad("updates", "too many (%d > %d)", len(s.Updates), MaxUpdates)
	} else {
		for i, u := range s.Updates {
			f := fmt.Sprintf("updates[%d]", i)
			match(f+".name", pkgNameRe, u.Name)
			match(f+".version", pkgVersionRe, u.Version)
			match(f+".arch", archRe, u.Arch)
		}
	}

	return errors.Join(errs...)
}

func checkText(s string, max int) string {
	switch {
	case !utf8.ValidString(s):
		return "not valid UTF-8"
	case utf8.RuneCountInString(s) > max:
		return fmt.Sprintf("longer than %d characters", max)
	case strings.ContainsFunc(s, unicode.IsControl):
		return "contains control characters"
	}
	return ""
}

// quote renders an untrusted value safely and briefly for error messages.
func quote(v string) string {
	if len(v) > 64 {
		v = v[:64] + "…"
	}
	return fmt.Sprintf("%q", v)
}
