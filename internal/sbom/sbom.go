// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sbom exports a host's inventory as a CycloneDX 1.5 SBOM, with a
// package URL (purl) for every component.
package sbom

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

type document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

type metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     tools     `json:"tools"`
	Component component `json:"component"`
}

type tools struct {
	Components []component `json:"components"`
}

type component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref,omitempty"`
	Group      string     `json:"group,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// purl type and namespace per package manager and os-release ID.
func osPURL(inv store.HostInventory, p store.InventoryPackage) string {
	var typ string
	switch inv.PackageManager {
	case "dpkg":
		typ = "deb"
	case "rpm":
		typ = "rpm"
	case "apk":
		typ = "apk"
	case "pacman":
		typ = "alpm"
	default:
		return ""
	}
	q := url.Values{}
	if p.Arch != "" {
		q.Set("arch", p.Arch)
	}
	if inv.OSID != "" {
		q.Set("distro", strings.TrimSuffix(inv.OSID+"-"+inv.OSVersion, "-"))
	}
	return fmt.Sprintf("pkg:%s/%s/%s@%s?%s", typ, url.PathEscape(inv.OSID), url.PathEscape(p.Name),
		url.PathEscape(p.Version), q.Encode())
}

func appPURL(ecosystem, name, version string) string {
	switch ecosystem {
	case "Packagist":
		vendor, pkg, _ := strings.Cut(name, "/")
		return fmt.Sprintf("pkg:composer/%s/%s@%s", url.PathEscape(vendor), url.PathEscape(pkg), url.PathEscape(version))
	case "npm":
		if scope, pkg, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
			return fmt.Sprintf("pkg:npm/%s/%s@%s", url.PathEscape(scope), url.PathEscape(pkg), url.PathEscape(version))
		}
		return fmt.Sprintf("pkg:npm/%s@%s", url.PathEscape(name), url.PathEscape(version))
	case "PyPI":
		n := strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(name))
		return fmt.Sprintf("pkg:pypi/%s@%s", url.PathEscape(n), url.PathEscape(version))
	}
	return ""
}

// Write emits the SBOM for one host's latest snapshot.
func Write(w io.Writer, inv store.HostInventory, toolVersion string, now time.Time) error {
	serial := make([]byte, 16)
	rand.Read(serial)
	serial[6], serial[8] = serial[6]&0x0f|0x40, serial[8]&0x3f|0x80 // UUID v4
	u := hex.EncodeToString(serial)
	doc := document{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		SerialNumber: fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", u[0:8], u[8:12], u[12:16], u[16:20], u[20:]),
		Metadata: metadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Tools:     tools{Components: []component{{Type: "application", Name: "heimdall", Version: toolVersion}}},
			Component: component{Type: "operating-system", Name: inv.Host.Name, Version: inv.OSVersion,
				Properties: []property{{"heimdall:org", inv.Host.OrgSlug}, {"heimdall:os", inv.OSPretty}}},
		},
		Components: []component{},
	}
	for _, p := range inv.Packages {
		c := component{Type: "library", Name: p.Name, Version: p.Version, PURL: osPURL(inv, p)}
		if p.SourceName != "" && p.SourceName != p.Name {
			c.Properties = append(c.Properties, property{"heimdall:source_package", p.SourceName})
		}
		c.BOMRef = c.PURL
		doc.Components = append(doc.Components, c)
	}
	add := func(eco, where string, pkgs []store.AppPackage) {
		for _, p := range pkgs {
			c := component{Type: "library", Name: p.Name, Version: p.Version, PURL: appPURL(eco, p.Name, p.Version),
				Properties: []property{{"heimdall:location", where}}}
			c.BOMRef = c.PURL + "#" + where
			doc.Components = append(doc.Components, c)
		}
	}
	for _, s := range inv.Sites {
		add("Packagist", s.Root, s.Packages)
	}
	for _, l := range inv.Lockfiles {
		add(l.Ecosystem, l.Path, l.Packages)
	}
	for _, c := range inv.Containers {
		ref := c.Image
		if c.Tag != "" {
			ref += ":" + c.Tag
		}
		doc.Components = append(doc.Components, component{Type: "container", Name: c.Image, Version: c.Tag,
			BOMRef: "container:" + c.Name, Properties: []property{{"heimdall:container", c.Name}, {"heimdall:image", ref}}})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
