// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clientonly finds Debian/Ubuntu source packages installed only
// for their client tools and libraries, with the server built from the
// same source missing: bind9's dig and libraries without named, the
// PostgreSQL client without the server. Advisories on these sources are
// mostly about the server, so a no-fix finding on one isn't worth
// watching for its EPSS score or the news alone (a known-exploited one
// still is).
package clientonly

import (
	"regexp"
	"strings"
)

// rule is one source whose server is a separate binary package.
type rule struct {
	source *regexp.Regexp
	// server is the server binary's name, or a prefix of it ending in "*"
	// ("mysql-server*" for mysql-server-8.0 and mysql-server-core-8.0);
	// "" means the binary named like the source (postgresql-16).
	server string
}

// rules are the sources whose advisories are mostly about the server. Kept
// short on purpose: a source here whose client side is exposed too would
// hide findings worth watching.
var rules = []rule{
	{regexp.MustCompile(`^bind9$`), "bind9"}, // named; bind9-host, -dnsutils, -libs are clients
	{regexp.MustCompile(`^isc-dhcp$`), "isc-dhcp-server"},
	{regexp.MustCompile(`^samba$`), "samba"}, // smbd; smbclient, samba-libs are clients
	{regexp.MustCompile(`^openssh$`), "openssh-server"},
	{regexp.MustCompile(`^cups$`), "cups-daemon"},
	{regexp.MustCompile(`^postgresql-[0-9]+$`), ""}, // postgresql-client-16 isn't the server
	{regexp.MustCompile(`^mysql-[0-9.]+$`), "mysql-server*"},
	{regexp.MustCompile(`^mariadb(-[0-9.]+)?$`), "mariadb-server*"},
}

// isServer reports whether binary is the rule's server for source.
func (r rule) isServer(source, binary string) bool {
	switch {
	case r.server == "":
		return binary == source
	case strings.HasSuffix(r.server, "*"):
		return strings.HasPrefix(binary, strings.TrimSuffix(r.server, "*"))
	}
	return binary == r.server
}

// label names the missing server for the page.
func (r rule) label(source string) string {
	if r.server == "" {
		return source
	}
	return strings.TrimSuffix(r.server, "*")
}

// Package is an installed binary package and the source it's built from
// ("" when they're the same).
type Package struct{ Name, Source string }

// Sources maps each source installed only for its clients to the server
// package that isn't installed. It's for Debian/Ubuntu (dpkg) hosts only.
func Sources(pkgs []Package) map[string]string {
	type seen struct {
		r      *rule
		server bool
	}
	bySource := map[string]*seen{}
	for _, p := range pkgs {
		src := p.Source
		if src == "" {
			src = p.Name
		}
		s, ok := bySource[src]
		if !ok {
			for i := range rules {
				if rules[i].source.MatchString(src) {
					s = &seen{r: &rules[i]}
					break
				}
			}
			bySource[src] = s
		}
		if s != nil && s.r.isServer(src, p.Name) {
			s.server = true
		}
	}
	out := map[string]string{}
	for src, s := range bySource {
		if s != nil && !s.server {
			out[src] = s.r.label(src)
		}
	}
	return out
}

// SourceLike is a SQL LIKE pattern per rule, to read only the packages
// that can matter.
var SourceLike = []string{"bind9", "isc-dhcp", "samba", "openssh", "cups", "postgresql-%", "mysql-%", "mariadb%"}
