// SPDX-License-Identifier: AGPL-3.0-or-later

// Package search answers fleet questions such as "openssl < 3.0.13",
// "php = 8.1" or "CVE-2024-6387".
package search

// Kind is what a query looks for.
type Kind string

const (
	KindPackage Kind = "package" // installed package, optionally with a version comparison
	KindRuntime Kind = "runtime" // php, nodejs, python (derived from packages)
	KindCVE     Kind = "cve"     // hosts with an open finding for a CVE or advisory ID
	KindHost    Kind = "host"    // hostname substring

	KindFramework Kind = "framework" // sites by framework version: laravel [op version]
	KindPHPFPM    Kind = "php-fpm"   // sites by the PHP-FPM version serving them
	KindSite      Kind = "site"      // sites whose server name or root contains a fragment
	KindComposer  Kind = "composer"  // sites whose composer.lock has a package
)

// Query is a parsed search.
type Query struct {
	Raw     string
	Kind    Kind
	Name    string // package, runtime, CVE/advisory ID or hostname fragment
	Op      string // "", "<", "<=", "=", ">=", ">" ("" = any version)
	Version string
}

// Match is one host that satisfies the query.
type Match struct {
	HostID  int64
	Org     string
	Host    string
	OS      string
	Name    string // the package/runtime/advisory that matched
	Version string // installed version (package/runtime kinds)
	Detail  string // short human note, e.g. "fixed in 3.0.13-1~deb12u1"
	Site    string // app root for site matches; "" for host-level matches
}

// Result is a query's answer, sorted by org, host, site, then name.
type Result struct {
	Query   Query
	Matches []Match
	Note    string // e.g. "2 hosts skipped: unsupported OS"
}
