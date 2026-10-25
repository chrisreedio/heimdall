// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services knows deploy and server-management services (Laravel
// Forge, Ploi, ...) by the source addresses they publish and the accounts
// they log in as, so a privilege watch session from one reads as
// automation, not an unknown address.
//
// Each enabled service's list is fetched daily from the vendor (public
// lists only; nothing is sent) and stored as IP labels with source
// "service:<id>". A failed fetch keeps the last good list.
package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Service is one deploy service in the catalog.
type Service struct {
	ID   string // config and label source ID: "service:<ID>"
	Name string // shown on sessions
	// URLs are its published lists; all are fetched and merged.
	URLs  []string
	Parse func([]byte) ([]string, error)
	// Users are the accounts it logs in as by default. A matching user is
	// only a guess (people log in as "forge" too); an address match is known.
	Users []string
	// Fallback is a built-in copy of the list, stored only while no sync
	// has ever succeeded. Only for small lists the vendor promises to
	// announce changes to; FallbackDate says when it was copied.
	Fallback     []string
	FallbackDate string
	// Token marks a list that needs the customer's API token.
	Token bool
	Docs  string // the vendor's page about the list
}

// Catalog is every known service. Only vendors that publish their source
// addresses themselves are here; each entry's Docs is where that's stated.
//
// Considered and left out (no list from the vendor that a hub could fetch):
// Laravel Cloud (a managed platform; it doesn't log in to your servers),
// RunCloud (its list, https://runcloud.io/docs/whitelist-runcloud-ip-addresses,
// is an HTML page and is for its agent port, not SSH), ServerPilot (an agent
// on the server connects out), SpinupWP (sends address changes by email
// only), Cleavr (no published list found). Add those as custom services.
var Catalog = []Service{
	{
		// "If you have set up your servers to restrict SSH access using IP
		// allow lists, you must allow the following Forge IP addresses ...
		// You can also access the IP addresses via the following URL:
		// https://forge.laravel.com/ips-v4.txt" and "we will always email
		// you several weeks prior to an IP address change".
		// https://laravel.com/forge/docs/introduction.md
		// Forge adds your keys to the "forge" account ("SSH into the server
		// as the forge user"): https://laravel.com/forge/docs/ssh.md
		ID: "forge", Name: "Laravel Forge",
		URLs:  []string{"https://forge.laravel.com/ips-v4.txt"},
		Parse: ParseLines,
		Users: []string{"forge"},
		// The four SSH addresses in the docs plus the Forge Terminal one,
		// exactly the ips-v4.txt list on this date.
		Fallback:     []string{"159.203.150.232", "159.203.150.216", "45.55.124.124", "165.227.248.218", "142.93.78.212"},
		FallbackDate: "2026-10-24",
		Docs:         "https://laravel.com/forge/docs/introduction",
	},
	{
		// Ploi's worker addresses are shown only to signed-in customers
		// (https://ploi.io/documentation/introduction/ploi-ip-for-whitelisting
		// has placeholders), and its API's GET /api/ips needs a token:
		// https://developers.ploi.io/getting-started/ip-addresses returns
		// {"data": {"workers": [...], "site-monitors": {...}}}. Site monitors
		// only make HTTP checks, so only workers are used.
		// The server account is "ploi" ("ssh ploi@{IP}", "log in as ploi
		// first and then sudo su"): https://ploi.io/documentation/ssh/how-do-i-connect-with-ssh-mac-linux
		ID: "ploi", Name: "Ploi",
		URLs:  []string{"https://ploi.io/api/ips"},
		Parse: JSONPaths([]string{"data", "workers"}),
		Users: []string{"ploi"},
		Token: true,
		Docs:  "https://developers.ploi.io/getting-started/ip-addresses",
	},
	{
		// The docs list the SSH addresses to allow
		// (https://docs.envoyer.io/introduction.md); envoyer.io serves the
		// same list, plus older addresses, as text like Forge's. Envoyer
		// logs in as whatever account you give it, so no user hint.
		ID: "envoyer", Name: "Laravel Envoyer",
		URLs:  []string{"https://envoyer.io/ips-v4.txt"},
		Parse: ParseLines,
		Docs:  "https://docs.envoyer.io/introduction",
	},
	{
		// "Unlike the rest of our API, it requires no authentication" —
		// GET <account>.deployhq.com/ip_ranges, the docs' example host:
		// https://www.deployhq.com/support/api/ip-ranges-api.md
		// all_ipv4/all_ipv6 are every zone's and the network agent's ranges.
		ID: "deployhq", Name: "DeployHQ",
		URLs:  []string{"https://test.deployhq.com/ip_ranges"},
		Parse: JSONPaths([]string{"all_ipv4"}, []string{"all_ipv6"}),
		Docs:  "https://www.deployhq.com/support/faq/our-ip-ranges",
	},
	{
		// "List of IPs for the US region in JSON" (/api/ips), EU
		// (/api/ips/eu) and Asia (/api/ips/asia), as {"runners": [...]}:
		// https://buddy.works/docs/troubleshooting/ip-whitelist
		ID: "buddy", Name: "Buddy",
		URLs:  []string{"https://buddy.works/api/ips"},
		Parse: JSONPaths([]string{"runners"}),
		Docs:  "https://buddy.works/docs/troubleshooting/ip-whitelist",
	},
	{
		ID: "buddy-eu", Name: "Buddy (EU)",
		URLs:  []string{"https://buddy.works/api/ips/eu"},
		Parse: JSONPaths([]string{"runners"}),
		Docs:  "https://buddy.works/docs/troubleshooting/ip-whitelist",
	},
	{
		ID: "buddy-asia", Name: "Buddy (Asia)",
		URLs:  []string{"https://buddy.works/api/ips/asia"},
		Parse: JSONPaths([]string{"runners"}),
		Docs:  "https://buddy.works/docs/troubleshooting/ip-whitelist",
	},
	{
		// The "actions" key of the meta API: thousands of Azure ranges that
		// other Azure customers share, so a match says "could be GitHub
		// Actions" more than "is". Opt-in.
		// https://docs.github.com/en/rest/meta/meta#get-github-meta-information
		ID: "github-actions", Name: "GitHub Actions",
		URLs:  []string{"https://api.github.com/meta"},
		Parse: JSONPaths([]string{"actions"}),
		Docs:  "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses",
	},
}

// Lookup returns the catalog entry for id.
func Lookup(id string) (Service, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return Service{}, false
}

// Source is a service's IP label source name.
func Source(id string) string { return "service:" + id }

// ParseLines reads one address or CIDR a line; blank lines and "#"
// comments are skipped. An HTML page (a sign-in or error page served with
// 200) is an error, not an empty list.
func ParseLines(b []byte) ([]string, error) {
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '<' {
		return nil, errors.New("got an HTML page, not a list")
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// JSONPaths reads arrays of strings at the given key paths of a JSON
// object, e.g. ["data", "workers"]. A missing path is an error: the
// format changed.
func JSONPaths(paths ...[]string) func([]byte) ([]string, error) {
	return func(b []byte) ([]string, error) {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("not JSON: %w", err)
		}
		var out []string
		for _, p := range paths {
			cur := v
			for _, k := range p {
				m, ok := cur.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("no %q in the response", strings.Join(p, "."))
				}
				cur = m[k]
			}
			arr, ok := cur.([]any)
			if !ok {
				return nil, fmt.Errorf("%q isn't a list", strings.Join(p, "."))
			}
			for _, e := range arr {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("%q has a non-string entry", strings.Join(p, "."))
				}
				out = append(out, s)
			}
		}
		return out, nil
	}
}

// ParseAny reads a custom service's list: a JSON array of strings, or one
// address or CIDR a line.
func ParseAny(b []byte) ([]string, error) {
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '[' {
		var out []string
		if err := json.Unmarshal(t, &out); err != nil {
			return nil, fmt.Errorf("not a JSON list of strings: %w", err)
		}
		return out, nil
	}
	return ParseLines(b)
}
