// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// MaxRepoLen caps a normalized repository URL.
const MaxRepoLen = 200

var (
	repoHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)
	repoPortRe = regexp.MustCompile(`^[0-9]{1,5}$`)
	repoPathRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*$`)
	scpRe      = regexp.MustCompile(`^([A-Za-z0-9_.-]{1,64})@([A-Za-z0-9.-]{1,253}):(/?[^/].*)$`)
	// SSH user names kept in a normalized URL. Anything else (which could
	// be a token pasted as a user name) is dropped.
	sshUsers = []string{"git", "gitea", "forgejo", "gogs", "gitlab"}
)

// ErrRepo is returned for a repository URL that isn't one of the accepted
// forms. Its text never echoes the input, which may hold a token.
var ErrRepo = errors.New("a repository is https://host/owner/repo, ssh://git@host/owner/repo or git@host:owner/repo")

// NormalizeRepo checks a git remote URL and returns it in canonical form,
// with any credentials removed:
//
//	https://user:token@GitHub.com/owner/repo.git → https://github.com/owner/repo
//	ssh://git@host:2222/owner/repo.git            → ssh://git@host:2222/owner/repo
//	git@github.com:owner/repo.git                 → git@github.com:owner/repo
//
// Only those three forms are accepted. Queries and fragments are dropped,
// a trailing ".git" or "/" is removed, and the result is at most
// MaxRepoLen characters.
func NormalizeRepo(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 1024 || strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f || r > 0x7e }) {
		return "", ErrRepo
	}
	var out string
	switch {
	case strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "ssh://"):
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.Opaque != "" {
			return "", ErrRepo
		}
		host, port, err := repoHostPort(u.Host)
		if err != nil {
			return "", err
		}
		path, err := repoPath(u.Path)
		if err != nil {
			return "", err
		}
		if port != "" {
			host += ":" + port
		}
		if u.Scheme == "https" {
			out = "https://" + host + "/" + path
		} else {
			user := ""
			if u.User != nil {
				if _, hasPassword := u.User.Password(); !hasPassword && slices.Contains(sshUsers, u.User.Username()) {
					user = u.User.Username() + "@"
				}
			}
			out = "ssh://" + user + host + "/" + path
		}
	default:
		m := scpRe.FindStringSubmatch(s)
		if m == nil {
			return "", ErrRepo
		}
		host := strings.ToLower(m[2])
		if !repoHostRe.MatchString(host) {
			return "", ErrRepo
		}
		lead := ""
		if strings.HasPrefix(m[3], "/") {
			lead = "/"
		}
		path, err := repoPath(m[3])
		if err != nil {
			return "", err
		}
		if slices.Contains(sshUsers, m[1]) {
			out = m[1] + "@" + host + ":" + lead + path
		} else {
			out = "ssh://" + host + "/" + path // an odd user name is dropped
		}
	}
	if len(out) > MaxRepoLen {
		return "", errors.New("the repository URL is too long")
	}
	return out, nil
}

func repoHostPort(hp string) (host, port string, err error) {
	if i := strings.LastIndexByte(hp, '@'); i >= 0 {
		hp = hp[i+1:] // credentials: never kept
	}
	host = hp
	if i := strings.LastIndexByte(hp, ':'); i >= 0 {
		host, port = hp[:i], hp[i+1:]
		if !repoPortRe.MatchString(port) {
			return "", "", ErrRepo
		}
	}
	host = strings.ToLower(host)
	if !repoHostRe.MatchString(host) || len(host) > 253 {
		return "", "", ErrRepo
	}
	return host, port, nil
}

func repoPath(p string) (string, error) {
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, ".git")
	p = strings.TrimRight(p, "/")
	if p == "" || !repoPathRe.MatchString(p) {
		return "", ErrRepo
	}
	for part := range strings.SplitSeq(p, "/") {
		if part == "." || part == ".." {
			return "", ErrRepo
		}
	}
	return p, nil
}

// WebURL returns a browser link for a normalized repository on GitHub or
// GitLab (https://github.com/owner/repo), or "" for any other host.
func WebURL(repo string) string {
	var host, path string
	switch {
	case strings.HasPrefix(repo, "https://"), strings.HasPrefix(repo, "ssh://"):
		u, err := url.Parse(repo)
		if err != nil {
			return ""
		}
		host, path = u.Hostname(), strings.Trim(u.Path, "/")
		if u.Port() != "" && u.Scheme == "https" {
			return ""
		}
	default:
		m := scpRe.FindStringSubmatch(repo)
		if m == nil {
			return ""
		}
		host, path = m[2], strings.Trim(m[3], "/")
	}
	host = strings.TrimPrefix(host, "www.")
	if host != "github.com" && host != "gitlab.com" {
		return ""
	}
	if !repoPathRe.MatchString(path) || !strings.Contains(path, "/") {
		return ""
	}
	return "https://" + host + "/" + path
}

// RepoKey identifies a normalized repository however it's reached: its
// host (without user or port) and path, lowercased, as in
// "github.com/acme/app". https://github.com/acme/app and
// git@github.com:acme/app have the same key. "" for anything else.
func RepoKey(repo string) string {
	var host, path string
	switch {
	case strings.HasPrefix(repo, "https://"), strings.HasPrefix(repo, "ssh://"):
		u, err := url.Parse(repo)
		if err != nil {
			return ""
		}
		host, path = u.Hostname(), u.Path
	default:
		m := scpRe.FindStringSubmatch(repo)
		if m == nil {
			return ""
		}
		host, path = m[2], m[3]
	}
	path = strings.Trim(path, "/")
	if host == "" || !repoPathRe.MatchString(path) {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(host, "www.") + "/" + path)
}

// RepoShort is a repository's short name: the last two parts of its path,
// as in "acme/app" (or the only one). "" when RepoKey is.
func RepoShort(repo string) string {
	key := RepoKey(repo)
	if key == "" {
		return ""
	}
	parts := strings.Split(key, "/")[1:]
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, "/")
}
