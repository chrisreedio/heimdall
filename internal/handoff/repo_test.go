// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"strings"
	"testing"
)

func TestNormalizeRepo(t *testing.T) {
	ok := map[string]string{
		"https://github.com/acme/app":                                "https://github.com/acme/app",
		"https://github.com/acme/app.git":                            "https://github.com/acme/app",
		"  https://GitHub.com/acme/App.git/  ":                       "https://github.com/acme/App",
		"https://forge:ghp_abcdef0123456789@github.com/acme/app.git": "https://github.com/acme/app",
		"https://x-access-token:tok@github.com/acme/app":             "https://github.com/acme/app",
		"https://oauth2:glpat-secret@gitlab.com/group/sub/app.git":   "https://gitlab.com/group/sub/app",
		"https://git.example.com:8443/team/app?token=abc#frag":       "https://git.example.com:8443/team/app",
		"ssh://git@github.com/acme/app.git":                          "ssh://git@github.com/acme/app",
		"ssh://git@git.example.com:2222/team/app":                    "ssh://git@git.example.com:2222/team/app",
		"ssh://deploy:hunter2@git.example.com/team/app":              "ssh://git.example.com/team/app",
		"ssh://git:pw@git.example.com/team/app":                      "ssh://git.example.com/team/app",
		"ssh://ghp_TOKEN@git.example.com/team/app":                   "ssh://git.example.com/team/app",
		"git@github.com:acme/app.git":                                "git@github.com:acme/app",
		"git@GitLab.com:group/app":                                   "git@gitlab.com:group/app",
		"gitea@git.example.com:/srv/app.git":                         "gitea@git.example.com:/srv/app",
		"deploy@git.example.com:team/app.git":                        "ssh://git.example.com/team/app",
	}
	for in, want := range ok {
		got, err := NormalizeRepo(in)
		if err != nil || got != want {
			t.Errorf("NormalizeRepo(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "github.com/acme/app", "http://github.com/acme/app", "file:///srv/git/app.git", "/srv/git/app.git",
		"git://github.com/acme/app", "https://github.com", "https://github.com/", "https://github.com/acme/../etc",
		"https://github.com/acme/app name", "https://github.com/acme/<script>", "https://gith ub.com/a/b",
		"https://github.com:99999999/a/b", "ext::sh -c touch% /tmp/pwned", "git@github.com:", "git@github.com://x",
		"https://github.com/acme/a\npp", "https://github.com/acme/" + strings.Repeat("a", 300),
		"https://github.com/acme/ăpp", "--upload-pack=touch /tmp/x",
	}
	for _, in := range bad {
		if got, err := NormalizeRepo(in); err == nil {
			t.Errorf("NormalizeRepo(%q) = %q, want an error", in, got)
		} else if strings.Contains(err.Error(), "acme") {
			t.Errorf("error echoes the input: %v", err)
		}
	}
}

func TestNormalizeRepoNeverKeepsCredentials(t *testing.T) {
	for _, in := range []string{
		"https://user:SECRET@github.com/a/b", "https://SECRET@github.com/a/b", "ssh://git:SECRET@github.com/a/b",
		"ssh://SECRET@github.com/a/b", "SECRET@github.com:a/b", "https://a:b@SECRET@github.com/a/b",
	} {
		got, err := NormalizeRepo(in)
		if err == nil && strings.Contains(got, "SECRET") {
			t.Errorf("NormalizeRepo(%q) = %q keeps the credential", in, got)
		}
	}
}

func TestWebURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/acme/app":      "https://github.com/acme/app",
		"git@github.com:acme/app":          "https://github.com/acme/app",
		"ssh://git@gitlab.com/group/sub/x": "https://gitlab.com/group/sub/x",
		"https://www.github.com/acme/app":  "https://github.com/acme/app",
		"https://git.example.com/team/app": "",
		"https://github.com:8443/acme/app": "",
		"https://github.com/acme":          "",
		"not a url":                        "",
	}
	for in, want := range cases {
		if got := WebURL(in); got != want {
			t.Errorf("WebURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRepoKey(t *testing.T) {
	cases := map[string][2]string{ // key, short
		"https://github.com/acme/app":        {"github.com/acme/app", "acme/app"},
		"git@github.com:Acme/App":            {"github.com/acme/app", "acme/app"},
		"ssh://git@github.com:2222/acme/app": {"github.com/acme/app", "acme/app"},
		"https://www.github.com/acme/app":    {"github.com/acme/app", "acme/app"},
		"ssh://git@gitlab.com/group/sub/x":   {"gitlab.com/group/sub/x", "sub/x"},
		"git@git.example.com:/srv/git/app":   {"git.example.com/srv/git/app", "git/app"},
		"https://git.example.com/app":        {"git.example.com/app", "app"},
		"not a url":                          {"", ""},
		"":                                   {"", ""},
	}
	for in, want := range cases {
		if got := [2]string{RepoKey(in), RepoShort(in)}; got != want {
			t.Errorf("RepoKey/RepoShort(%q) = %q, want %q", in, got, want)
		}
	}
}
