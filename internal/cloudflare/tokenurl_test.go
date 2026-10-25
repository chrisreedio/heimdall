package cloudflare

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestTokenURL(t *testing.T) {
	u, err := url.Parse(TokenURL("Heimdall (read-only)", ReadPerms))
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "dash.cloudflare.com" || u.Path != "/profile/api-tokens" {
		t.Fatalf("url = %s", u)
	}
	q := u.Query()
	if q.Get("name") != "Heimdall (read-only)" || q.Get("accountId") != "*" || q.Get("zoneId") != "all" {
		t.Fatalf("query = %v", q)
	}
	var perms []Perm
	if err := json.Unmarshal([]byte(q.Get("permissionGroupKeys")), &perms); err != nil {
		t.Fatal(err)
	}
	if len(perms) != len(ReadPerms) {
		t.Fatalf("perms = %v", perms)
	}
	for _, p := range perms {
		if p.Type != "read" {
			t.Errorf("%s is %s, want read", p.Key, p.Type)
		}
	}
	if strings.Contains(u.RawQuery, " ") {
		t.Errorf("unencoded query: %s", u.RawQuery)
	}
}
