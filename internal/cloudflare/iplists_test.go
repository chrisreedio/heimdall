// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

const testAccount = "dddddddddddddddddddddddddddddddd"

// fakeLists is the account and list endpoints: an account with IP lists
// (one paged by cursor), an ASN list, and a switch to deny the lists.
type fakeLists struct {
	mu    sync.Mutex
	lists []IPList
	items map[string][][]map[string]any // list ID → pages of items
	deny  bool
	// noAccounts: /accounts lists none (a token without Account
	// Settings: Read); the zone still names the account.
	noAccounts bool
}

func (f *fakeLists) handler() http.Handler {
	env := func(w http.ResponseWriter, result any, after string) {
		b, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "result": result,
			"result_info": map[string]any{"cursors": map[string]string{"after": after}}})
		w.Write(b)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		base := "/accounts/" + testAccount + "/rules/lists"
		switch {
		case r.URL.Path == "/accounts" && f.noAccounts:
			env(w, []Account{}, "")
		case r.URL.Path == "/accounts":
			env(w, []Account{{ID: testAccount, Name: "Acme"}}, "")
		case r.URL.Path == "/zones":
			env(w, []map[string]any{{"id": "z1", "name": "example.com", "status": "active", "account": map[string]string{"id": testAccount, "name": "Acme"}}}, "")
		case f.deny && strings.HasPrefix(r.URL.Path, base):
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
		case r.URL.Path == base:
			env(w, f.lists, "")
		case strings.HasPrefix(r.URL.Path, base+"/") && strings.HasSuffix(r.URL.Path, "/items"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, base+"/"), "/items")
			pages, ok := f.items[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"success":false,"errors":[{"code":10001,"message":"not found"}]}`)
				return
			}
			page := 0
			if c := r.URL.Query().Get("cursor"); c != "" {
				page = int(c[0] - '0')
			}
			after := ""
			if page+1 < len(pages) {
				after = string(rune('0' + page + 1))
			}
			env(w, pages[page], after)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"success":false,"errors":[{"code":7003,"message":"no route"}]}`)
		}
	})
}

func TestListSyncer(t *testing.T) {
	f := &fakeLists{
		lists: []IPList{
			{ID: "offices01", Name: "offices", Kind: "ip", NumItems: 4, Description: "Where the team works from"},
			{ID: "deploys01", Name: "deploys", Kind: "ip", NumItems: 1},
			{ID: "blocked01", Name: "blocked", Kind: "ip", NumItems: 1},
			{ID: "asns01", Name: "networks", Kind: "asn", NumItems: 1},
			{ID: "bans01", Name: "heimdall_challenge", Kind: "ip", NumItems: 5, Description: BanListDescription + "challenge); managed by Heimdall"},
		},
		items: map[string][][]map[string]any{
			"offices01": {
				{{"id": "i1", "ip": "203.0.113.4", "comment": "Alice Example - Developer"},
					{"id": "i2", "asn": 64500, "comment": "an ASN item"}},
				{{"id": "i3", "ip": "198.51.100.0/24", "comment": " Branch office "},
					{"id": "i4", "ip": "203.0.113.4", "comment": "a repeat"},
					{"id": "i5", "ip": "not-an-address"}},
			},
			"deploys01": {{{"id": "i6", "ip": "192.0.2.10", "comment": "CI runner"}}},
			"blocked01": {{{"id": "i7", "ip": "192.0.2.66"}}},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	t.Cleanup(srv.Close)
	st := storetest.New(t)
	ctx := t.Context()
	clock := now
	sy := &ListSyncer{Client: &Client{Base: srv.URL, Token: testToken, HTTP: srv.Client()}, Store: st, Now: func() time.Time { return clock }}
	r := &ipinfo.Resolver{Store: st}
	state := func(src string) store.IPSourceState {
		t.Helper()
		states, err := st.IPSourceStates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range states {
			if s.Source == src {
				return s
			}
		}
		return store.IPSourceState{}
	}

	// Found lists start ignored: nothing becomes a label.
	if err := sy.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	lists, err := st.CloudflareIPLists(ctx)
	if err != nil || len(lists) != 3 || lists[0].Name != "blocked" || lists[2].Description != "Where the team works from" {
		t.Fatalf("lists: %+v %v", lists, err) // neither the ASN list nor the ban list
	}
	if v := r.Resolve(ctx, 0, "203.0.113.4", "", now); !v.Unknown() {
		t.Errorf("an ignored list labelled: %+v", v.Labels)
	}

	// Mapped lists sync: ASN items, repeats and junk skipped; the comment
	// is the person for office, the note for automation.
	st.SetCloudflareIPListKind(ctx, "test", "offices01", store.IPKindOffice, now)
	st.SetCloudflareIPListKind(ctx, "test", "deploys01", store.IPKindAutomation, now)
	clock = now.Add(time.Hour)
	if err := sy.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	v := r.Resolve(ctx, 0, "203.0.113.4", "", now)
	if b := v.Best(); v.Kind() != store.IPKindOffice || b.Name != "offices" || b.Person != "Alice Example - Developer" ||
		b.Source != store.IPListSource("offices01") || len(v.Labels) != 1 {
		t.Errorf("office label: %+v", v.Labels)
	}
	if b := r.Resolve(ctx, 0, "198.51.100.77", "", now).Best(); b.Person != "Branch office" || b.Prefix.String() != "198.51.100.0/24" {
		t.Errorf("office range: %+v", b)
	}
	if b := r.Resolve(ctx, 0, "192.0.2.10", "", now).Best(); b.Kind != store.IPKindAutomation || b.Person != "" || b.Note != "CI runner" {
		t.Errorf("automation label: %+v", b)
	}
	if !r.Resolve(ctx, 0, "192.0.2.66", "", now).Unknown() {
		t.Error("the ignored list labelled")
	}
	if s := state(store.IPListSource("offices01")); s.Labels != 2 || s.LastError != "" || !s.LastSuccess.Equal(clock) {
		t.Errorf("offices state: %+v", s)
	}
	if s := state(ListsSource); s.Labels != 3 || s.LastError != "" {
		t.Errorf("lists state: %+v", s)
	}

	// A list deleted at Cloudflare loses its labels.
	f.mu.Lock()
	f.lists = f.lists[:1]
	f.mu.Unlock()
	if err := sy.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !r.Resolve(ctx, 0, "192.0.2.10", "", now).Unknown() || state(store.IPListSource("deploys01")).Source != "" {
		t.Error("a deleted list's labels stayed")
	}
	if lists, _ := st.CloudflareIPLists(ctx); len(lists) != 1 || lists[0].Kind != store.IPKindOffice {
		t.Errorf("lists after a delete: %+v", lists)
	}

	// Without the permission: the error says what to add, and the last
	// good labels stay.
	f.mu.Lock()
	f.deny = true
	f.mu.Unlock()
	err = sy.Sync(ctx)
	if err == nil || !strings.Contains(err.Error(), "Account Filter Lists > Read") {
		t.Fatalf("denied: %v", err)
	}
	if s := state(ListsSource); !strings.Contains(s.LastError, "Account Filter Lists > Read") || s.LastSuccess.IsZero() {
		t.Errorf("denied state: %+v", s)
	}
	if r.Resolve(ctx, 0, "203.0.113.4", "", now).Kind() != store.IPKindOffice {
		t.Error("labels lost to a failed sync")
	}
}

// A token that can't list accounts (no Account Settings: Read) still
// reads the lists of its zones' account.
func TestListSyncerAccountFromZones(t *testing.T) {
	f := &fakeLists{noAccounts: true, lists: []IPList{{ID: "offices01", Name: "offices", Kind: "ip", NumItems: 1}}}
	srv := httptest.NewTLSServer(f.handler())
	t.Cleanup(srv.Close)
	st := storetest.New(t)
	sy := &ListSyncer{Client: &Client{Base: srv.URL, Token: testToken, HTTP: srv.Client()}, Store: st, Now: func() time.Time { return now }}
	if err := sy.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lists, err := st.CloudflareIPLists(t.Context()); err != nil || len(lists) != 1 || lists[0].AccountID != testAccount {
		t.Errorf("lists: %+v %v", lists, err)
	}
}

func TestListLabelsClips(t *testing.T) {
	l := store.CloudflareIPList{ID: "x", Name: strings.Repeat("n", 120), Kind: store.IPKindStaff}
	ls := ListLabels(l, []ListItem{{IP: "2001:db8::/48", Comment: strings.Repeat("é", 150) + "\x00"}})
	if len(ls) != 1 || len(ls[0].Name) != 100 || len(ls[0].Person) > 200 || strings.ContainsRune(ls[0].Person, 0) ||
		ls[0].Prefix.String() != "2001:db8::/48" {
		t.Errorf("clipped: %+v", ls)
	}
	if ListURL(testAccount, "x") == "" || ListURL("bad", "x") != "" {
		t.Error("ListURL")
	}
}
