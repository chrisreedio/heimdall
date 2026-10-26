// SPDX-License-Identifier: AGPL-3.0-or-later

package bans

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/realmwatch/heimdall/internal/cloudflare"
)

// fakeCF is a Cloudflare account's lists and zone rulesets, in memory.
type fakeCF struct {
	mu       sync.Mutex
	account  string
	lists    map[string]*fakeList // by ID
	rulesets map[string]*cloudflare.Ruleset
	next     int
	writes   int      // every POST, PATCH, DELETE
	calls    []string // "METHOD path"
	// Failure injection.
	failAdd     int    // fail this many item adds with a 500
	failRule    string // a zone whose rule writes fail with a plan limit
	failListNew string // a list name whose creation fails
}

type fakeList struct {
	ID, Name string
	Items    map[string]cloudflare.ListItem
}

func newFakeCF(t *testing.T) (*fakeCF, *cloudflare.Client) {
	f := &fakeCF{account: strings.Repeat("a", 32), lists: map[string]*fakeList{}, rulesets: map[string]*cloudflare.Ruleset{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &cloudflare.Client{Base: srv.URL, Token: "test-token-not-real-0000", HTTP: srv.Client()}
}

func (f *fakeCF) id() string {
	f.next++
	return fmt.Sprintf("id%04d", f.next)
}

func ok(w http.ResponseWriter, result any) {
	b, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "result": result})
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func apiErr(w http.ResponseWriter, status, code int, msg string) {
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": msg}}})
	w.Write(b)
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-token-not-real-0000" {
		apiErr(w, 403, 10000, "Authentication error")
		return
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Method != http.MethodGet {
		f.writes++
	}
	body, _ := io.ReadAll(r.Body)
	seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/accounts":
		ok(w, []cloudflare.Account{{ID: f.account, Name: "Example"}})
	case len(seg) >= 4 && seg[0] == "accounts" && seg[2] == "rules" && seg[3] == "lists":
		f.listsRoute(w, r, seg[4:], body)
	case len(seg) >= 3 && seg[0] == "zones" && seg[2] == "rulesets":
		f.rules(w, r, seg[1], seg[3:], body)
	default:
		apiErr(w, 404, 7003, "no route")
	}
}

func (f *fakeCF) listsRoute(w http.ResponseWriter, r *http.Request, rest []string, body []byte) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		out := []cloudflare.IPList{}
		for _, l := range f.lists {
			out = append(out, cloudflare.IPList{ID: l.ID, Name: l.Name, Kind: "ip", NumItems: len(l.Items)})
		}
		ok(w, out)
	case len(rest) == 0 && r.Method == http.MethodPost:
		var in struct{ Name, Kind string }
		json.Unmarshal(body, &in)
		if in.Name == f.failListNew {
			apiErr(w, 400, 10027, "You have reached the maximum number of lists")
			return
		}
		l := &fakeList{ID: f.id(), Name: in.Name, Items: map[string]cloudflare.ListItem{}}
		f.lists[l.ID] = l
		ok(w, cloudflare.IPList{ID: l.ID, Name: l.Name, Kind: "ip"})
	case len(rest) == 2 && rest[0] == "bulk_operations":
		ok(w, cloudflare.Operation{ID: rest[1], Status: "completed"})
	case len(rest) == 2 && rest[1] == "items":
		l := f.lists[rest[0]]
		if l == nil {
			apiErr(w, 404, 10001, "list not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			out := []cloudflare.ListItem{}
			for _, it := range l.Items {
				out = append(out, it)
			}
			ok(w, out)
		case http.MethodPost:
			if f.failAdd > 0 {
				f.failAdd--
				apiErr(w, 500, 10000, "internal error")
				return
			}
			var in []cloudflare.NewItem
			json.Unmarshal(body, &in)
			for _, it := range in {
				id := f.id()
				l.Items[id] = cloudflare.ListItem{ID: id, IP: it.IP, Comment: it.Comment}
			}
			ok(w, map[string]string{"operation_id": f.id()})
		case http.MethodDelete:
			var in struct{ Items []struct{ ID string } }
			json.Unmarshal(body, &in)
			for _, it := range in.Items {
				delete(l.Items, it.ID)
			}
			ok(w, map[string]string{"operation_id": f.id()})
		}
	default:
		apiErr(w, 404, 7003, "no route")
	}
}

func (f *fakeCF) rules(w http.ResponseWriter, r *http.Request, zone string, rest []string, body []byte) {
	rs := f.rulesets[zone]
	switch {
	case len(rest) == 3 && rest[0] == "phases" && r.Method == http.MethodGet:
		if rs == nil {
			apiErr(w, 404, 10003, "could not find entrypoint ruleset")
			return
		}
		ok(w, rs)
	case len(rest) == 0 && r.Method == http.MethodPost:
		if zone == f.failRule {
			apiErr(w, 400, 20120, "exceeded maximum number of rules in the phase")
			return
		}
		var in cloudflare.Ruleset
		json.Unmarshal(body, &in)
		in.ID = f.id()
		for i := range in.Rules {
			in.Rules[i].ID = f.id()
		}
		f.rulesets[zone] = &in
		ok(w, in)
	case len(rest) == 2 && rest[1] == "rules" && r.Method == http.MethodPost:
		if zone == f.failRule {
			apiErr(w, 400, 20120, "exceeded maximum number of rules in the phase")
			return
		}
		var in cloudflare.Rule
		json.Unmarshal(body, &in)
		in.ID = f.id()
		rs.Rules = append(rs.Rules, in)
		ok(w, rs)
	case len(rest) == 3 && rest[1] == "rules":
		for i, x := range rs.Rules {
			if x.ID != rest[2] {
				continue
			}
			if r.Method == http.MethodDelete {
				rs.Rules = append(rs.Rules[:i], rs.Rules[i+1:]...)
				ok(w, rs)
				return
			}
			var in cloudflare.Rule
			json.Unmarshal(body, &in)
			in.ID = x.ID
			rs.Rules[i] = in
			ok(w, rs)
			return
		}
		apiErr(w, 404, 10004, "rule not found")
	default:
		apiErr(w, 404, 7003, "no route")
	}
}

func (f *fakeCF) list(name string) *fakeList {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.lists {
		if l.Name == name {
			return l
		}
	}
	return nil
}

func (f *fakeCF) itemIPs(name string) []string {
	l := f.list(name)
	if l == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, it := range l.Items {
		out = append(out, it.IP)
	}
	return out
}

func cfRule(ref, expr, action string) cloudflare.Rule {
	return cloudflare.Rule{ID: ref + "-id", Ref: ref, Expression: expr, Action: action, Enabled: true}
}

func cfItem(id, ip string) cloudflare.ListItem { return cloudflare.ListItem{ID: id, IP: ip} }
