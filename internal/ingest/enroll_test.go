// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/secret"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestEnroll(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	_, key, err := e.st.CreateEnrollKey(ctx, "test", "acme", "prod",
		store.NewEnrollKey{Label: "rollout", Tags: []string{"web"}, MaxUses: 2, TTL: time.Hour}, e.now)
	if err != nil {
		t.Fatal(err)
	}
	machine := strings.Repeat("ab", 32)

	w := e.expect(req{token: key, hostname: "web-02.example.com", machine: machine, body: []byte{}}, http.StatusCreated)
	token := strings.TrimSpace(w.Body.String())
	if !secret.LooksLike(token, secret.IngestPrefix) {
		t.Fatalf("body %q isn't an ingest token", token)
	}
	if got := w.Header().Get(HostHeader); got != "web-02.example.com" {
		t.Errorf("host header %q", got)
	}
	h, err := e.st.HostByName(ctx, "acme", "web-02.example.com")
	if err != nil || h.EnvSlug != "prod" || h.AutoName {
		t.Fatalf("enrolled host %+v, %v", h, err)
	}
	if tags, _ := e.st.HostTags(ctx, h.ID); len(tags) != 1 || tags[0] != "web" {
		t.Errorf("tags %v", tags)
	}
	// The new token reports; the key itself never can.
	e.expect(req{token: token}, http.StatusCreated)
	e.expect(req{method: http.MethodGet, token: key}, http.StatusMethodNotAllowed)

	// The same server again is refused, by machine ID.
	w = e.expect(req{token: key, hostname: "web-02", machine: machine, body: []byte{}}, http.StatusConflict)
	if !strings.Contains(w.Body.String(), "already enrolled as web-02.example.com") {
		t.Errorf("conflict body %q", w.Body.String())
	}
	// Hosts added by hand are known by machine ID once they report with it.
	other := strings.Repeat("cd", 32)
	e.expect(req{machine: other}, http.StatusCreated)
	e.expect(req{token: key, machine: other, body: []byte{}}, http.StatusConflict)

	// A second server uses the key up.
	e.expect(req{token: key, hostname: "web-03", body: []byte{}}, http.StatusCreated)
	w = e.expect(req{token: key, hostname: "web-04", body: []byte{}}, http.StatusForbidden)
	if !strings.Contains(w.Body.String(), "used up") {
		t.Errorf("used up body %q", w.Body.String())
	}

	keys, err := e.st.ListEnrollKeys(ctx, "acme")
	if err != nil || len(keys) != 1 || keys[0].Uses != 2 || strings.Join(keys[0].Hosts, ",") != "web-02.example.com,web-03" {
		t.Fatalf("keys %+v, %v", keys, err)
	}
	if s := keys[0].Status(e.now); s != "used up" {
		t.Errorf("status %q", s)
	}

	// Expired and revoked keys.
	_, short, _ := e.st.CreateEnrollKey(ctx, "test", "acme", "prod", store.NewEnrollKey{TTL: time.Minute}, e.now)
	e.now = e.now.Add(2 * time.Minute)
	if w := e.expect(req{token: short, body: []byte{}}, http.StatusForbidden); !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("expired body %q", w.Body.String())
	}
	k2, revoked, _ := e.st.CreateEnrollKey(ctx, "test", "acme", "prod", store.NewEnrollKey{TTL: time.Hour}, e.now)
	if err := e.st.RevokeEnrollKey(ctx, "test", "acme", k2.ID); err != nil {
		t.Fatal(err)
	}
	e.expect(req{token: revoked, body: []byte{}}, http.StatusUnauthorized)
	if err := e.st.RevokeEnrollKey(ctx, "test", "acme", k2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoke twice: %v", err)
	}
	e.expect(req{token: secret.EnrollPrefix + "nope", body: []byte{}}, http.StatusUnauthorized)
}

func TestEnrollKeyLimits(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	for _, c := range []struct {
		ttl  time.Duration
		uses int
	}{{0, 0}, {31 * 24 * time.Hour, 0}, {time.Hour, -1}} {
		if _, _, err := e.st.CreateEnrollKey(ctx, "test", "acme", "prod", store.NewEnrollKey{MaxUses: c.uses, TTL: c.ttl}, e.now); err == nil {
			t.Errorf("ttl %v uses %d: no error", c.ttl, c.uses)
		}
	}
	if _, _, err := e.st.CreateEnrollKey(ctx, "test", "acme", "nope", store.NewEnrollKey{TTL: time.Hour}, e.now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown env: %v", err)
	}
}

func TestEnrollApproval(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	_, key, err := e.st.CreateEnrollKey(ctx, "test", "acme", "prod", store.NewEnrollKey{TTL: time.Hour, Approval: true}, e.now)
	if err != nil {
		t.Fatal(err)
	}
	w := e.expect(req{token: key, hostname: "web-02", machine: strings.Repeat("ef", 32), body: []byte{}}, http.StatusCreated)
	if w.Header().Get(PendingHeader) != "1" {
		t.Errorf("enroll answer lacks %s", PendingHeader)
	}
	token := strings.TrimSpace(w.Body.String())
	h, err := e.st.HostByName(ctx, "acme", "web-02")
	if err != nil {
		t.Fatal(err)
	}

	// Waiting: answered 202, nothing stored; asking the hub's version works.
	w = e.expect(req{token: token, hostname: "web-02"}, http.StatusAccepted)
	if w.Header().Get(PendingHeader) != "1" || !strings.Contains(w.Body.String(), "waiting for approval") {
		t.Errorf("waiting answer %q %v", w.Body.String(), w.Header())
	}
	if _, err := e.st.LatestSnapshot(ctx, h.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("snapshot stored while waiting: %v", err)
	}
	if hosts, _ := e.st.ListHosts(ctx, "acme"); !slicesContainsAwaiting(hosts, "web-02") {
		t.Errorf("web-02 not listed as waiting: %+v", hosts)
	}
	if w := e.expect(req{method: http.MethodGet, token: token}, http.StatusOK); w.Header().Get(PendingHeader) != "1" {
		t.Errorf("version check lacks %s", PendingHeader)
	}

	// Approved: its next report counts.
	if err := e.st.ApproveHost(ctx, "test", "acme", "web-02"); err != nil {
		t.Fatal(err)
	}
	if w := e.expect(req{token: token}, http.StatusCreated); w.Header().Get(PendingHeader) != "" {
		t.Errorf("approved host still marked pending")
	}
	if err := e.st.ApproveHost(ctx, "test", "acme", "web-02"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("approve twice: %v", err)
	}
}

func slicesContainsAwaiting(hosts []store.Host, name string) bool {
	for _, h := range hosts {
		if h.Name == name {
			return h.Awaiting
		}
	}
	return false
}
