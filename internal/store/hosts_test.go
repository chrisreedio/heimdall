// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"strings"
	"testing"
)

func TestAutoNamedHosts(t *testing.T) {
	s, ctx := newStore(t), t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := s.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	a, _, err := s.AddHost(ctx, "test", "acme", "prod", "", nil)
	if err != nil || !a.AutoName || !strings.HasPrefix(a.Name, "pending-") {
		t.Fatalf("auto host = %+v, %v", a, err)
	}
	// The reported hostname is cleaned up and made unique in the org.
	name, ok, err := s.ClaimHostName(ctx, a.ID, "WEB-01")
	if err != nil || !ok || name != "web-01-2" {
		t.Fatalf("claim = %q %v %v", name, ok, err)
	}
	// Only once: a later report doesn't rename it again.
	if _, ok, _ := s.ClaimHostName(ctx, a.ID, "something-else"); ok {
		t.Error("claimed a second time")
	}
	// A host that was named never takes a reported name.
	named, _ := s.HostByName(ctx, "acme", "web-01")
	if _, ok, _ := s.ClaimHostName(ctx, named.ID, "evil"); ok {
		t.Error("named host was renamed by its report")
	}
	// Junk that can't be made into a name is ignored.
	b, _, _ := s.AddHost(ctx, "test", "acme", "prod", "", nil)
	if _, ok, _ := s.ClaimHostName(ctx, b.ID, "---"); ok {
		t.Error("unusable hostname claimed")
	}
	if got := reportedHostName("My Box.local\n"); got != "my-box.local" {
		t.Errorf("reportedHostName = %q", got)
	}
	// Manual rename, and its rules.
	if err := s.RenameHost(ctx, "test", "acme", "web-01-2", "db-01"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameHost(ctx, "test", "acme", "db-01", "web-01"); !errors.Is(err, ErrExists) {
		t.Errorf("rename onto an existing name: %v", err)
	}
	var ve *ValidationError
	if err := s.RenameHost(ctx, "test", "acme", "db-01", "bad name"); !errors.As(err, &ve) {
		t.Errorf("invalid new name: %v", err)
	}
	// Renaming a pending host by hand stops auto-naming.
	if err := s.RenameHost(ctx, "test", "acme", b.Name, "manual"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.HostByName(ctx, "acme", "manual")
	if _, ok, _ := s.ClaimHostName(ctx, m.ID, "reported"); ok || m.AutoName {
		t.Error("hand-renamed host still auto-names")
	}
}

func TestTagging(t *testing.T) {
	s, ctx := newStore(t), t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	a, _, _ := s.AddHost(ctx, "test", "acme", "prod", "a", []string{"web"})
	b, _, _ := s.AddHost(ctx, "test", "acme", "prod", "b", nil)
	if n, err := s.TagHosts(ctx, "test", "Role:LB", []int64{a.ID, b.ID}); err != nil || n != 2 {
		t.Fatalf("tag: %d %v", n, err)
	}
	if n, _ := s.TagHosts(ctx, "test", "role:lb", []int64{a.ID}); n != 0 {
		t.Error("re-adding a tag counted")
	}
	if _, err := s.TagHosts(ctx, "test", "bad tag", []int64{a.ID}); err == nil {
		t.Error("invalid tag accepted")
	}
	if err := s.SetHostTags(ctx, "test", a.ID, []string{"db", "db", "Prod"}); err != nil {
		t.Fatal(err)
	}
	hs, _ := s.ListHosts(ctx, "acme")
	got := map[string]string{}
	for _, h := range hs {
		got[h.Name] = strings.Join(h.Tags, ",")
	}
	if got["a"] != "db,prod" || got["b"] != "role:lb" {
		t.Errorf("tags = %v", got)
	}
}
