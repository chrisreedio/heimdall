// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"
)

func TestHostSSH(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	s.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	h, _ := s.HostByName(ctx, "acme", "web-01")
	if _, ok, err := s.HostSSHOf(ctx, h.ID); ok || err != nil {
		t.Fatalf("before any report: ok %v err %v", ok, err)
	}
	in := HostSSH{Source: "g", Ports: []int{22}, Listen: []string{"0.0.0.0"}, Password: "yes", KbdInteractive: "no", PAM: "yes", RootLogin: "no"}
	if err := s.SetHostSSH(ctx, h.ID, in, newsNow); err != nil {
		t.Fatal(err)
	}
	in.Password = "no"
	if err := s.SetHostSSH(ctx, h.ID, in, newsNow); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.HostSSHOf(ctx, h.ID)
	if !ok || err != nil || got.Password != "no" || got.Listen[0] != "0.0.0.0" || !got.SeenAt.Equal(newsNow) {
		t.Fatalf("HostSSHOf = %+v %v %v", got, ok, err)
	}
	all, err := s.HostSSHs(ctx)
	if err != nil || len(all) != 1 || all[h.ID].RootLogin != "no" {
		t.Fatalf("HostSSHs = %+v %v", all, err)
	}
}

func TestPasswordLogin(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		pw, kbd, pam string
		on, known    bool
	}{
		{"yes", "no", "yes", true, true},
		{"no", "yes", "yes", true, true}, // keyboard-interactive through PAM asks for the password
		{"no", "yes", "no", false, true},
		{"no", "no", "yes", false, true},
		{"no", "", "", false, false},
		{"", "", "", false, false},
	} {
		on, known := HostSSH{Password: c.pw, KbdInteractive: c.kbd, PAM: c.pam}.PasswordLogin()
		if on != c.on || known != c.known {
			t.Errorf("%+v: PasswordLogin = %v %v, want %v %v", c, on, known, c.on, c.known)
		}
	}
}
