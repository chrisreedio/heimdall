// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"testing"
)

func TestSiteLabelsAndMoveHost(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	s.CreateEnv(ctx, "test", "acme", "shared", "")
	h, _, _ := s.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	if err := s.SetSiteLabel(ctx, "test", h.ID, "/var/www/app", "staging"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSiteLabel(ctx, "test", h.ID, "/var/www/app", "development"); err != nil {
		t.Fatal(err)
	}
	labels, _ := s.SiteLabelsByName(ctx)
	if labels[SiteLabelKey("acme", "web-01", "/var/www/app")] != "development" {
		t.Errorf("labels = %v", labels)
	}
	var ve *ValidationError
	if err := s.SetSiteLabel(ctx, "test", h.ID, "/var/www/app", "qa"); !errors.As(err, &ve) {
		t.Errorf("unknown label: %v", err)
	}
	s.SetSiteLabel(ctx, "test", h.ID, "/var/www/app", "")
	if labels, _ := s.SiteLabelsByName(ctx); len(labels) != 0 {
		t.Errorf("label not cleared: %v", labels)
	}
	if err := s.MoveHost(ctx, "test", h.ID, "shared"); err != nil {
		t.Fatal(err)
	}
	if hs, _ := s.ListHosts(ctx, "acme"); hs[0].EnvSlug != "shared" {
		t.Errorf("env = %s", hs[0].EnvSlug)
	}
	if err := s.MoveHost(ctx, "test", h.ID, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing env: %v", err)
	}
}
