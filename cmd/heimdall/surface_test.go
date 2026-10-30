// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

func TestSurfaceCommand(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "heimdall.toml")
	os.WriteFile(cfgPath, []byte("database = \"h.db\"\n[cloudflare]\nenabled = true\n"), 0o600)
	dbPath := filepath.Join(dir, "h.db")
	storetest.WriteFile(t, dbPath)
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"-c", cfgPath, "migrate"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	ctx := t.Context()
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	acme, _ := st.CreateOrg(ctx, "test", "acme", "acme")
	st.CreateOrg(ctx, "test", "other", "other")
	for _, org := range []string{"acme", "other"} {
		st.CreateEnv(ctx, "test", org, "prod", "")
	}
	h, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	st.RecordReportIP(ctx, h.ID, "203.0.113.10")
	h2, _, _ := st.AddHost(ctx, "test", "other", "prod", "web-09", nil)
	st.RecordReportIP(ctx, h2.ID, "203.0.113.20")
	const zone = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now()
	if err := st.ReplaceCloudflareZones(ctx, []store.CloudflareZone{{ID: zone, Name: "example.com", Plan: "Free Website"}},
		map[string][]store.CloudflareRecord{zone: {
			{Name: "api.example.com", Type: "A", Content: "203.0.113.10", TTL: 1},
			{Name: "partner.example.com", Type: "A", Content: "203.0.113.20", Proxied: true, TTL: 1},
		}}, now); err != nil {
		t.Fatal(err)
	}
	st.AddSurfaceChanges(ctx, []store.SurfaceChange{{At: now, ZoneID: zone, Zone: "example.com", Name: "api.example.com",
		Kind: store.SurfaceUnproxied, Old: "proxied", New: "not proxied", Orgs: []int64{acme.ID}}}, now)
	st.Close()

	out.Reset()
	if err := run(ctx, []string{"-c", cfgPath, "surface"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	o := out.String()
	for _, want := range []string{"NAME", "api.example.com", "unproxied,exposed", "acme/web-01", "partner.example.com", "other/web-09"} {
		if !strings.Contains(o, want) {
			t.Errorf("table missing %q:\n%s", want, o)
		}
	}
	out.Reset()
	if err := run(ctx, []string{"-c", cfgPath, "surface", "--org", "acme", "--json"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	var got struct {
		Rows []struct {
			Name    string `json:"name"`
			Exposed bool   `json:"exposed"`
		} `json:"rows"`
		Changes []struct{ Kind string } `json:"changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err, out.String())
	}
	if len(got.Rows) != 1 || got.Rows[0].Name != "api.example.com" || !got.Rows[0].Exposed || len(got.Changes) != 1 {
		t.Errorf("json: %+v", got)
	}
	out.Reset()
	if err := run(ctx, []string{"-c", cfgPath, "surface", "--changes"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if o := out.String(); !strings.Contains(o, "unproxied") || !strings.Contains(o, now.Local().Format("2006-01-02")) {
		t.Errorf("changes:\n%s", o)
	}
	if err := run(ctx, []string{"-c", cfgPath, "surface", "--org", "nope"}, &out, &errb); err == nil {
		t.Error("unknown org accepted")
	}
}
