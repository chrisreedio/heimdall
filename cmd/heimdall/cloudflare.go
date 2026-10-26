// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// cloudflareCredential is the systemd credential name holding the token.
const cloudflareCredential = "heimdall-cloudflare"

// defaultCloudflareTokenFile is where the unit's LoadCredential line reads it.
const defaultCloudflareTokenFile = "/etc/heimdall/cloudflare-token"

// Seams for tests: the HTTP client (allowlisted to the API host and
// www.cloudflare.com) and the edge-range URLs (nil: the published ones).
var (
	cloudflareHTTPClient = func(cfg config.Cloudflare) *http.Client {
		return cloudflare.NewHTTP(cfg.Host(), "heimdall/"+version)
	}
	cloudflareEdgeURLs []string
)

// cloudflareLists is the IP list sync, for the settings page's "sync now";
// set by newCloudflare when there's a token.
var cloudflareLists *cloudflare.ListSyncer

// cloudflareEdge is the edge set serve's ingest handler trusts for
// CF-Connecting-IP; set by newCloudflare when [cloudflare] allows it.
var cloudflareEdge *cloudflare.Edge

// cloudflareTrustedEdge is ingest's TrustedEdge hook: nil (never trust
// CF-Connecting-IP) unless [cloudflare] is on with connecting_ip.
func cloudflareTrustedEdge() func(netip.Addr) bool {
	if cloudflareEdge == nil {
		return nil
	}
	return cloudflareEdge.Contains
}

// newCloudflare builds the Cloudflare syncers for serve and adds Radar to
// the resolver's sources. The edge ranges need no token and always sync;
// the rest needs the token, and a missing one is logged, not fatal.
func newCloudflare(cfg config.Config, s *store.Store, log *slog.Logger, r *ipinfo.Resolver) []ipinfo.Syncer {
	c := cfg.Cloudflare
	log = log.With("component", "cloudflare")
	hc := cloudflareHTTPClient(c)
	edge := cloudflare.NewEdge()
	es := &cloudflare.EdgeSyncer{Store: s, Edge: edge, HTTP: hc, URLs: cloudflareEdgeURLs, Now: time.Now}
	if err := es.Load(context.Background()); err != nil {
		log.Warn("Cloudflare edge ranges not loaded; using the built-in list", "err", err)
	}
	cloudflareEdge, cloudflareLists = nil, nil
	if c.ConnectingIP {
		cloudflareEdge = edge
		if !cfg.Ingest.BehindProxy {
			log.Info("cloudflare.connecting_ip has no effect without ingest.behind_proxy")
		}
	}
	syncers := []ipinfo.Syncer{es}
	token, _, err := cloudflareToken(false)
	if err != nil {
		log.Warn("Cloudflare is on without a token: only the edge ranges are synced", "err", err)
		return syncers
	}
	client := &cloudflare.Client{Base: c.APIBase, Token: token, HTTP: hc, UserAgent: "heimdall/" + version}
	syncers = append(syncers, &cloudflare.Syncer{Client: client, Store: s, Zones: c.Zones, Security: c.SecurityEvents,
		Interval: c.SyncEvery.Duration, Now: time.Now, Log: log, Surface: true, Edge: edge})
	cloudflareLists = &cloudflare.ListSyncer{Client: client, Store: s, Now: time.Now, Log: log} // IP labels from mapped IP lists
	syncers = append(syncers, cloudflareLists)
	if c.Radar {
		radar := &cloudflare.Radar{Client: client, Store: s, Edge: edge, Now: time.Now, Log: log}
		r.Sources = append(r.Sources, radar)
		syncers = append(syncers, radar)
	}
	log.Info("Cloudflare on", "zones", len(c.Zones), "sync_every", c.SyncEvery.Duration.String(),
		"security_events", c.SecurityEvents, "radar", c.Radar, "connecting_ip", c.ConnectingIP)
	return syncers
}

// cmdCloudflareSetToken stores the API token exactly like `ai set-key`
// stores the AI key: read with echo off (or from stdin), written
// owner-only and atomically, and loaded by the hub as a systemd credential.
func cmdCloudflareSetToken(a *app, args []string) error {
	fs := a.flags("cloudflare set-token", "[--file path] [--stdin] [--unit path]")
	path := fs.String("file", defaultCloudflareTokenFile, "where to store the token (the unit's LoadCredential source)")
	fromStdin := fs.Bool("stdin", false, "read the token from stdin instead of a terminal prompt")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var token string
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	} else {
		in, err := newInput(a, false)
		if err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the token")
		}
		printCloudflareTokenURL(a.stderr)
		if token, err = in.line("Cloudflare API token (input hidden): ", true); err != nil {
			return err
		}
		token = strings.TrimSpace(token)
	}
	if token == "" {
		return errors.New("empty token")
	}
	if len(token) < 20 || len(token) > 4096 || strings.ContainsFunc(token, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("that doesn't look like an API token (create one under My Profile > API Tokens; see docs/cloudflare.md)")
	}
	if err := writePrivate(*path, token+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the Cloudflare API token in %s (owner-only).\n", *path)
	if *path == defaultCloudflareTokenFile || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, cloudflareCredential, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself, then: sudo heimdall restart\n", err, cloudflareCredential, *path)
			return nil
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", cloudflareCredential, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	fmt.Fprintln(a.stderr, "Check it with `sudo heimdall cloudflare status`, then apply with: sudo heimdall restart")
	return nil
}

// cloudflareToken reads the token from the systemd credential, or from
// HEIMDALL_CLOUDFLARE_TOKEN_FILE. It is never read from the config file.
// With fallback (CLI as root), the default token file is used directly.
func cloudflareToken(fallback bool) (string, string, error) {
	path, fromSystemd := os.Getenv("HEIMDALL_CLOUDFLARE_TOKEN_FILE"), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, cloudflareCredential)); err == nil {
				path, fromSystemd = filepath.Join(dir, cloudflareCredential), true
			}
		}
	}
	if path == "" && keyFallback(fallback) {
		path = defaultCloudflareTokenFile
	}
	if path == "" {
		return "", "", errors.New("no Cloudflare token: run `sudo heimdall cloudflare set-token` (it adds `LoadCredential=" +
			cloudflareCredential + ":" + defaultCloudflareTokenFile + "` to the unit), or set HEIMDALL_CLOUDFLARE_TOKEN_FILE")
	}
	perm, b, err := readKeyFile(path)
	if err != nil {
		return "", path, fmt.Errorf("cloudflare token: %w", err)
	}
	if !fromSystemd && perm&0o077 != 0 {
		return "", path, fmt.Errorf("cloudflare token %s is readable by other users; run `chmod 600 %s`", path, path)
	}
	if len(b) > 4096 {
		return "", path, fmt.Errorf("cloudflare token %s is suspiciously large", path)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", path, fmt.Errorf("cloudflare token %s is empty", path)
	}
	return token, path, nil
}

// datasetShort names the GraphQL datasets in status output.
var datasetShort = map[string]string{
	"firewallEventsAdaptiveGroups": "events", "firewallEventsAdaptive": "events-raw",
	"httpRequests1hGroups": "requests-1h", "httpRequestsAdaptiveGroups": "requests-adaptive",
}

// cmdCloudflareStatus shows the config, checks the token live (never
// printing it), and lists the zones it can see with each zone's plan and
// which analytics datasets it can query, then the last syncs.
func cmdCloudflareStatus(a *app, args []string) error {
	if _, err := parse(a.flags("cloudflare status", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	c, out := cfg.Cloudflare, a.stdout
	if !c.Enabled {
		fmt.Fprintln(out, "Cloudflare: off (set enabled = true under [cloudflare] in heimdall.toml)")
		return nil
	}
	zones := "all the token can read"
	if len(c.Zones) > 0 {
		zones = strings.Join(c.Zones, ", ")
	}
	fmt.Fprintf(out, "Cloudflare:  on\nZones:       %s\nSync:        every %s (security events %s, Radar %s)\n", zones,
		c.SyncEvery.Duration, onOff(c.SecurityEvents), onOff(c.Radar))
	switch {
	case !c.ConnectingIP:
		fmt.Fprintln(out, "Client IP:   CF-Connecting-IP never trusted (connecting_ip = false)")
	case !cfg.Ingest.BehindProxy:
		fmt.Fprintln(out, "Client IP:   CF-Connecting-IP unused (ingest.behind_proxy is off)")
	default:
		fmt.Fprintln(out, "Client IP:   CF-Connecting-IP trusted only from Cloudflare's edge, via the local proxy")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	syncs, err := s.CloudflareSyncs(a.ctx)
	if err != nil {
		return err
	}
	token, path, terr := cloudflareToken(isRoot())
	if terr != nil {
		fmt.Fprintf(out, "Token:       not usable: %v\n", terr)
	} else {
		fmt.Fprintf(out, "Token:       loaded from %s\n", path)
	}
	if terr == nil {
		ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
		defer cancel()
		cl := &cloudflare.Client{Base: c.APIBase, Token: token, HTTP: cloudflareHTTPClient(c), UserAgent: "heimdall/" + version}
		switch t, err := cl.VerifyToken(ctx); {
		case err != nil:
			fmt.Fprintf(out, "Token check: %v (an account-owned token can fail this check and still work)\n", err)
		default:
			exp := ""
			if t.ExpiresOn != "" {
				exp = ", expires " + t.ExpiresOn
			}
			fmt.Fprintf(out, "Token check: %s%s\n", t.Status, exp)
		}
		all, err := cl.Zones(ctx)
		if err != nil {
			fmt.Fprintf(out, "Zones:       can't list (%v); the token needs Zone > Zone > Read\n", err)
		} else {
			want := cloudflare.Wanted(all, c.Zones)
			fmt.Fprintf(out, "Visible:     %d zones (%d synced)\n\n", len(all), len(want))
			var rows [][]string
			for _, z := range want {
				var ds []string
				for _, d := range cloudflare.Datasets {
					set, err := cl.DatasetSettings(ctx, z.ID, d)
					switch {
					case err != nil && cloudflare.IsPermission(err):
						ds = append(ds, datasetShort[d]+":no-permission")
					case err != nil:
						ds = append(ds, datasetShort[d]+":?")
					case set.Enabled:
						ds = append(ds, fmt.Sprintf("%s:%s", datasetShort[d], spanDays(set.NotOlderThan)))
					default:
						ds = append(ds, datasetShort[d]+":no")
					}
				}
				rows = append(rows, []string{z.Name, z.Plan.Name, z.Status, strings.Join(ds, " ")})
			}
			if err := table(a, "ZONE\tPLAN\tSTATUS\tDATASETS (days back)", rows); err != nil {
				return err
			}
			for _, w := range c.Zones {
				if len(cloudflare.Wanted(all, []string{w})) == 0 {
					fmt.Fprintf(out, "Note: zone %q is in the config but not visible to the token\n", w)
				}
			}
		}
		if c.Radar {
			switch _, err := cl.ASNByIP(ctx, netip.MustParseAddr("1.1.1.1")); {
			case err == nil:
				fmt.Fprintln(out, "\nRadar:       ok")
			case cloudflare.IsPermission(err):
				fmt.Fprintln(out, "\nRadar:       no permission (add Account > Radar > Read, or set radar = false)")
			default:
				fmt.Fprintf(out, "\nRadar:       %v\n", err)
			}
		}
	}
	fmt.Fprintln(out)
	var rows [][]string
	for _, w := range []string{"edge", "zones", "radar"} {
		st, ok := syncs[w]
		if !ok {
			rows = append(rows, []string{w, "never", ""})
			continue
		}
		status := "ok"
		if st.Error != "" {
			status = st.Error
		}
		rows = append(rows, []string{w, formatTime(st.At), status})
	}
	// IP lists keep their state with the other IP label sources.
	row := []string{"ip lists", "never", ""}
	if states, err := s.IPSourceStates(a.ctx); err == nil {
		for _, st := range states {
			if st.Source == cloudflare.ListsSource {
				row[1], row[2] = formatTime(st.LastAttempt), cmp.Or(st.LastError, "ok")
			}
		}
	}
	if lists, err := s.CloudflareIPLists(a.ctx); err == nil && len(lists) > 0 {
		mapped := 0
		for _, l := range lists {
			if l.Kind != store.CFListIgnore {
				mapped++
			}
		}
		row[2] += fmt.Sprintf(" (%d of %d lists mapped, on /cloudflare)", mapped, len(lists))
	}
	rows = append(rows, row)
	return table(a, "SYNC\tLAST RUN\tRESULT", rows)
}

func spanDays(secs int64) string {
	if secs <= 0 {
		return "yes"
	}
	return strconv.FormatInt(secs/86400, 10) + "d"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// cmdCloudflareSync syncs the edge ranges and (with a token) the zones now.
func cmdCloudflareSync(a *app, args []string) error {
	if _, err := parse(a.flags("cloudflare sync", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	c := cfg.Cloudflare
	if !c.Enabled {
		return errors.New("[cloudflare] is off; set enabled = true in heimdall.toml first")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	hc := cloudflareHTTPClient(c)
	es := &cloudflare.EdgeSyncer{Store: s, Edge: cloudflare.NewEdge(), HTTP: hc, URLs: cloudflareEdgeURLs, Now: time.Now}
	if err := es.Sync(a.ctx); err != nil {
		fmt.Fprintf(a.stderr, "edge ranges: %v\n", err)
	} else {
		fmt.Fprintf(a.stderr, "edge ranges: %d\n", len(es.Edge.Prefixes()))
		resolveKnownCLI(a, s) // ipinfo.go
	}
	token, _, err := cloudflareToken(isRoot())
	if err != nil {
		return err
	}
	cl := &cloudflare.Client{Base: c.APIBase, Token: token, HTTP: hc, UserAgent: "heimdall/" + version}
	sy := &cloudflare.Syncer{Client: cl, Store: s, Zones: c.Zones, Security: c.SecurityEvents, Interval: c.SyncEvery.Duration, Now: time.Now, Surface: true, Edge: es.Edge}
	serr := sy.Sync(a.ctx)
	zs, err := s.CloudflareZones(a.ctx)
	if err != nil {
		return err
	}
	recs, err := s.CloudflareRecords(a.ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "zones: %d, records: %d\n", len(zs), len(recs))
	// IP lists are optional (their own permission): an error is reported,
	// not fatal.
	ls := &cloudflare.ListSyncer{Client: cl, Store: s, Now: time.Now}
	if err := ls.Sync(a.ctx); err != nil {
		fmt.Fprintf(a.stderr, "IP lists: %v\n", err)
	} else if lists, err := s.CloudflareIPLists(a.ctx); err == nil {
		mapped := slices.DeleteFunc(lists, func(l store.CloudflareIPList) bool { return l.Kind == store.CFListIgnore })
		fmt.Fprintf(a.stderr, "IP lists: %d mapped to labels (map them on /cloudflare)\n", len(mapped))
		resolveKnownCLI(a, s)
	}
	if serr != nil {
		return fmt.Errorf("sync finished with errors (the last good data is kept): %w", serr)
	}
	return nil
}

// cmdCloudflareTokenURL prints the dashboard link that pre-fills a
// read-only token with exactly the permissions Heimdall uses.
func cmdCloudflareTokenURL(a *app, args []string) error {
	if _, err := parse(a.flags("cloudflare token-url", ""), args, 0); err != nil {
		return err
	}
	printCloudflareTokenURL(a.stdout)
	return nil
}

func printCloudflareTokenURL(w io.Writer) {
	fmt.Fprintf(w, "Create the token here (permissions pre-filled, read-only; check them, then Create):\n\n  %s\n\nAlso add by hand: %s.\nThen paste it into: sudo heimdall cloudflare set-token\n\n",
		cloudflare.TokenURL("Heimdall (read-only)", cloudflare.ReadPerms), cloudflare.ReadManual)
}
