// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/anomaly"
	"github.com/realmwatch/heimdall/internal/bans"
	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/logins"
	"github.com/realmwatch/heimdall/internal/notify"
	"github.com/realmwatch/heimdall/internal/store"
)

// Bans (docs/bans.md): scored offenders, proposed or recorded (shadow),
// written to Cloudflare with a second token of their own.

// bansCredential is the systemd credential holding the write token.
const bansCredential = "heimdall-cloudflare-bans"

// defaultBansTokenFile is where the unit's LoadCredential line reads it.
const defaultBansTokenFile = "/etc/heimdall/cloudflare-bans-token"

// bansService is what serve hands the UI (set by startBans).
var bansService *bans.Service

// banAlertEvery is how often the login and surface alerts are checked.
var banAlertEvery = 5 * time.Minute

// startBans starts the ban engine and enforcer (when [bans] is on) and the
// alerts that come with failed logins and the surface map (always).
func startBans(ctx context.Context, cfg config.Config, s *store.Store, log *slog.Logger, ips *ipinfo.Resolver) *bans.Service {
	log = log.With("component", "bans")
	edge := cloudflareEdgeSet()
	go runBanAlerts(ctx, cfg, s, log, ips, edge)
	c := cfg.Bans
	svc := &bans.Service{Cfg: c, Cloudflare: cfg.Cloudflare.Enabled}
	bansService = svc
	enf := &bans.Enforcer{Store: s, Cfg: c, Edge: edge, Now: time.Now, Log: log}
	svc.Enforcer = enf
	svc.Engine = &bans.Engine{Store: s, Ranker: &logins.Ranker{Store: s, IPs: ips, Edge: edge}, Cfg: c, Now: time.Now, Log: log,
		BaseURL: cfg.UI.BaseURL, Kick: enf.Kick, Notify: func(ctx context.Context, a notify.Alert) error {
			dests, cerr := senders(cfg)
			if len(dests) == 0 {
				return cerr
			}
			_, err := sendAlert(ctx, s, dests, a)
			return errors.Join(cerr, err)
		}}
	// The token is loaded in every mode: in shadow or off the enforcer
	// never adds anything, but still takes down bans an earlier propose or
	// auto mode left behind, as they expire.
	if token, _, err := bansToken(false); err != nil {
		svc.TokenNote = err.Error()
		if c.Writes() {
			log.Warn("bans can't write to Cloudflare yet", "err", err)
		}
	} else {
		enf.Client = &cloudflare.Client{Base: cfg.Cloudflare.APIBase, Token: token, HTTP: cloudflareHTTPClient(cfg.Cloudflare),
			UserAgent: "heimdall/" + version}
	}
	go bans.Loop(ctx, log, enf, enf.Kicks())
	if !c.On() {
		return svc
	}
	go bans.Loop(ctx, log, svc.Engine, nil)
	log.Info("bans on", "mode", c.Mode, "propose_at", c.ProposeAt, "max_per_hour", c.MaxPerHour, "max_active", c.MaxActive)
	return svc
}

// cloudflareEdgeSet is the edge newCloudflare loaded, or the built-in list.
func cloudflareEdgeSet() *cloudflare.Edge {
	if cloudflareEdge != nil {
		return cloudflareEdge
	}
	return cloudflare.NewEdge()
}

func runBanAlerts(ctx context.Context, cfg config.Config, s *store.Store, log *slog.Logger, ips *ipinfo.Resolver, edge *cloudflare.Edge) {
	e := &anomaly.Engine{Store: s, Now: time.Now, Log: log}
	t := time.NewTicker(banAlertEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := e.CheckLoginSucceeded(ctx, ips, edge); err != nil {
			log.Warn("then-succeeded check failed", "err", err)
		} else if n > 0 {
			log.Warn("logins succeeded after failing, from unknown addresses", "count", n)
		}
		if cfg.Cloudflare.Enabled {
			if n, err := e.CheckSurface(ctx); err != nil {
				log.Warn("surface alert check failed", "err", err)
			} else if n > 0 {
				log.Warn("surface alerts", "count", n)
			}
		}
	}
}

// bansToken reads the write token like cloudflareToken reads the
// read-only one: the systemd credential, or HEIMDALL_CLOUDFLARE_BANS_TOKEN_FILE;
// with fallback (CLI as root), the default file. Never the config file.
func bansToken(fallback bool) (string, string, error) {
	path, fromSystemd := os.Getenv("HEIMDALL_CLOUDFLARE_BANS_TOKEN_FILE"), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, bansCredential)); err == nil {
				path, fromSystemd = filepath.Join(dir, bansCredential), true
			}
		}
	}
	if path == "" && keyFallback(fallback) {
		path = defaultBansTokenFile
	}
	if path == "" {
		return "", "", errors.New("no ban token: run `sudo heimdall bans set-token` (it adds `LoadCredential=" +
			bansCredential + ":" + defaultBansTokenFile + "` to the unit), or set HEIMDALL_CLOUDFLARE_BANS_TOKEN_FILE")
	}
	perm, b, err := readKeyFile(path)
	if err != nil {
		return "", path, fmt.Errorf("ban token: %w", err)
	}
	if !fromSystemd && perm&0o077 != 0 {
		return "", path, fmt.Errorf("ban token %s is readable by other users; run `chmod 600 %s`", path, path)
	}
	if len(b) > 4096 {
		return "", path, fmt.Errorf("ban token %s is suspiciously large", path)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", path, fmt.Errorf("ban token %s is empty", path)
	}
	return token, path, nil
}

// cmdBansSetToken stores the write token exactly like `cloudflare
// set-token`: read with echo off (or from stdin), written owner-only and
// atomically, and loaded by the hub as a systemd credential.
func cmdBansSetToken(a *app, args []string) error {
	fs := a.flags("bans set-token", "[--file path] [--stdin] [--unit path]")
	path := fs.String("file", defaultBansTokenFile, "where to store the token (the unit's LoadCredential source)")
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
		if token, err = in.line("Cloudflare ban (write) token (input hidden): ", true); err != nil {
			return err
		}
		token = strings.TrimSpace(token)
	}
	if token == "" {
		return errors.New("empty token")
	}
	if len(token) < 20 || len(token) > 4096 || strings.ContainsFunc(token, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("that doesn't look like an API token (create one with `heimdall bans token-url`; see docs/bans.md)")
	}
	if err := writePrivate(*path, token+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the Cloudflare ban token in %s (owner-only).\n", *path)
	if *path == defaultBansTokenFile || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, bansCredential, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself, then: sudo heimdall restart\n", err, bansCredential, *path)
			return nil
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", bansCredential, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	fmt.Fprintln(a.stderr, "Check it with `sudo heimdall bans status`, then apply with: sudo heimdall restart")
	return nil
}

// cmdBansTokenURL prints the pre-filled "create token" link.
func cmdBansTokenURL(a *app, args []string) error {
	if _, err := parse(a.flags("bans token-url", ""), args, 0); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, bans.TokenURL())
	fmt.Fprintf(a.stderr, "\nThe form is pre-filled with Zone > Zone WAF > Edit. Add %s by hand\n"+
		"(Cloudflare doesn't document its key), then store it with: sudo heimdall bans set-token\n", bans.TokenManualStep)
	return nil
}

// banJSON is a ban in --json output.
type banJSON struct {
	ID        int64         `json:"id"`
	Target    string        `json:"target"`
	Kind      string        `json:"kind"`
	Action    string        `json:"action"`
	Status    string        `json:"status"`
	Score     float64       `json:"score"`
	Breakdown []bans.Factor `json:"breakdown"`
	Evidence  bans.Evidence `json:"evidence"`
	Days      int           `json:"days"`
	Offense   int           `json:"offense"`
	Created   time.Time     `json:"created_at"`
	DecidedBy string        `json:"decided_by,omitempty"`
	Started   *time.Time    `json:"started_at,omitempty"`
	Expires   *time.Time    `json:"expires_at,omitempty"`
	EndReason string        `json:"end_reason,omitempty"`
	LastError string        `json:"last_error,omitempty"`
}

func toBanJSON(b store.Ban) banJSON {
	fs, ev := bans.Decode(b)
	out := banJSON{ID: b.ID, Target: b.Target, Kind: b.Kind, Action: b.Action, Status: b.Status, Score: b.Score,
		Breakdown: fs, Evidence: ev, Days: int(b.Duration.Hours() / 24), Offense: b.Offense, Created: b.CreatedAt,
		DecidedBy: b.DecidedBy, EndReason: b.EndReason, LastError: b.LastError}
	if !b.StartedAt.IsZero() {
		out.Started = &b.StartedAt
	}
	if !b.ExpiresAt.IsZero() {
		out.Expires = &b.ExpiresAt
	}
	return out
}

func printJSON(a *app, v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// cmdBansStatus shows the mode, the pause switch, the token, the lists and
// zones, and how many bans are where.
func cmdBansStatus(a *app, args []string) error {
	fs := a.flags("bans status", "[--json]")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	pause, err := s.BanPaused(a.ctx)
	if err != nil {
		return err
	}
	lists, err := bans.Lists(a.ctx, s)
	if err != nil {
		return err
	}
	sync, err := bans.LastSync(a.ctx, s)
	if err != nil {
		return err
	}
	zones, err := s.BanZones(a.ctx)
	if err != nil {
		return err
	}
	all, err := s.Bans(a.ctx, store.BanQuery{Limit: 100000})
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, b := range all {
		counts[b.Status]++
	}
	_, tokenPath, terr := bansToken(isRoot())
	if *asJSON {
		type zoneJSON struct {
			Zone    string `json:"zone"`
			Enabled bool   `json:"enabled"`
			State   string `json:"state"`
			Note    string `json:"note,omitempty"`
		}
		out := struct {
			Mode   string          `json:"mode"`
			Paused store.BanPause  `json:"paused"`
			Token  bool            `json:"token"`
			Lists  bans.ListsState `json:"lists"`
			Sync   bans.SyncState  `json:"last_sync"`
			Counts map[string]int  `json:"counts"`
			Zones  []zoneJSON      `json:"zones"`
		}{Mode: cfg.Bans.Mode, Paused: pause, Token: terr == nil, Lists: lists, Sync: sync, Counts: counts}
		for _, z := range zones {
			out.Zones = append(out.Zones, zoneJSON{Zone: z.Zone, Enabled: z.Enabled, State: z.State, Note: z.Note})
		}
		return printJSON(a, out)
	}
	out := a.stdout
	fmt.Fprintf(out, "Mode:     %s\n", cfg.Bans.Mode)
	if pause.Paused {
		fmt.Fprintf(out, "Paused:   yes, by %s at %s (no Cloudflare writes)\n", pause.By, formatTime(pause.At))
	} else {
		fmt.Fprintln(out, "Paused:   no")
	}
	switch {
	case terr != nil:
		fmt.Fprintf(out, "Token:    not usable: %v\n", terr)
	default:
		fmt.Fprintf(out, "Token:    loaded from %s\n", tokenPath)
	}
	if lists.Challenge.ID != "" {
		fmt.Fprintf(out, "Lists:    %s (challenge), %s (block)\n", lists.Challenge.Name, map[bool]string{true: lists.Challenge.Name + ": fallback", false: lists.Block.Name}[lists.Fallback])
	}
	if !sync.At.IsZero() {
		res := "ok"
		if sync.Error != "" {
			res = sync.Error
		}
		fmt.Fprintf(out, "Synced:   %s (%s)\n", formatTime(sync.At), res)
	}
	fmt.Fprintf(out, "Bans:     %d proposed, %d pending, %d active, %d lifting, %d shadow, %d ended\n",
		counts[store.BanProposed], counts[store.BanPending], counts[store.BanActive], counts[store.BanLifting],
		counts[store.BanShadow], counts[store.BanEnded])
	if len(zones) == 0 {
		fmt.Fprintln(out, "Zones:    none opted in (turn them on on the /bans page)")
		return nil
	}
	fmt.Fprintln(out)
	var rows [][]string
	for _, z := range zones {
		rows = append(rows, []string{z.Zone, onOff(z.Enabled), z.State, z.Note})
	}
	return table(a, "ZONE\tBAN RULE\tSTATE\tNOTE", rows)
}

// cmdBansList lists bans, or (--candidates) the current scores.
func cmdBansList(a *app, args []string) error {
	fs := a.flags("bans list", "[--status proposed|active|shadow|...] [--candidates] [--json]")
	status := fs.String("status", "", "only bans in this status")
	cands := fs.Bool("candidates", false, "score the current offenders instead (each score's breakdown)")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if *cands {
		r, _ := newIPResolver(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
		e := &bans.Engine{Store: s, Ranker: &logins.Ranker{Store: s, IPs: r}, Cfg: cfg.Bans, Now: time.Now}
		cs, err := e.Candidates(a.ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			type candJSON struct {
				Target   string        `json:"target"`
				Kind     string        `json:"kind"`
				Action   string        `json:"action"`
				Score    float64       `json:"score"`
				Over     bool          `json:"over_threshold"`
				Skip     string        `json:"friendly,omitempty"`
				Factors  []bans.Factor `json:"breakdown"`
				Evidence bans.Evidence `json:"evidence"`
			}
			out := []candJSON{}
			for _, c := range cs {
				out = append(out, candJSON{Target: bans.TargetString(c.Target), Kind: c.Kind, Action: c.Action, Score: c.Score,
					Over: c.Over, Skip: c.Skip, Factors: c.Factors, Evidence: c.Evidence})
			}
			return printJSON(a, out)
		}
		var rows [][]string
		for _, c := range cs {
			var parts []string
			for _, f := range c.Factors {
				parts = append(parts, fmt.Sprintf("%s %g→%.1f", f.Name, f.Value, f.Points))
			}
			mark := ""
			switch {
			case c.Skip != "":
				mark = "friendly: " + c.Skip
			case c.Over:
				mark = "over"
			}
			rows = append(rows, []string{bans.TargetString(c.Target), strconv.FormatFloat(c.Score, 'f', 1, 64), c.Action, strings.Join(parts, " "), mark})
		}
		fmt.Fprintf(a.stderr, "Proposed at %.1f.\n", cfg.Bans.ProposeAt)
		return table(a, "TARGET\tSCORE\tACTION\tBREAKDOWN\t", rows)
	}
	q := store.BanQuery{Limit: 1000}
	if *status != "" {
		q.Statuses = []string{*status}
	}
	bs, err := s.Bans(a.ctx, q)
	if err != nil {
		return err
	}
	if *asJSON {
		out := []banJSON{}
		for _, b := range bs {
			out = append(out, toBanJSON(b))
		}
		return printJSON(a, out)
	}
	var rows [][]string
	for _, b := range bs {
		exp := ""
		if !b.ExpiresAt.IsZero() {
			exp = formatTime(b.ExpiresAt)
		}
		rows = append(rows, []string{strconv.FormatInt(b.ID, 10), b.Target, b.Action, b.Status,
			strconv.FormatFloat(b.Score, 'f', 1, 64), strconv.Itoa(int(b.Duration.Hours()/24)) + "d", exp, b.LastError})
	}
	return table(a, "ID\tTARGET\tACTION\tSTATUS\tSCORE\tDAYS\tEXPIRES\tNOTE", rows)
}

// banDecision approves, rejects or unbans one ban from the CLI. The hub
// writes the change to Cloudflare on its next sync (within a minute).
func banDecision(action string) command {
	return func(a *app, args []string) error {
		fs := a.flags("bans "+action, "[--note \"...\"] <id>")
		note := fs.String("note", "", "why (kept in the audit log)")
		pos, err := parse(fs, args, 1)
		if err != nil {
			return err
		}
		id, err := strconv.ParseInt(pos[0], 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a ban ID (see `heimdall bans list`)", pos[0])
		}
		cfg, err := config.Load(a.configPath)
		if err != nil {
			return err
		}
		if action == "approve" && !cfg.Bans.Writes() {
			return fmt.Errorf("[bans] mode is %q, which writes nothing to Cloudflare; set mode = \"propose\" first", cfg.Bans.Mode)
		}
		s, err := a.openStore()
		if err != nil {
			return err
		}
		defer s.Close()
		switch action {
		case "approve", "reject":
			err = s.DecideBan(a.ctx, id, action == "approve", actor(), *note, time.Now())
		default:
			err = s.Unban(a.ctx, id, actor(), time.Now())
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "Ban %d: %s. The hub applies it at Cloudflare within a minute.\n", id, map[string]string{
			"approve": "approved", "reject": "rejected", "unban": "unbanned"}[action])
		return nil
	}
}

// banPauseCmd flips the "pause all" switch.
func banPauseCmd(paused bool) command {
	name := map[bool]string{true: "pause", false: "resume"}[paused]
	return func(a *app, args []string) error {
		fs := a.flags("bans "+name, "[--note \"...\"]")
		note := fs.String("note", "", "why (kept in the audit log)")
		if _, err := parse(fs, args, 0); err != nil {
			return err
		}
		s, err := a.openStore()
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.SetBanPaused(a.ctx, paused, actor(), *note, time.Now()); err != nil {
			return err
		}
		if paused {
			fmt.Fprintln(a.stderr, "Paused: the hub writes nothing to Cloudflare until `heimdall bans resume`.")
		} else {
			fmt.Fprintln(a.stderr, "Resumed: waiting writes go out on the hub's next sync.")
		}
		return nil
	}
}

var bansCommands = map[string]command{
	"status": cmdBansStatus, "list": cmdBansList, "approve": banDecision("approve"), "reject": banDecision("reject"),
	"unban": banDecision("unban"), "pause": banPauseCmd(true), "resume": banPauseCmd(false),
	"set-token": cmdBansSetToken, "token-url": cmdBansTokenURL,
}
