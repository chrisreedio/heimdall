// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/anomaly"
	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/findings"
	"github.com/chrisreedio/heimdall/internal/ingest"
	"github.com/chrisreedio/heimdall/internal/mcp"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/search"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/updates"
	"github.com/chrisreedio/heimdall/internal/web"
)

func cmdServe(a *app, args []string) error {
	if _, err := parse(a.flags("serve", ""), args, 0); err != nil {
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

	log := slog.New(slog.NewTextHandler(a.stderr, nil))
	h, err := ingest.NewHandler(s, cfg.Ingest, log, time.Now)
	if h != nil {
		h.Version = version
	}
	if err != nil {
		return err
	}
	// Findings: recompute a host right after it reports, and sync every
	// feed on a schedule. Both run in one goroutine so they never overlap.
	syncer := newSyncer(cfg, s, log)
	reported := make(chan store.IngestHost, 256)
	h.OnStored = func(host store.IngestHost) {
		select {
		case reported <- host:
		default: // queue full; the next scheduled sync catches up
		}
	}
	tripwires := &anomaly.Engine{Store: s, Now: time.Now, Log: log}
	startTamperChecks(a.ctx, cfg, s, h, tripwires, log) // fast silence alerts; rules for unchanged reports
	newsSync := newNewsSyncer(cfg, s, log)
	go runFindings(a.ctx, syncer, newsSync, tripwires, cfg.Hosts.StaleAfter.Duration, reported,
		cfg.Feeds.SyncInterval.Duration, cfg.News.Interval.Duration, log)
	if every := cfg.Notify.Every.Duration; every > 0 {
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-a.ctx.Done():
					return
				case <-t.C:
					if err := sendDigest(a.ctx, cfg, s, time.Now()); err != nil {
						log.Warn("digest failed", "err", err)
					}
				}
			}
		}()
	}

	uiSrv, err := newUIServer(cfg, s, log)
	if err != nil {
		return err
	}
	uiLn, err := net.Listen("tcp", cfg.UI.Listen)
	if err != nil {
		return err
	}
	var mcpSrv *http.Server
	var mcpLn net.Listener
	if cfg.MCP.Enabled {
		h, err := mcp.New(mcp.Config{BaseURL: cfg.MCP.BaseURL, Version: version}, s, log.With("component", "mcp"), time.Now)
		if err != nil {
			return err
		}
		mcpSrv = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10,
			ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
		if mcpLn, err = net.Listen("tcp", cfg.MCP.Listen); err != nil {
			return err
		}
	}

	srv := ingest.Server(h, log)
	useTLS := cfg.Ingest.TLSCert != ""
	if useTLS {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	ln, err := net.Listen("tcp", cfg.Ingest.Listen)
	if err != nil {
		return err
	}
	log.Info("ingest listening", "addr", ln.Addr().String(), "tls", useTLS, "path", ingest.Path)
	log.Info("web UI listening", "addr", uiLn.Addr().String(), "base_url", cfg.UI.BaseURL)

	errc := make(chan error, 3)
	servers := 2
	go func() {
		if useTLS {
			errc <- srv.ServeTLS(ln, cfg.Ingest.TLSCert, cfg.Ingest.TLSKey)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	go func() { errc <- uiSrv.Serve(uiLn) }()
	if mcpSrv != nil {
		servers++
		log.Info("MCP listening", "addr", mcpLn.Addr().String(), "path", mcp.Path, "base_url", cfg.MCP.BaseURL)
		go func() { errc <- mcpSrv.Serve(mcpLn) }()
	}

	select {
	case err := <-errc:
		return err
	case <-a.ctx.Done():
	}
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownErr := errors.Join(srv.Shutdown(ctx), uiSrv.Shutdown(ctx))
	if mcpSrv != nil {
		shutdownErr = errors.Join(shutdownErr, mcpSrv.Shutdown(ctx))
	}
	for range servers {
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return shutdownErr
}

// newUIServer builds the web UI: local accounts behind sessions, the
// dashboard, host pages and fleet search.
func newUIServer(cfg config.Config, s *store.Store, log *slog.Logger) (*http.Server, error) {
	authn := &auth.Service{
		Store:        s,
		Now:          time.Now,
		SessionIdle:  cfg.UI.SessionIdle.Duration,
		SessionMax:   cfg.UI.SessionMax.Duration,
		DisableLocal: !cfg.Auth.LocalLogin,
		SyncAppRoles: cfg.Auth.Entra.Enabled && cfg.Auth.Entra.AppRoleMapping,
	}
	var sso web.SSO
	if cfg.Auth.Entra.Enabled {
		client, err := newEntraClient(cfg)
		if err != nil {
			return nil, err
		}
		sso = client
	}
	searchFn := func(ctx context.Context, q string, scope store.Scope) (*search.Result, error) {
		query, err := search.Parse(q)
		if err != nil {
			return nil, err // shown to the user
		}
		res, err := search.Run(ctx, s, query, scope)
		if err != nil {
			log.Error("search failed", "err", err)
			return nil, errors.New("search failed; see the server log")
		}
		return res, nil
	}
	h, err := web.New(web.Config{
		BaseURL:      cfg.UI.BaseURL,
		StaleAfter:   cfg.Hosts.StaleAfter.Duration,
		Version:      version,
		SessionMax:   cfg.UI.SessionMax.Duration,
		SSO:          sso,
		LocalLogin:   cfg.Auth.LocalLogin,
		EntraTenants: cfg.Auth.Entra.AllowedTenants,
		IngestURL:    cfg.Ingest.PublicURL,
		Updates:      updateChecker(cfg, log),
		News:         cfg.News.Enabled,
	}, s, authn, searchFn, log.With("component", "ui"), time.Now)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}, nil
}

// runFindings runs every feed sync and findings update in one goroutine, so
// they never overlap. news may be nil (threat news off).
func runFindings(ctx context.Context, syncer *findings.Syncer, news *findings.NewsSyncer, tripwires *anomaly.Engine,
	staleAfter time.Duration, reported <-chan store.IngestHost, every, newsEvery time.Duration, log *slog.Logger) {
	first := time.NewTimer(10 * time.Second) // let the listener come up first
	defer first.Stop()
	tick := time.NewTicker(every)
	defer tick.Stop()
	var newsTick <-chan time.Time
	if news != nil && newsEvery > 0 {
		t := time.NewTicker(newsEvery)
		defer t.Stop()
		newsTick = t.C
	}
	// A failing news feed is logged and recorded in feed status; it never
	// stops findings or the other feeds.
	syncNews := func() {
		if news != nil {
			news.Run(ctx)
		}
	}
	rematch := func() {
		if err := news.MatchAll(ctx); err != nil {
			log.Warn("news matching failed", "err", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			syncer.Run(ctx)
			syncNews()
		case <-newsTick:
			syncNews()
		case <-tick.C:
			syncer.Run(ctx)
			rematch()
			if n, err := tripwires.CheckSilence(ctx, staleAfter); err != nil {
				log.Warn("silence check failed", "err", err)
			} else if n > 0 {
				log.Warn("hosts went silent", "count", n)
			}
			if keep := syncer.Retention; keep.For > 0 {
				if n, err := syncer.Store.PruneSnapshots(ctx, time.Now().Add(-keep.For), keep.Min); err != nil {
					log.Warn("snapshot retention failed", "err", err)
				} else if n > 0 {
					log.Info("old snapshots removed", "count", n)
				}
			}
			if n, err := syncer.Store.DeleteExpiredSessions(ctx, time.Now()); err != nil {
				log.Warn("session cleanup failed", "err", err)
			} else if n > 0 {
				log.Info("expired sessions removed", "count", n)
			}
		case host := <-reported:
			if raised, err := tripwires.OnSnapshot(ctx, host); err != nil {
				log.Warn("anomaly rules failed", "host", host.Name, "err", err)
			} else {
				for _, an := range raised {
					log.Warn("anomaly", "host", host.Name, "rule", an.Rule, "severity", an.Severity, "summary", an.Summary)
				}
			}
			if err := syncer.SyncMissingEOL(ctx); err != nil {
				log.Warn("lifecycle data fetch failed", "err", err)
			}
			if r, err := syncer.Engine.EvaluateHost(ctx, host); err != nil {
				log.Warn("findings update failed", "host", host.Name, "err", err)
			} else if r.Ecosystem != "" {
				log.Info("findings updated", "host", host.Name, "open", r.Findings, "new", r.Added, "resolved", r.Resolved)
			}
			if err := news.MatchHost(ctx, host.ID); err != nil {
				log.Warn("news matching failed", "host", host.Name, "err", err)
			}
		}
	}
}

func cmdImport(a *app, args []string) error {
	fs := a.flags("import", "--org <org> --host <hostname> <file.json|->\n       heimdall import --check <file.json|->")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	hostName := fs.String("host", "", "hostname the snapshot belongs to")
	check := fs.Bool("check", false, "only validate the file; store nothing")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	raw, err := readCapped(pos[0], int64(cfg.Ingest.MaxBody))
	if err != nil {
		return err
	}

	if *check {
		acc := ingest.Accepter{Now: time.Now}
		snap, err := acc.Check(raw)
		if err != nil {
			return fmt.Errorf("%s is not a valid snapshot:\n%w", pos[0], err)
		}
		fmt.Fprintf(a.stderr, "%s is valid: %s, %d packages, %d pending updates.\n",
			pos[0], snap.OS.PrettyName, len(snap.Packages), len(snap.Updates))
		return nil
	}

	if err := required(fs, "host"); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	host, err := s.HostByName(a.ctx, *org, *hostName)
	if err != nil {
		return err
	}
	acc := ingest.Accepter{Store: s, Now: time.Now}
	res, err := acc.Accept(a.ctx, host, "import", raw)
	if err != nil {
		return err
	}
	if res.Status >= 400 {
		return fmt.Errorf("snapshot rejected: %s", res.Message)
	}
	tripwires := &anomaly.Engine{Store: s, Now: time.Now, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	more, err := tripwires.OnSnapshot(a.ctx, host)
	if err != nil {
		return err
	}
	for _, an := range append(res.Anomalies, more...) {
		fmt.Fprintf(a.stderr, "anomaly (%s): %s\n", an.Rule, an.Summary)
	}
	fmt.Fprintf(a.stderr, "Imported snapshot for %s (%s, %d packages): %s.\n"+
		"Findings update on the next scheduled sync, or now with `heimdall feeds sync`.\n",
		host.Name, res.Snapshot.OS.PrettyName, len(res.Snapshot.Packages), res.Message)
	return nil
}

// readCapped reads a file (or stdin for "-") up to max bytes.
func readCapped(path string, max int64) ([]byte, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than ingest.max_body (%d bytes)", path, max)
	}
	return b, nil
}

func cmdHostToken(a *app, args []string) error {
	fs := a.flags("host token", "--org <org> --rotate <hostname>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	rotate := fs.Bool("rotate", false, "revoke the current token and print a new one")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if !*rotate {
		return errors.New("tokens are stored only as hashes and can't be shown again; use --rotate to issue a new one")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	token, err := s.RotateToken(a.ctx, actor(), *org, pos[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Rotated the token for %s; the old one no longer works.\n"+
		"New ingest token, shown once (install it on the host as /etc/heimdall/token, mode 0400):\n\n", pos[0])
	fmt.Fprintln(a.stdout, token)
	return nil
}

func cmdHostShow(a *app, args []string) error {
	fs := a.flags("host show", "--org <org> <hostname>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	host, err := s.HostByName(a.ctx, *org, pos[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Host:      %s (org %s)\n", host.Name, host.OrgSlug)
	sum, err := s.LatestSnapshot(a.ctx, host.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fmt.Fprintln(a.stdout, "Snapshot:  none yet")
	case err != nil:
		return err
	default:
		reboot := "unknown"
		if sum.RebootRequired != nil {
			reboot = map[bool]string{true: "yes", false: "no"}[*sum.RebootRequired]
		}
		fmt.Fprintf(a.stdout, "Last seen: %s (via %s, collector %s)\n", formatTime(sum.ReceivedAt), sum.Source, sum.CollectorVersion)
		fmt.Fprintf(a.stdout, "OS:        %s\n", sum.OS)
		fmt.Fprintf(a.stdout, "Packages:  %d installed, %d with updates (%d security)\n", sum.Packages, sum.PendingUpdates, sum.PendingSecurity)
		fmt.Fprintf(a.stdout, "Reboot:    %s\n", reboot)
	}
	anomalies, err := s.Anomalies(a.ctx, host.ID)
	if err != nil {
		return err
	}
	if len(anomalies) == 0 {
		fmt.Fprintln(a.stdout, "Anomalies: none open")
		return nil
	}
	fmt.Fprintf(a.stdout, "Anomalies: %d open\n", len(anomalies))
	for _, an := range anomalies {
		fmt.Fprintf(a.stdout, "  %s  %-6s %-10s %s\n", formatTime(an.DetectedAt), an.Severity, an.Rule, an.Summary)
	}
	return nil
}

func cmdCollectorTrust(a *app, args []string) error {
	fs := a.flags("collector trust", "--version <x.y.z> [--note \"...\"] <sha256>")
	version := fs.String("version", "", "collector version this checksum belongs to (required)")
	note := fs.String("note", "", "optional note, e.g. where you verified it")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if err := required(fs, "version"); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.TrustCollector(a.ctx, actor(), strings.ToLower(pos[0]), *version, *note); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Trusted collector %s (%s).\n", *version, pos[0][:12])
	return nil
}

func cmdCollectorList(a *app, args []string) error {
	if _, err := parse(a.flags("collector list", ""), args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	trusted, untrusted, err := s.ListCollectors(a.ctx)
	if err != nil {
		return err
	}
	var rows [][]string
	for _, k := range trusted {
		rows = append(rows, []string{"trusted", k.Version, k.SHA256, strconv.Itoa(k.Hosts), k.Note})
	}
	for _, k := range untrusted {
		rows = append(rows, []string{"UNTRUSTED", k.Version + " (claimed)", k.SHA256, strconv.Itoa(k.Hosts), ""})
	}
	return table(a, "STATUS\tVERSION\tSHA256\tHOSTS\tNOTE", rows)
}

// updateChecker starts the daily release check (if enabled) and returns
// what the UI asks for its admin banner.
func updateChecker(cfg config.Config, log *slog.Logger) func() (updates.Release, bool) {
	if !cfg.Updates.Check {
		return nil
	}
	c := &updates.Checker{HTTP: netx.New(netx.ReleaseHosts, "heimdall/"+version), Current: version}
	go c.Run(context.Background(), func(msg string, args ...any) { log.Info(msg, args...) })
	return c.Available
}
