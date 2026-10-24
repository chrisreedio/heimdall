// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/secret"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/triggers"
)

// Path is the only route the ingest listener serves.
const Path = "/api/v1/ingest"

const (
	// Failed authentication attempts allowed per client IP per minute.
	authFailuresPerMinute = 20
	maxLimiterKeys        = 10000
)

// HostnameHeader carries the machine's hostname on a push. It's a header,
// not a snapshot field, so collectors and hubs of different versions still
// accept each other's requests.
const HostnameHeader = "X-Heimdall-Hostname"

// TriggersHeader carries the state of the collector's own triggers (its
// timer, change watch or hooks), e.g. "timer=enabled,active;
// changes=enabled,active", so the hub notices one being switched off. A
// header for the same reason as HostnameHeader; see anomaly.Triggers.
const TriggersHeader = "X-Heimdall-Triggers"

// VersionHeader tells an authenticated collector which release the hub
// runs, so it can say when it's behind and upgrade to match.
const VersionHeader = "X-Heimdall-Version"

type Handler struct {
	// Version is the hub's release (e.g. v0.4.11), told to authenticated
	// collectors only.
	Version     string
	acc         *Accepter
	store       *store.Store
	log         *slog.Logger
	maxBody     int64
	allow       []*net.IPNet
	behindProxy bool
	perHost     *limiter
	authFail    *limiter

	// OnStored, if set, is called after a new snapshot is stored (e.g. to
	// recompute the host's findings). It must not block.
	OnStored func(store.IngestHost)
	// OnSeen, if set, is called after an unchanged report is recorded as a
	// heartbeat (e.g. to run the reboot rules). It must not block.
	OnSeen func(store.IngestHost)
}

func NewHandler(st *store.Store, cfg config.Ingest, log *slog.Logger, now func() time.Time) (*Handler, error) {
	h := &Handler{
		acc:         &Accepter{Store: st, Now: now},
		store:       st,
		log:         log,
		maxBody:     int64(cfg.MaxBody),
		behindProxy: cfg.BehindProxy,
		perHost:     newLimiter(cfg.RatePerHost.N, cfg.RatePerHost.Per, maxLimiterKeys, now),
		authFail:    newLimiter(authFailuresPerMinute, time.Minute, maxLimiterKeys, now),
	}
	for _, c := range cfg.AllowCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		h.allow = append(h.allow, n)
	}
	return h, nil
}

// respond ends a request with a short plain-text message. Bodies are for
// humans debugging with curl; the collector reads only the status code.
func respond(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, msg+"\n")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	if r.URL.Path != Path {
		respond(w, http.StatusNotFound, "not found")
		return
	}
	// GET (with a valid token) asks which release the hub runs, for
	// `heimdall-collect upgrade`. Everything else is POST.
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		respond(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ip := h.clientIP(r)
	log := h.log.With("ip", ip.String())
	if len(h.allow) > 0 && !h.allowed(ip) {
		log.Warn("ingest rejected: source not in allow_cidrs")
		respond(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.authFail.exhausted(ip.String()) {
		respond(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}

	host, ok := h.authenticate(r)
	if !ok {
		h.authFail.allow(ip.String())
		log.Warn("ingest rejected: invalid token")
		respond(w, http.StatusUnauthorized, "invalid token")
		return
	}
	log = log.With("org", host.OrgSlug, "host", host.Name)
	if h.Version != "" {
		w.Header().Set(VersionHeader, h.Version)
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "{\"version\":%q}\n", h.Version)
		return
	}

	if !h.perHost.allow(strconv.FormatInt(host.ID, 10)) {
		log.Warn("ingest rejected: rate limited")
		respond(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	raw, status, err := h.readBody(w, r)
	if err != nil {
		log.Warn("ingest rejected: bad body", "status", status, "err", err)
		respond(w, status, err.Error())
		return
	}

	res, err := h.acc.Accept(r.Context(), host, "push", raw)
	if err != nil {
		log.Error("ingest failed", "err", err)
		respond(w, http.StatusInternalServerError, "internal error")
		return
	}
	attrs := []any{"status", res.Status, "bytes", len(raw)}
	if res.Snapshot != nil {
		attrs = append(attrs, "packages", len(res.Snapshot.Packages), "updates", len(res.Snapshot.Updates))
	}
	for _, a := range res.Anomalies {
		attrs = append(attrs, "anomaly", a.Rule)
	}
	if res.Status >= 400 {
		log.Warn("ingest rejected: "+res.Message, attrs...)
	} else {
		log.Info("ingest "+res.Message, attrs...)
	}
	// A host added without a name takes the hostname its collector sends
	// (once; it's only a display name, and only for its own registration).
	if res.Status == http.StatusCreated && host.AutoName {
		if reported := r.Header.Get(HostnameHeader); reported != "" {
			if name, ok, err := h.store.ClaimHostName(r.Context(), host.ID, reported); err != nil {
				log.Error("could not name host from its report", "err", err)
			} else if ok {
				log.Info("host named from its report", "name", name)
				host.Name = name
			}
		}
	}
	if res.Status == http.StatusCreated || res.Unchanged {
		raised, err := triggers.Check(r.Context(), h.store, host.ID, res.SnapshotID, r.Header.Get(TriggersHeader), h.acc.Now())
		if err != nil {
			log.Warn("collector trigger state not recorded", "err", err)
		}
		for _, a := range raised {
			log.Warn("anomaly", "rule", a.Rule, "severity", a.Severity, "summary", a.Summary)
		}
	}
	if res.Status < 300 { // opt-in privilege watch (privilege.go)
		h.recordPrivilege(r.Context(), log, host, res.SnapshotID, r)
	}
	if res.Status == http.StatusCreated && h.OnStored != nil {
		h.OnStored(host)
	}
	if res.Unchanged && h.OnSeen != nil {
		h.OnSeen(host)
	}
	respond(w, res.Status, res.Message)
}

func (h *Handler) authenticate(r *http.Request) (store.IngestHost, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !secret.LooksLike(token, secret.IngestPrefix) {
		return store.IngestHost{}, false
	}
	host, err := h.store.HostByToken(r.Context(), secret.Hash(token))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.log.Error("token lookup failed", "err", err)
		}
		return store.IngestHost{}, false
	}
	return host, true
}

// readBody enforces the content type and the size cap on both the wire
// bytes and the decompressed bytes (so a gzip bomb can't get past it).
func (h *Handler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, int, error) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, http.StatusUnsupportedMediaType, errors.New("content type must be application/json")
	}
	body := io.Reader(http.MaxBytesReader(w, r.Body, h.maxBody))
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, bodyStatus(err), fmt.Errorf("invalid gzip body")
		}
		defer zr.Close()
		body = zr
	default:
		return nil, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content encoding")
	}
	raw, err := io.ReadAll(io.LimitReader(body, h.maxBody+1))
	if err != nil {
		return nil, bodyStatus(err), errors.New("could not read body")
	}
	if int64(len(raw)) > h.maxBody {
		return nil, http.StatusRequestEntityTooLarge, errors.New("snapshot too large")
	}
	return raw, 0, nil
}

func bodyStatus(err error) int {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func (h *Handler) clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return net.IPv4zero
	}
	if h.behindProxy && ip.IsLoopback() {
		// Only the last hop: anything earlier was supplied by the client.
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if fwd := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); fwd != nil {
				return fwd
			}
		}
	}
	return ip
}

func (h *Handler) allowed(ip net.IP) bool {
	for _, n := range h.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Server returns an http.Server for the ingest listener with conservative
// timeouts and header limits.
func Server(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}
