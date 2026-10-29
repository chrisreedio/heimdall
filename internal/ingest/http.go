// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/secret"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/triggers"
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
	enrolls     *limiter

	// hostByToken is store.HostByToken (replaced in tests), bounded by
	// lookupTimeout so a busy store answers 503 while the collector can
	// still read the reply.
	hostByToken   func(context.Context, [32]byte) (store.IngestHost, error)
	lookupTimeout time.Duration

	// OnStored, if set, is called after a new snapshot is stored (e.g. to
	// recompute the host's findings). It must not block.
	OnStored func(store.IngestHost)
	// OnSeen, if set, is called after an unchanged report is recorded as a
	// heartbeat (e.g. to run the reboot rules). It must not block.
	OnSeen func(store.IngestHost)
	// IPs, if set, says what's known about privilege sessions' sources.
	IPs *ipinfo.Resolver

	// TrustedEdge, if set, reports whether an address is a CDN edge in
	// front of the local proxy (Cloudflare's; see internal/cloudflare). Only
	// when the proxy's trusted hop is such an address is the client taken
	// from CF-Connecting-IP.
	TrustedEdge func(netip.Addr) bool
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
		enrolls:     newLimiter(enrollsPerMinute, time.Minute, maxLimiterKeys, now),

		hostByToken:   st.HostByToken,
		lookupTimeout: tokenLookupTimeout,
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

// tokenLookupTimeout bounds the wait for the store to look up a token: well
// inside Server's WriteTimeout, so a busy hub's 503 still reaches the
// collector.
const tokenLookupTimeout = 15 * time.Second

// retryAfter is the Retry-After on a 503, in seconds (the collector's own
// retry delay).
const retryAfter = "10"

// unavailable answers 503 with Retry-After, which collectors retry.
func unavailable(w http.ResponseWriter, msg string) {
	w.Header().Set("Retry-After", retryAfter)
	respond(w, http.StatusServiceUnavailable, msg)
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

	if key, ok := enrollKey(r); ok {
		h.enroll(w, r, ip, key, log) // enroll.go
		return
	}
	token, ok := bearerToken(r)
	if !ok {
		h.authFail.allow(ip.String())
		log.Warn("ingest rejected: invalid token")
		respond(w, http.StatusUnauthorized, "invalid token")
		return
	}
	// The body is read before the token is looked up, so a wait for the
	// store can't use up the server's read deadline (and turn a good
	// report into a 400). Only a well-formed token gets this far, and the
	// read is capped on the wire and decompressed (readBody).
	var raw []byte
	var bodyCode int
	var bodyErr error
	if r.Method == http.MethodPost {
		raw, bodyCode, bodyErr = h.readBody(w, r)
	}
	host, found, err := h.authenticate(r.Context(), token)
	if err != nil {
		log.Error("ingest deferred: token lookup failed", "err", err)
		unavailable(w, "hub busy, retry later")
		return
	}
	if !found {
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
		if host.Awaiting { // install.sh asks, re-run on an enrolled server
			w.Header().Set(PendingHeader, "1")
		}
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

	// Enrolled and waiting for an admin's approval: answered, so the
	// collector stays quiet, but nothing it sends is stored.
	if host.Awaiting {
		log.Info("ingest ignored: host waiting for approval")
		w.Header().Set(PendingHeader, "1")
		respond(w, http.StatusAccepted, "waiting for approval")
		return
	}

	if bodyErr != nil {
		log.Warn("ingest rejected: bad body", "status", bodyCode, "err", bodyErr)
		if bodyCode == http.StatusServiceUnavailable {
			unavailable(w, bodyErr.Error())
		} else {
			respond(w, bodyCode, bodyErr.Error())
		}
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
	if res.Status < 300 {
		if err := h.store.RecordReportIP(r.Context(), host.ID, ip.String()); err != nil {
			log.Warn("report address not recorded", "err", err)
		}
		if err := h.store.RecordMachine(r.Context(), host.ID, r.Header.Get(MachineHeader)); err != nil { // enroll.go
			log.Warn("machine ID not recorded", "err", err)
		}
		h.recordPrivilege(r.Context(), log, host, res.SnapshotID, r) // opt-in privilege watch (privilege.go)
		h.recordSiteRepos(r.Context(), log, host, r)                 // repos.go
		h.recordSiteBranches(r.Context(), log, host, r)              // branches.go
		h.recordPHP(r.Context(), log, host, r)                       // php.go
		h.recordLogins(r.Context(), log, host, r)                    // opt-in login watch (logins.go)
	}
	if res.Status == http.StatusCreated && h.OnStored != nil {
		h.OnStored(host)
	}
	if res.Unchanged && h.OnSeen != nil {
		h.OnSeen(host)
	}
	respond(w, res.Status, res.Message)
}

// bearerToken is the request's ingest token, if it has a well-formed one.
func bearerToken(r *http.Request) (string, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token, ok && secret.LooksLike(token, secret.IngestPrefix)
}

// authenticate looks up token's host. found is false for an unknown or
// revoked token; err is the store failing or too slow to answer.
func (h *Handler) authenticate(ctx context.Context, token string) (host store.IngestHost, found bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.lookupTimeout)
	defer cancel()
	host, err = h.hostByToken(ctx, secret.Hash(token))
	if errors.Is(err, store.ErrNotFound) {
		return host, false, nil
	}
	return host, err == nil, err
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
			return nil, bodyStatus(err), bodyError(err, "invalid gzip body")
		}
		defer zr.Close()
		body = zr
	default:
		return nil, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content encoding")
	}
	raw, err := io.ReadAll(io.LimitReader(body, h.maxBody+1))
	if err != nil {
		return nil, bodyStatus(err), bodyError(err, "could not read body")
	}
	if int64(len(raw)) > h.maxBody {
		return nil, http.StatusRequestEntityTooLarge, errors.New("snapshot too large")
	}
	return raw, 0, nil
}

// bodyError is msg, or for a read that timed out, says so.
func bodyError(err error, msg string) error {
	if bodyStatus(err) == http.StatusServiceUnavailable {
		return errors.New("timed out reading the body, retry later")
	}
	return errors.New(msg)
}

// bodyStatus is the answer to a failed body read: 413 over the cap, 503
// when the read deadline passed (a slow link or a stalled hub, not a bad
// report: collectors retry a 503), else 400.
func bodyStatus(err error) int {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return http.StatusRequestEntityTooLarge
	}
	var ne net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return http.StatusServiceUnavailable
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
				return h.edgeClient(r, fwd)
			}
		}
	}
	return ip
}

// edgeClient returns CF-Connecting-IP when the proxy's peer fwd is a
// trusted edge address and the header holds exactly one address, else fwd.
// Cloudflare sets the header itself; from anywhere else it's ignored.
func (h *Handler) edgeClient(r *http.Request, fwd net.IP) net.IP {
	a, ok := netip.AddrFromSlice(fwd)
	if h.TrustedEdge == nil || !ok || !h.TrustedEdge(a.Unmap()) {
		return fwd
	}
	if v := r.Header.Values("CF-Connecting-IP"); len(v) == 1 {
		if c := net.ParseIP(strings.TrimSpace(v[0])); c != nil && !c.IsUnspecified() && !c.IsLoopback() {
			return c
		}
	}
	return fwd
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
