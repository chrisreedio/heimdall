// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/realmwatch/heimdall/internal/secret"
	"github.com/realmwatch/heimdall/internal/store"
)

// MachineHeader carries a hash of the server's machine ID (hex SHA-256 of
// "heimdall-machine:" and /etc/machine-id, or Windows' MachineGuid), so a
// server is enrolled once. The ID itself never leaves the server.
const MachineHeader = "X-Heimdall-Machine"

// HostHeader tells an enrolling collector the host it became.
const HostHeader = "X-Heimdall-Host"

// PendingHeader marks an answer for a host waiting for an admin's
// approval (on enrolling, and on each report until then).
const PendingHeader = "X-Heimdall-Pending"

// Enrollments allowed per key per minute: a leaked key can't flood the
// hub with hosts faster than this.
const enrollsPerMinute = 60

// enrollKey returns the enrollment key a request carries, if any. Enrolling
// uses the ingest path, so a hub's reverse proxy needs no new route.
func enrollKey(r *http.Request) (string, bool) {
	key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return key, ok && strings.HasPrefix(key, secret.EnrollPrefix)
}

// enroll adds a host with an enrollment key and answers with its own
// ingest token (the body, text/plain), which the installer stores.
func (h *Handler) enroll(w http.ResponseWriter, r *http.Request, ip net.IP, key string, log *slog.Logger) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		respond(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !secret.LooksLike(key, secret.EnrollPrefix) {
		h.authFail.allow(ip.String())
		log.Warn("enroll rejected: invalid key")
		respond(w, http.StatusUnauthorized, "invalid enrollment key")
		return
	}
	hash := secret.Hash(key)
	if !h.enrolls.allow(hex.EncodeToString(hash[:8])) {
		log.Warn("enroll rejected: rate limited")
		respond(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 4<<10)) // the request has no body
	machine := r.Header.Get(MachineHeader)
	got, err := h.store.EnrollHost(r.Context(), hash, r.Header.Get(HostnameHeader), machine, ip.String(), h.acc.Now())
	var dup *store.AlreadyEnrolledError
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.authFail.allow(ip.String())
		log.Warn("enroll rejected: unknown or revoked key")
		respond(w, http.StatusUnauthorized, "invalid enrollment key")
		return
	case errors.Is(err, store.ErrEnrollExpired), errors.Is(err, store.ErrEnrollUsedUp):
		log.Warn("enroll rejected: " + err.Error())
		respond(w, http.StatusForbidden, err.Error())
		return
	case errors.As(err, &dup):
		log.Warn("enroll rejected: server already enrolled", "host", dup.Host)
		respond(w, http.StatusConflict, dup.Error()+"; to reinstall it, keep its existing token, or remove that host on the hub first")
		return
	case err != nil:
		log.Error("enroll failed", "err", err)
		respond(w, http.StatusInternalServerError, "internal error")
		return
	}
	log.Info("host enrolled", "org", got.Host.OrgSlug, "host", got.Host.Name, "enroll_key", got.KeyID, "awaiting_approval", got.Awaiting)
	w.Header().Set(HostHeader, got.Host.Name)
	if got.Awaiting {
		w.Header().Set(PendingHeader, "1")
	}
	if h.Version != "" {
		w.Header().Set(VersionHeader, h.Version)
	}
	respond(w, http.StatusCreated, got.Token)
}
