// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// HostSSH is what a host's collector said about its sshd (migration 0037).
type HostSSH struct {
	Source string   // g (sshd -G), files, unreadable or none
	Ports  []int    // sshd's ports
	Listen []string // addresses listening on them
	// yes, no, or "" unknown; RootLogin is sshd's PermitRootLogin value.
	Password, KbdInteractive, PAM, RootLogin string
	SeenAt                                   time.Time
}

// PasswordLogin reports whether sshd takes passwords: directly, or
// through keyboard-interactive with PAM. known is false when it can't
// tell.
func (h HostSSH) PasswordLogin() (on, known bool) {
	switch {
	case h.Password == "yes" || (h.KbdInteractive == "yes" && h.PAM == "yes"):
		return true, true
	case h.Password == "no" && (h.KbdInteractive == "no" || h.PAM == "no"):
		return false, true
	}
	return false, false
}

// SetHostSSH records a host's sshd settings.
func (s *Store) SetHostSSH(ctx context.Context, hostID int64, h HostSSH, at time.Time) error {
	if h.Ports == nil {
		h.Ports = []int{}
	}
	if h.Listen == nil {
		h.Listen = []string{}
	}
	ports, _ := json.Marshal(h.Ports)
	listen, _ := json.Marshal(h.Listen)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO host_ssh (host_id, src, ports, listen, password, kbd, pam, root, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET src = excluded.src, ports = excluded.ports, listen = excluded.listen,
			password = excluded.password, kbd = excluded.kbd, pam = excluded.pam, root = excluded.root, seen_at = excluded.seen_at`,
		hostID, h.Source, string(ports), string(listen), h.Password, h.KbdInteractive, h.PAM, h.RootLogin, at.UTC().Format(timeLayout))
	return err
}

const hostSSHCols = `host_id, src, ports, listen, password, kbd, pam, root, seen_at`

func scanHostSSH(sc interface{ Scan(...any) error }) (int64, HostSSH, error) {
	var id int64
	var h HostSSH
	var ports, listen, at string
	if err := sc.Scan(&id, &h.Source, &ports, &listen, &h.Password, &h.KbdInteractive, &h.PAM, &h.RootLogin, &at); err != nil {
		return 0, h, err
	}
	json.Unmarshal([]byte(ports), &h.Ports)
	json.Unmarshal([]byte(listen), &h.Listen)
	h.SeenAt = parseTime(at)
	return id, h, nil
}

// HostSSHOf is a host's sshd settings; ok is false when its collector
// never reported them.
func (s *Store) HostSSHOf(ctx context.Context, hostID int64) (h HostSSH, ok bool, err error) {
	_, h, err = scanHostSSH(s.rd.QueryRowContext(ctx, `SELECT `+hostSSHCols+` FROM host_ssh WHERE host_id = ?`, hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return HostSSH{}, false, nil
	}
	return h, err == nil, err
}

// HostSSHs is every host's sshd settings, by host ID; hosts whose
// collector never reported them are absent.
func (s *Store) HostSSHs(ctx context.Context) (map[int64]HostSSH, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT `+hostSSHCols+` FROM host_ssh`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostSSH{}
	for rows.Next() {
		id, h, err := scanHostSSH(rows)
		if err != nil {
			return nil, err
		}
		out[id] = h
	}
	return out, rows.Err()
}

// LoginWatchHosts is the hosts whose login watch has reported, with when
// it last did.
func (s *Store) LoginWatchHosts(ctx context.Context) (map[int64]time.Time, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, reported_at FROM login_watch WHERE source NOT IN ('none', 'unreadable')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]time.Time{}
	for rows.Next() {
		var id int64
		var at string
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = parseTime(at)
	}
	return out, rows.Err()
}
