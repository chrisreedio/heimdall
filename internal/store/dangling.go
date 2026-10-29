// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"
)

// Dangling probe states (cloudflare.Prober).
const (
	ProbeAnswers = "answers" // a TCP connect to Port succeeded
	ProbeRefused = "refused" // something is there, but 443 and 80 are closed
	ProbeSilent  = "silent"  // no reply on either port
)

// DanglingProbe is the last probe of a dangling record's address. The zero
// value (no row) is "not checked".
type DanglingProbe struct {
	Addr      netip.Addr
	State     string
	Port      int
	CheckedAt time.Time
}

// Checked: the address has been probed.
func (p DanglingProbe) Checked() bool { return p.State != "" }

// SetDanglingProbes stores probe results, replacing earlier ones.
func (s *Store) SetDanglingProbes(ctx context.Context, ps []DanglingProbe) error {
	if len(ps) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, p := range ps {
		if !p.Addr.IsValid() {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO dangling_probes (addr, state, port, checked_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (addr) DO UPDATE SET state = excluded.state, port = excluded.port, checked_at = excluded.checked_at`,
			p.Addr.Unmap().String(), p.State, p.Port, p.CheckedAt.UTC().Format(timeLayout)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneDanglingProbes drops the results for every address not in keep.
func (s *Store) PruneDanglingProbes(ctx context.Context, keep []netip.Addr) error {
	strs := make([]string, 0, len(keep))
	for _, a := range keep {
		strs = append(strs, a.Unmap().String())
	}
	b, _ := json.Marshal(strs)
	_, err := s.db.ExecContext(ctx, `DELETE FROM dangling_probes WHERE addr NOT IN (SELECT value FROM json_each(?))`, string(b))
	return err
}

// DanglingProbes is every stored result, by address.
func (s *Store) DanglingProbes(ctx context.Context) (map[netip.Addr]DanglingProbe, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT addr, state, port, checked_at FROM dangling_probes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[netip.Addr]DanglingProbe{}
	for rows.Next() {
		var p DanglingProbe
		var addr, at string
		if err := rows.Scan(&addr, &p.State, &p.Port, &at); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		p.Addr, p.CheckedAt = a, parseTime(at)
		out[a] = p
	}
	return out, rows.Err()
}
