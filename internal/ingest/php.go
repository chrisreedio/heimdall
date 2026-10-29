// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/realmwatch/heimdall/internal/store"
)

// PHPHeader says which PHP versions the host uses outside its sites'
// PHP-FPM sockets:
//
//	X-Heimdall-PHP: v1 cli=8.4 fpm=8.3,8.4
//
// cli is the version the command line `php` runs, fpm the versions whose
// PHP-FPM is running; "-" for none. A header for the same reason as
// SiteReposHeader (older hubs reject unknown snapshot fields). Without it
// (an older collector) the stored state is left as it is.
const PHPHeader = "X-Heimdall-PHP"

// parsePHP parses a PHPHeader value. ok is false when it's malformed.
func parsePHP(v string) (cli string, fpm []string, ok bool) {
	if len(v) > 512 {
		return "", nil, false
	}
	f := strings.Fields(v)
	if len(f) != 3 || f[0] != "v1" {
		return "", nil, false
	}
	c, ok1 := strings.CutPrefix(f[1], "cli=")
	p, ok2 := strings.CutPrefix(f[2], "fpm=")
	if !ok1 || !ok2 {
		return "", nil, false
	}
	if c != "-" {
		if !store.ValidPHPVersion(c) {
			return "", nil, false
		}
		cli = c
	}
	fpm = []string{}
	if p != "-" {
		for x := range strings.SplitSeq(p, ",") {
			if !store.ValidPHPVersion(x) {
				return "", nil, false
			}
			fpm = append(fpm, x)
		}
	}
	return cli, fpm, true
}

func (h *Handler) recordPHP(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(PHPHeader)
	if len(vals) != 1 {
		return
	}
	cli, fpm, ok := parsePHP(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + PHPHeader + " header")
		return
	}
	if err := h.store.SetHostPHP(ctx, host.ID, cli, fpm, h.acc.Now()); err != nil {
		log.Warn("PHP state not recorded", "err", err)
	}
}
