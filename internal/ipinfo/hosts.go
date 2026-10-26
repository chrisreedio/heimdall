// SPDX-License-Identifier: AGPL-3.0-or-later

package ipinfo

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Hosts knows your own servers by the address their reports come from.
type Hosts struct{ Store *store.Store }

func (Hosts) Name() string { return "hosts" }

func (h Hosts) Lookup(ctx context.Context, orgID int64, ip netip.Addr, _ time.Time) ([]Label, error) {
	names, err := h.Store.HostsByReportIP(ctx, orgID, ip.String())
	if err != nil || len(names) == 0 {
		return nil, err
	}
	return []Label{{Kind: store.IPKindInfra, Name: strings.Join(names, ", "), Source: "hosts",
		Prefix: netip.PrefixFrom(ip, ip.BitLen())}}, nil
}
