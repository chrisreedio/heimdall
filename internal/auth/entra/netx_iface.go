// SPDX-License-Identifier: AGPL-3.0-or-later

package entra

import "github.com/realmwatch/heimdall/internal/netx"

// The hub's allowlisted client is what production passes as Config.HTTP.
var _ HTTP = (*netx.Client)(nil)
