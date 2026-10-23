// SPDX-License-Identifier: AGPL-3.0-or-later

package entra

import "github.com/chrisreedio/heimdall/internal/netx"

// The hub's allowlisted client is what production passes as Config.HTTP.
var _ HTTP = (*netx.Client)(nil)
