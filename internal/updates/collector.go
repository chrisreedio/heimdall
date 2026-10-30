// SPDX-License-Identifier: AGPL-3.0-or-later

package updates

import "strings"

// CollectorChanged is the last release whose collector (collector/) differs
// from the one before it in more than its version number. Every release
// bumps that number, so comparing a server's collector with the hub's own
// release would call it behind after each one, changed or not; a collector
// at this release or later is current. TestCollectorChanged fails when
// collector/ changes and this isn't moved up.
const CollectorChanged = "v0.4.54"

// CollectorBehind reports whether a collector at version v ("0.4.41" or
// "v0.4.41") predates CollectorChanged, so upgrading it would change it.
func CollectorBehind(v string) bool {
	return Newer(CollectorChanged, "v"+strings.TrimPrefix(strings.TrimSpace(v), "v"))
}
