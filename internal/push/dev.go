// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package push

// Dev builds accept a loopback endpoint over plain http, so the app can be
// tried against a local fake push service. See devLoopback.
func init() { devLoopback = true }
