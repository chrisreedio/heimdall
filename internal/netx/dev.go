// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package netx

// Dev builds allow plain http to an allowlisted loopback host (a local fake
// model server for the AI features). See devLoopbackHTTP.
func init() { devLoopbackHTTP = true }
