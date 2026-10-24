// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package config

// Dev builds (go build -tags dev) accept a plain-http loopback ai.endpoint,
// so the AI features can be tried against a local fake model server.
func init() { devBuild = true }
