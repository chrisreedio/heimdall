// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !dev

package web

import "testing"

// Release builds must never serve from disk or expose the dev routes.
func TestDevModeAbsentInReleaseBuilds(t *testing.T) {
	if devMode || devSetup != nil || devLoginEmail != "" {
		t.Fatal("dev mode is compiled into a non-dev build")
	}
	if templatesFS != templateFS || staticFiles != staticFS {
		t.Fatal("non-dev build doesn't use the embedded assets")
	}
}
