// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

// diskFree is unknown here; VACUUM fails cleanly (and leaves the database
// unchanged) if the disk fills.
func diskFree(string) (int64, bool) { return 0, false }
