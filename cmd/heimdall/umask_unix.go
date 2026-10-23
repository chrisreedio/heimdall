// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import "syscall"

// restrictUmask makes every file heimdall creates (including SQLite's WAL
// and SHM files) private to its owner.
func restrictUmask() { syscall.Umask(0o077) }
