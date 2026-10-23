// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"os"
	"syscall"
)

// restrictUmask makes every file heimdall creates (including SQLite's WAL
// and SHM files) private to its owner.
func restrictUmask() { syscall.Umask(0o077) }

// fileOwner returns a file's owner, so rewritten files can keep it.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
