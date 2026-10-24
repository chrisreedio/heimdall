// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import "syscall"

// diskFree returns the bytes available to unprivileged users in dir's
// filesystem.
func diskFree(dir string) (int64, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
