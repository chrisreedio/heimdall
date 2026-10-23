// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

import "os"

func restrictUmask() {}

func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
