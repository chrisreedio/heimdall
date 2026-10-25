// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "os"

// preloadedKey is a key file read as root before a keyCommand dropped to
// the hub user (drop_unix.go).
type preloadedKey struct {
	perm os.FileMode
	b    []byte
}

var preloadedKeys = map[string]preloadedKey{}

// keyFallback says whether a CLI command may read the default key file:
// as root, or after reading it as root.
func keyFallback(root bool) bool { return root || len(preloadedKeys) > 0 }

// readKeyFile reads a key file, or the copy read as root.
func readKeyFile(path string) (os.FileMode, []byte, error) {
	if k, ok := preloadedKeys[path]; ok {
		return k.perm, k.b, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0, nil, err
	}
	if fi.Size() > 4096 {
		return fi.Mode().Perm(), make([]byte, 4097), nil
	}
	b, err := os.ReadFile(path)
	return fi.Mode().Perm(), b, err
}
