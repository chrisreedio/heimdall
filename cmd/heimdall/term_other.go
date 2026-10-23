// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package main

import (
	"bufio"
	"errors"
	"os"
)

// Hidden terminal input is only implemented for Linux, where the hub runs;
// elsewhere use --password-stdin.
func isTerminal(*os.File) bool { return false }

func readHidden(*os.File, *bufio.Reader) (string, error) {
	return "", errors.New("hidden input is not supported on this OS; use --password-stdin")
}

func readHiddenBlock(*os.File, *bufio.Reader, func(string) bool) (string, error) {
	return "", errors.New("hidden input is not supported on this OS; use --key-file")
}
