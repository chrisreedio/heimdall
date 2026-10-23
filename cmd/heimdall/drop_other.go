// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

func asHubUser(string, []string) error { return nil }
