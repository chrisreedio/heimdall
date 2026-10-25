// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

func asHubUser(configPath string, _ []string) (string, error) { return configPath, nil }
