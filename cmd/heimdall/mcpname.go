// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strconv"

	"github.com/realmwatch/heimdall/internal/config"
)

// cmdMCPSetName sets mcp.name, what assistants call this hub's connection,
// keeping the rest of the config (comments included). Someone connected to
// two hubs needs a different name for each.
func cmdMCPSetName(a *app, args []string) error {
	fs := a.flags("mcp set-name", "<name>")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	name := pos[0]
	if !config.ValidConnectorName(name) {
		return fmt.Errorf("%q: use 1-40 lowercase letters, digits, - or _, starting with a letter or digit (e.g. heimdall-acme)", name)
	}
	path := hubConfigPath(a.configPath)
	if err := updateConfigKeys(path, "mcp", [][2]string{{"name", strconv.Quote(name)}},
		func(cfg config.Config) bool { return cfg.MCP.Name == name }); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Set mcp.name = %q in %s.\n", name, path)
	fmt.Fprintln(a.stderr, "Restart the hub to use it: sudo heimdall restart")
	fmt.Fprintln(a.stderr, "Anyone already connected removes the old connection and adds it again from the AI assistants page.")
	return nil
}
